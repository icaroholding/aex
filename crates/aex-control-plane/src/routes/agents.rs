//! Agents HTTP endpoints.
//!
//! **POST /v1/agents/register** — the core registration flow. The client:
//!   1. Generates an Ed25519 keypair locally.
//!   2. Builds the canonical challenge via
//!      [`aex_core::wire::registration_challenge_bytes`].
//!   3. Signs it with the private key.
//!   4. Submits `{public_key_hex, org, name, nonce, issued_at, signature_hex}`.
//!
//! The server re-derives the challenge bytes, verifies the signature against
//! the submitted public key, enforces timestamp freshness and nonce single-
//! use, computes the canonical `agent_id`, and persists. Private keys never
//! leave the client device — the server only stores the public half.
//!
//! **GET /v1/agents/:agent_id** — resolve an agent_id to its public key. Used
//! by peers during transfer to verify signed messages.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use ed25519_dalek::{Signature as DalekSignature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

use aex_core::wire::{
    registration_challenge_bytes, MAX_CLOCK_SKEW_SECS, MAX_NONCE_LEN, MIN_NONCE_LEN,
};

use crate::{
    db::agents as db,
    error::ApiError,
    AppState,
};

const PUBLIC_KEY_LEN: usize = 32;
const SIGNATURE_LEN: usize = 64;
const MAX_LABEL_LEN: usize = 64;

pub fn router() -> Router<AppState> {
    // Wildcard `*agent_id` captures the rest of the path including slashes,
    // because agent_ids contain `/` (e.g. `spize:acme/alice:a4f8b2`). Axum
    // resolves `/register` with higher specificity than the wildcard, so
    // route order does not matter. Inbox lives at its own top-level
    // `POST /v1/inbox` (see routes::inbox) to avoid wildcard ambiguity.
    Router::new()
        .route("/register", post(register))
        .route("/*agent_id", get(get_agent))
}

// ---------- POST /register ----------

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    /// Hex-encoded Ed25519 public key (32 bytes → 64 hex chars).
    pub public_key_hex: String,
    pub org: String,
    pub name: String,
    /// Hex, 32–128 chars, client-generated.
    pub nonce: String,
    /// Unix seconds at which the client built the challenge.
    pub issued_at: i64,
    /// Hex-encoded Ed25519 signature (64 bytes → 128 hex chars) over the
    /// canonical challenge bytes.
    pub signature_hex: String,
}

#[derive(Debug, Serialize)]
pub struct AgentResponse {
    pub agent_id: String,
    pub public_key_hex: String,
    pub fingerprint: String,
    pub org: String,
    pub name: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

async fn register(
    State(state): State<AppState>,
    Json(req): Json<RegisterRequest>,
) -> Result<(StatusCode, Json<AgentResponse>), ApiError> {
    // 1. Shape validation.
    validate_label(&req.org, "org")?;
    validate_label(&req.name, "name")?;
    if req.nonce.len() < MIN_NONCE_LEN || req.nonce.len() > MAX_NONCE_LEN {
        return Err(ApiError::BadRequest(format!(
            "nonce length must be {}..={} hex chars",
            MIN_NONCE_LEN, MAX_NONCE_LEN
        )));
    }
    if !req.nonce.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ApiError::BadRequest("nonce must be hex".into()));
    }

    let public_key = decode_hex_exact(&req.public_key_hex, PUBLIC_KEY_LEN, "public_key_hex")?;
    let signature = decode_hex_exact(&req.signature_hex, SIGNATURE_LEN, "signature_hex")?;

    // 2. Freshness. Overflow-safe even on adversarial timestamps.
    let now = OffsetDateTime::now_utc().unix_timestamp();
    if !aex_core::wire::is_within_clock_skew(now, req.issued_at) {
        return Err(ApiError::BadRequest(format!(
            "issued_at is outside allowed skew (±{}s)",
            MAX_CLOCK_SKEW_SECS
        )));
    }

    // 3. Cryptographic verification.
    let challenge = registration_challenge_bytes(
        &req.public_key_hex,
        &req.org,
        &req.name,
        &req.nonce,
        req.issued_at,
    )
    .map_err(|e| ApiError::BadRequest(format!("cannot build challenge: {}", e)))?;

    let vk_bytes: [u8; PUBLIC_KEY_LEN] = public_key
        .as_slice()
        .try_into()
        .expect("length already validated");
    let verifying_key = VerifyingKey::from_bytes(&vk_bytes)
        .map_err(|e| ApiError::BadRequest(format!("invalid public key: {}", e)))?;

    let sig_bytes: [u8; SIGNATURE_LEN] = signature
        .as_slice()
        .try_into()
        .expect("length already validated");
    let dalek_sig = DalekSignature::from_bytes(&sig_bytes);

    verifying_key
        .verify(&challenge, &dalek_sig)
        .map_err(|_| ApiError::Unauthorized("signature does not match challenge".into()))?;

    // 4. Nonce single-use (replay protection). Must come AFTER signature
    //    verification to avoid letting unauthenticated traffic fill the
    //    nonce table.
    let fresh = db::consume_nonce(&state.db, &req.nonce, &public_key).await?;
    if !fresh {
        return Err(ApiError::Conflict("nonce already used".into()));
    }

    // 5. Derive canonical agent_id server-side.
    let fingerprint = compute_fingerprint(&public_key);
    let agent_id = format!("spize:{}/{}:{}", req.org, req.name, fingerprint);

    // 6. Persist.
    match db::insert(
        &state.db,
        &agent_id,
        &public_key,
        &fingerprint,
        &req.org,
        &req.name,
    )
    .await
    {
        Ok(row) => Ok((
            StatusCode::CREATED,
            Json(AgentResponse {
                agent_id: row.agent_id,
                public_key_hex: hex::encode(&row.public_key),
                fingerprint: row.fingerprint,
                org: row.org,
                name: row.name,
                created_at: row.created_at,
            }),
        )),
        Err(err) => {
            if let Some(field) = db::unique_violation_field(&err) {
                Err(ApiError::Conflict(format!(
                    "{} already registered",
                    field
                )))
            } else {
                Err(err.into())
            }
        }
    }
}

// ---------- GET /:agent_id ----------

async fn get_agent(
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
) -> Result<Json<AgentResponse>, ApiError> {
    // Parse through AgentId to reject malformed lookups early.
    let parsed = aex_core::AgentId::new(&agent_id)?;

    let row = db::find_by_agent_id(&state.db, parsed.as_str())
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("agent {} not found", parsed)))?;

    Ok(Json(AgentResponse {
        agent_id: row.agent_id,
        public_key_hex: hex::encode(&row.public_key),
        fingerprint: row.fingerprint,
        org: row.org,
        name: row.name,
        created_at: row.created_at,
    }))
}

// ---------- helpers ----------

fn validate_label(s: &str, field: &str) -> Result<(), ApiError> {
    if s.is_empty() {
        return Err(ApiError::BadRequest(format!("{} is empty", field)));
    }
    if s.len() > MAX_LABEL_LEN {
        return Err(ApiError::BadRequest(format!(
            "{} exceeds {} chars",
            field, MAX_LABEL_LEN
        )));
    }
    if !s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(ApiError::BadRequest(format!(
            "{} must match [a-zA-Z0-9_-]+",
            field
        )));
    }
    Ok(())
}

fn decode_hex_exact(s: &str, expected: usize, field: &str) -> Result<Vec<u8>, ApiError> {
    let bytes = hex::decode(s)
        .map_err(|e| ApiError::BadRequest(format!("{}: invalid hex ({})", field, e)))?;
    if bytes.len() != expected {
        return Err(ApiError::BadRequest(format!(
            "{}: expected {} bytes, got {}",
            field,
            expected,
            bytes.len()
        )));
    }
    Ok(bytes)
}

fn compute_fingerprint(public_key: &[u8]) -> String {
    let hash = Sha256::digest(public_key);
    hex::encode(&hash[..3])
}
