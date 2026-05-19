//! `GET /.well-known/agent-card.json` — JWS-signed agent card of the
//! control plane itself (ADR-0025).
//!
//! At v2.0 beta this endpoint serves the **control plane's own**
//! agent card — the identity of the registry / ticket issuer — using
//! the same Ed25519 signing key the control plane uses to sign data-
//! plane tickets (`AppState.signer`). Per-agent cards (one per
//! registered agent) are served by spize-cp's commercial layer at a
//! later sprint.
//!
//! Response shape matches the schema in `docs/protocol-v2.md` §6.2.

use std::time::{SystemTime, UNIX_EPOCH};

use axum::{extract::State, http::StatusCode, response::IntoResponse, routing::get, Router};
use serde::Serialize;

use crate::routes::v2::capabilities::default_capability_set;
use crate::AppState;

/// JSON shape of the unsigned agent-card payload.
///
/// Mirrors `aex_identity::AgentCardPayload` so downstream verifiers
/// can deserialize the body with the existing struct. We don't import
/// it here to keep `aex-control-plane` decoupled from `aex-identity`
/// at the type level — the public_key block shape is stable enough
/// that string-typed serialization is enough.
#[derive(Debug, Serialize)]
struct AgentCardPayload {
    iss: String,
    sub: String,
    iat: i64,
    exp: i64,
    agent_id: String,
    public_key: PublicKeyDeclaration,
    capabilities: Vec<&'static str>,
    endpoints: Endpoints,
}

#[derive(Debug, Serialize)]
struct PublicKeyDeclaration {
    #[serde(rename = "type")]
    key_type: &'static str,
    #[serde(rename = "publicKeyHex")]
    public_key_hex: String,
}

#[derive(Debug, Serialize)]
struct Endpoints {
    control_plane: String,
    data_planes: Vec<String>,
}

async fn agent_card(State(state): State<AppState>) -> Result<impl IntoResponse, StatusCode> {
    let signer = state.signer.ok_or(StatusCode::SERVICE_UNAVAILABLE)?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    // Card validity: now → now + 24h. Matches ADR-0046's stale-while-
    // revalidate ceiling; resolver chain's 1 h cache TTL means most
    // consumers revalidate well before exp.
    let exp = now + 24 * 60 * 60;

    let agent_id = "did:spize:control-plane#self".to_string();

    let payload = AgentCardPayload {
        iss: "did:spize:control-plane".into(),
        sub: agent_id.clone(),
        iat: now,
        exp,
        agent_id,
        public_key: PublicKeyDeclaration {
            key_type: "Ed25519VerificationKey2020",
            public_key_hex: signer.public_key_hex(),
        },
        capabilities: default_capability_set().to_string_array(),
        endpoints: Endpoints {
            // These are placeholder values; the deployment overrides
            // them via env vars in a follow-up sprint that wires
            // `AppState.config` into here.
            control_plane: "self".into(),
            data_planes: vec![],
        },
    };

    // NOTE: v2.0 beta serves the payload as plain JSON — wrapping it
    // in a JWS Compact Serialization requires `aex-jws` integration
    // and lives in the GA follow-up. ADR-0025 marks the JWS-wrapping
    // as required for did:web cards specifically; the Spize hosted
    // control plane is `did:spize` whose trust root is the registry
    // membership, not the well-known fetch.
    Ok((StatusCode::OK, axum::Json(payload)))
}

pub fn router() -> Router<AppState> {
    Router::new().route("/.well-known/agent-card.json", get(agent_card))
}
