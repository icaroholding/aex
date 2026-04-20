//! End-to-end tests for the agent registration flow.
//!
//! Uses `#[sqlx::test]` which provisions a fresh Postgres database per test,
//! runs the migrations in `./migrations`, and hands us a `PgPool`. The test
//! database lifecycle is managed by sqlx — no manual cleanup.
//!
//! Requires `DATABASE_URL` to point at a live Postgres instance. During
//! local dev, run `docker compose -f deploy/docker-compose.dev.yml up -d`.

mod common;

use axum::http::StatusCode;
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use serde_json::{json, Value};
use sqlx::PgPool;

use common::{random_nonce, TestEnv};
use aex_core::wire::registration_challenge_bytes;

fn build_payload(signing_key: &SigningKey, org: &str, name: &str) -> serde_json::Value {
    build_payload_with_nonce(signing_key, org, name, &random_nonce())
}

fn build_payload_with_nonce(
    signing_key: &SigningKey,
    org: &str,
    name: &str,
    nonce: &str,
) -> serde_json::Value {
    let public_key_hex = hex::encode(signing_key.verifying_key().to_bytes());
    let issued_at = time::OffsetDateTime::now_utc().unix_timestamp();
    let challenge =
        registration_challenge_bytes(&public_key_hex, org, name, nonce, issued_at).unwrap();
    let signature = signing_key.sign(&challenge);
    json!({
        "public_key_hex": public_key_hex,
        "org": org,
        "name": name,
        "nonce": nonce,
        "issued_at": issued_at,
        "signature_hex": hex::encode(signature.to_bytes()),
    })
}

// --- happy path ---

#[sqlx::test]
async fn register_returns_derived_agent_id(pool: PgPool) {
    let env = TestEnv::new(pool);
    let key = SigningKey::generate(&mut OsRng);
    let payload = build_payload(&key, "acme", "alice");
    let (status, body) = env.post_json("/v1/agents/register", &payload).await;
    assert_eq!(status, StatusCode::CREATED, "body = {}", body);

    let agent_id = body["agent_id"].as_str().expect("agent_id");
    assert!(agent_id.starts_with("spize:acme/alice:"));
    let fingerprint = body["fingerprint"].as_str().expect("fingerprint");
    assert_eq!(fingerprint.len(), 6);
    assert!(agent_id.ends_with(fingerprint));
}

#[sqlx::test]
async fn get_agent_by_id_returns_same_data(pool: PgPool) {
    let env = TestEnv::new(pool);
    let key = SigningKey::generate(&mut OsRng);
    let payload = build_payload(&key, "acme", "alice");
    let (_, registered) = env.post_json("/v1/agents/register", &payload).await;
    let agent_id = registered["agent_id"].as_str().unwrap().to_string();

    let (status, body) = env.get(&format!("/v1/agents/{}", agent_id)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["agent_id"], registered["agent_id"]);
    assert_eq!(body["public_key_hex"], registered["public_key_hex"]);
}

#[sqlx::test]
async fn healthz_returns_ok(pool: PgPool) {
    let env = TestEnv::new(pool);
    let (status, body) = env.get("/healthz").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "ok");
    assert_eq!(body["service"], "aex-control-plane");
}

// --- security: signature ---

#[sqlx::test]
async fn tampered_signature_rejected_401(pool: PgPool) {
    let env = TestEnv::new(pool);
    let key = SigningKey::generate(&mut OsRng);
    let mut payload = build_payload(&key, "acme", "alice");
    let sig = payload["signature_hex"].as_str().unwrap().to_string();
    let first = sig.chars().next().unwrap();
    let replacement = if first == '0' { '1' } else { '0' };
    let mut flipped = String::with_capacity(sig.len());
    flipped.push(replacement);
    flipped.push_str(&sig[1..]);
    payload["signature_hex"] = Value::String(flipped);

    let (status, _) = env.post_json("/v1/agents/register", &payload).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[sqlx::test]
async fn signature_over_wrong_message_rejected(pool: PgPool) {
    let env = TestEnv::new(pool);
    let key = SigningKey::generate(&mut OsRng);
    let mut payload = build_payload(&key, "acme", "alice");
    payload["org"] = Value::String("evil".into());
    let (status, _) = env.post_json("/v1/agents/register", &payload).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[sqlx::test]
async fn mismatched_public_key_rejected(pool: PgPool) {
    let env = TestEnv::new(pool);
    let signer = SigningKey::generate(&mut OsRng);
    let impersonator = SigningKey::generate(&mut OsRng);
    let mut payload = build_payload(&signer, "acme", "alice");
    payload["public_key_hex"] =
        Value::String(hex::encode(impersonator.verifying_key().to_bytes()));
    let (status, _) = env.post_json("/v1/agents/register", &payload).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

// --- security: freshness and replay ---

#[sqlx::test]
async fn stale_timestamp_rejected(pool: PgPool) {
    let env = TestEnv::new(pool);
    let key = SigningKey::generate(&mut OsRng);
    let public_key_hex = hex::encode(key.verifying_key().to_bytes());
    let nonce = random_nonce();
    let stale_ts = time::OffsetDateTime::now_utc().unix_timestamp() - 10_000;
    let challenge =
        registration_challenge_bytes(&public_key_hex, "acme", "alice", &nonce, stale_ts).unwrap();
    let signature = key.sign(&challenge);
    let payload = json!({
        "public_key_hex": public_key_hex,
        "org": "acme",
        "name": "alice",
        "nonce": nonce,
        "issued_at": stale_ts,
        "signature_hex": hex::encode(signature.to_bytes()),
    });
    let (status, _) = env.post_json("/v1/agents/register", &payload).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[sqlx::test]
async fn nonce_replay_rejected_409(pool: PgPool) {
    let env = TestEnv::new(pool);
    let key = SigningKey::generate(&mut OsRng);
    let payload = build_payload(&key, "acme", "alice");
    let (first, _) = env.post_json("/v1/agents/register", &payload).await;
    assert_eq!(first, StatusCode::CREATED);
    let (second, _) = env.post_json("/v1/agents/register", &payload).await;
    assert_eq!(second, StatusCode::CONFLICT);
}

// --- security: uniqueness ---

#[sqlx::test]
async fn same_pubkey_different_name_rejected(pool: PgPool) {
    let env = TestEnv::new(pool);
    let key = SigningKey::generate(&mut OsRng);
    let first = build_payload(&key, "acme", "alice");
    let (s1, _) = env.post_json("/v1/agents/register", &first).await;
    assert_eq!(s1, StatusCode::CREATED);

    let second = build_payload(&key, "acme", "bob");
    let (s2, body) = env.post_json("/v1/agents/register", &second).await;
    assert_eq!(s2, StatusCode::CONFLICT);
    assert!(body["message"].as_str().unwrap().contains("public_key"));
}

#[sqlx::test]
async fn different_pubkeys_both_register(pool: PgPool) {
    let env = TestEnv::new(pool);
    let a = SigningKey::generate(&mut OsRng);
    let b = SigningKey::generate(&mut OsRng);
    let (s1, _) = env
        .post_json("/v1/agents/register", &build_payload(&a, "acme", "alice"))
        .await;
    let (s2, _) = env
        .post_json("/v1/agents/register", &build_payload(&b, "acme", "bob"))
        .await;
    assert_eq!(s1, StatusCode::CREATED);
    assert_eq!(s2, StatusCode::CREATED);
}

// --- validation ---

#[sqlx::test]
async fn bad_org_rejected(pool: PgPool) {
    let env = TestEnv::new(pool);
    let key = SigningKey::generate(&mut OsRng);
    let mut payload = build_payload(&key, "acme", "alice");
    payload["org"] = Value::String("acme corp".into());
    let (status, body) = env.post_json("/v1/agents/register", &payload).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "bad_request");
}

#[sqlx::test]
async fn bad_public_key_length_rejected(pool: PgPool) {
    let env = TestEnv::new(pool);
    let payload = json!({
        "public_key_hex": "deadbeef",
        "org": "acme",
        "name": "alice",
        "nonce": random_nonce(),
        "issued_at": time::OffsetDateTime::now_utc().unix_timestamp(),
        "signature_hex": "00".repeat(64),
    });
    let (status, _) = env.post_json("/v1/agents/register", &payload).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[sqlx::test]
async fn short_nonce_rejected(pool: PgPool) {
    let env = TestEnv::new(pool);
    let key = SigningKey::generate(&mut OsRng);
    let mut payload = build_payload(&key, "acme", "alice");
    payload["nonce"] = Value::String("deadbeef".into());
    let (status, _) = env.post_json("/v1/agents/register", &payload).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[sqlx::test]
async fn get_unknown_agent_returns_404(pool: PgPool) {
    let env = TestEnv::new(pool);
    let (status, _) = env.get("/v1/agents/spize:acme/nonexistent:aabbcc").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[sqlx::test]
async fn get_malformed_agent_id_returns_400(pool: PgPool) {
    let env = TestEnv::new(pool);
    let (status, _) = env.get("/v1/agents/not%20an%20id").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}
