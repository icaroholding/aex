//! `POST /v2/intents` — wire-v2 transfer-intent verification endpoint.
//!
//! At v2.0 beta this is a structural stub: the endpoint exists so
//! capability-negotiating senders can detect v2 support, but the full
//! verification path (sender resolution via [`aex_identity::ResolverChain`],
//! JWS verification on agent card, scanner + policy + audit, dual-wire
//! dispatcher into the v1 transfer pipeline) lands as a follow-up PR.
//! The stub returns a structured 501 Not Implemented with a `Link`
//! header pointing at the rollout runbook so operators triaging
//! integration failures land on the right doc.
//!
//! See ADR-0043 §5 for the negotiation contract this endpoint
//! participates in.

use axum::{
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::IntoResponse,
    routing::post,
    Json, Router,
};
use serde::{Deserialize, Serialize};

use crate::AppState;

/// Request body for `POST /v2/intents`.
///
/// Fields mirror [`aex_core::wire_v2::transfer_intent_bytes_v2`] inputs
/// plus the JWS signature produced over those bytes by the sender.
/// The full handler verifies the JWS against the sender's resolved key
/// and forwards to the existing transfer pipeline.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct IntentBody {
    /// Sender agent_id (W3C DID URI or legacy `spize:`).
    pub sender: String,
    /// Recipient agent_id (same shape).
    pub recipient: String,
    /// Declared payload size in bytes.
    pub size: u64,
    /// Declared MIME (may be empty).
    #[serde(default)]
    pub mime: String,
    /// Declared filename (may be empty).
    #[serde(default)]
    pub filename: String,
    /// Hex nonce (32..128 chars, lowercase).
    pub nonce: String,
    /// Unix seconds timestamp.
    pub ts: i64,
    /// Sender's signature over the canonical wire-v2 bytes.
    /// Hex-encoded; 64 bytes for Ed25519, 64 for ES256K.
    pub signature_hex: String,
}

/// Stub response body emitted by the v2.0-beta `/v2/intents` handler.
#[derive(Debug, Clone, Serialize)]
pub struct StubBody {
    /// Stable error code so SDKs can branch.
    pub error: &'static str,
    /// Human-readable explanation.
    pub message: &'static str,
    /// URL to the rollout runbook.
    pub runbook: &'static str,
    /// Echo back the sender field so the caller can confirm the
    /// request parsed.
    pub echoed_sender: String,
}

async fn create_intent(Json(body): Json<IntentBody>) -> impl IntoResponse {
    let stub = StubBody {
        error: "not_implemented_yet",
        message: "POST /v2/intents is reserved for wire-v2 transfer verification \
             but the verification pipeline is staged for the v2.0 GA \
             follow-up sprint. See the rollout runbook.",
        runbook: "https://aex.dev/runbooks/v2-intent-stub",
        echoed_sender: body.sender,
    };
    let mut headers = HeaderMap::new();
    headers.insert(
        header::LINK,
        HeaderValue::from_static("<https://aex.dev/runbooks/v2-intent-stub>; rel=\"help\""),
    );
    (StatusCode::NOT_IMPLEMENTED, headers, Json(stub))
}

pub fn router() -> Router<AppState> {
    Router::new().route("/v2/intents", post(create_intent))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intent_body_serde_roundtrip() {
        let body = IntentBody {
            sender: "did:web:acme.com#alice".into(),
            recipient: "did:web:beta.com#bob".into(),
            size: 12345,
            mime: "application/pdf".into(),
            filename: "x.pdf".into(),
            nonce: "0123456789abcdef0123456789abcdef".into(),
            ts: 1_700_000_000,
            signature_hex: "ab".repeat(32),
        };
        let json = serde_json::to_string(&body).unwrap();
        let back: IntentBody = serde_json::from_str(&json).unwrap();
        assert_eq!(body.sender, back.sender);
        assert_eq!(body.nonce, back.nonce);
        assert_eq!(body.signature_hex, back.signature_hex);
    }

    #[test]
    fn intent_body_accepts_empty_optional_fields() {
        // `mime` and `filename` are #[serde(default)] so missing in the
        // JSON must parse cleanly.
        let json = r#"{
            "sender":"did:web:a.com#a",
            "recipient":"did:web:b.com#b",
            "size":1,
            "nonce":"0123456789abcdef0123456789abcdef",
            "ts":1,
            "signature_hex":"aa"
        }"#;
        let body: IntentBody = serde_json::from_str(json).unwrap();
        assert_eq!(body.mime, "");
        assert_eq!(body.filename, "");
    }

    #[tokio::test]
    async fn stub_handler_returns_501_with_runbook_link() {
        let body = IntentBody {
            sender: "did:web:acme.com#alice".into(),
            recipient: "did:web:beta.com#bob".into(),
            size: 1,
            mime: String::new(),
            filename: String::new(),
            nonce: "0123456789abcdef0123456789abcdef".into(),
            ts: 1,
            signature_hex: "aa".into(),
        };
        let resp = create_intent(Json(body)).await.into_response();
        assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
        let link = resp.headers().get(header::LINK).unwrap();
        assert!(link.to_str().unwrap().contains("v2-intent-stub"));
    }
}
