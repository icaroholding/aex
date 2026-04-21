//! Shared test helpers for integration tests.
//!
//! [`TestEnv`] owns a single [`AppState`] + [`Router`] per test so that
//! in-memory pieces (blob store, audit log) are shared across every HTTP
//! request the test makes. Without this, a `create` + `download` pair
//! would talk to two distinct stores.

// Each integration-test binary compiles this module independently, so
// helpers used by only one binary trip `dead_code` in the other.
#![allow(dead_code)]

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use axum::Router;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use serde_json::Value;
use sqlx::PgPool;
use tower::ServiceExt;

use aex_audit::MemoryAuditLog;
use aex_control_plane::{blob::MemoryBlobStore, build_app, AppState};
use aex_policy::{TierName, TierPolicy};
use aex_scanner::{
    eicar::EicarScanner, injection::RegexInjectionScanner, magic::MagicByteScanner,
    size::SizeLimitScanner, ScanPipeline,
};

pub struct TestEnv {
    pub app: Router,
}

impl TestEnv {
    pub fn new(pool: PgPool) -> Self {
        Self::with_tier(pool, TierName::Dev)
    }

    pub fn with_tier(pool: PgPool, tier: TierName) -> Self {
        let scanner = ScanPipeline::new()
            .with_scanner(Arc::new(SizeLimitScanner::new(50 * 1024 * 1024)))
            .with_scanner(Arc::new(MagicByteScanner::new()))
            .with_scanner(Arc::new(EicarScanner::new()))
            .with_scanner(Arc::new(RegexInjectionScanner::new()));
        let state = AppState::new(
            pool,
            scanner,
            Arc::new(TierPolicy::for_tier(tier)),
            Arc::new(MemoryAuditLog::new()),
            Arc::new(MemoryBlobStore::new()),
        );
        Self {
            app: build_app(state),
        }
    }

    pub async fn request(&self, request: Request<Body>) -> (StatusCode, Value) {
        let resp = self.app.clone().oneshot(request).await.unwrap();
        let status = resp.status();
        let bytes = to_bytes(resp.into_body(), 256 * 1024 * 1024).await.unwrap();
        let json: Value = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap_or(Value::Null)
        };
        (status, json)
    }

    pub async fn post_json(&self, path: &str, body: &Value) -> (StatusCode, Value) {
        let req = Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(body).unwrap()))
            .unwrap();
        self.request(req).await
    }

    pub async fn get(&self, path: &str) -> (StatusCode, Value) {
        let req = Request::builder()
            .method("GET")
            .uri(path)
            .body(Body::empty())
            .unwrap();
        self.request(req).await
    }
}

pub fn random_nonce() -> String {
    use rand::RngCore;
    let mut buf = [0u8; 16];
    OsRng.fill_bytes(&mut buf);
    hex::encode(buf)
}

pub fn gen_signing_key() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}
