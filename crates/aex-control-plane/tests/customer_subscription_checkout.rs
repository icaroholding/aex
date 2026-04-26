//! Integration tests for the new subscription + checkout endpoints
//! (Sprint 4 PR 8).
//!
//! Subscription endpoint (`/v1/customer/subscription`) is fully
//! exercised because all the data lives in our DB. Checkout endpoint
//! (`/v1/checkout/session`) is exercised only on the client-side
//! paths (config gate, bad tier, missing config) — the success path
//! requires a real Stripe API call and is verified via a manual
//! smoke test post-deploy.

mod common;

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use serde_json::{json, Value};
use sqlx::PgPool;
use tower::ServiceExt;

use aex_control_plane::{
    clock::FrozenClock,
    config::{CustomerAuthConfig, StripeConfig},
    session,
};
use aex_policy::TierName;
use common::TestEnv;

const SESSION_SECRET: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const FRONTEND_BASE_URL: &str = "https://spize.io";
const FROZEN_NOW: i64 = 1_700_000_000;

/// TestEnv with customer auth + Stripe webhook config (no
/// `secret_key`, so checkout endpoint is intentionally unconfigured
/// for the 503 path tests).
fn env_no_checkout(pool: PgPool) -> TestEnv {
    TestEnv::with_state_override(pool, TierName::Dev, |s| {
        s.with_customer_auth(CustomerAuthConfig {
            session_secret: Some(SESSION_SECRET.into()),
            frontend_base_url: Some(FRONTEND_BASE_URL.into()),
        })
        .with_stripe(StripeConfig {
            webhook_secret: Some("whsec_x".into()),
            price_dev: Some("price_dev".into()),
            price_team: Some("price_team".into()),
            secret_key: None,
        })
        .with_clock(Arc::new(FrozenClock::new(FROZEN_NOW)))
    })
}

async fn seed_customer_with_subscription(
    pool: &PgPool,
    customer_id: &str,
    email: &str,
    tier: &str,
    status: &str,
) {
    let mut tx = pool.begin().await.unwrap();
    aex_control_plane::db::customers::upsert_in_tx(&mut tx, customer_id, email)
        .await
        .unwrap();
    aex_control_plane::db::subscriptions::upsert_in_tx(
        &mut tx,
        customer_id,
        &format!("sub_{customer_id}"),
        tier,
        status,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
}

fn issue_session_cookie(customer_id: &str) -> String {
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let token = session::issue(SESSION_SECRET, customer_id, 3600, now).unwrap();
    format!("{}={}", session::COOKIE_NAME, token)
}

async fn req_json(
    env: &TestEnv,
    method: &str,
    path: &str,
    cookie: Option<&str>,
) -> (StatusCode, Value) {
    let mut req = Request::builder().method(method).uri(path);
    if let Some(c) = cookie {
        req = req.header("cookie", c);
    }
    let req = req.body(Body::empty()).unwrap();
    let resp = env.app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 256 * 1024).await.unwrap();
    let json = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, json)
}

async fn post_json(env: &TestEnv, path: &str, body: Value) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = env.app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 256 * 1024).await.unwrap();
    let json = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, json)
}

// ---------- subscription endpoint ----------

#[sqlx::test]
async fn subscription_returns_data_for_active_customer(pool: PgPool) {
    seed_customer_with_subscription(&pool, "cus_sub", "s@example.com", "dev", "active").await;
    let env = env_no_checkout(pool);
    let cookie = issue_session_cookie("cus_sub");

    let (status, json) = req_json(&env, "GET", "/v1/customer/subscription", Some(&cookie)).await;
    assert_eq!(status, StatusCode::OK, "body = {json}");
    assert_eq!(json["tier"], "dev");
    assert_eq!(json["status"], "active");
    assert_eq!(json["stripe_subscription_id"], "sub_cus_sub");
}

#[sqlx::test]
async fn subscription_returns_404_when_no_row(pool: PgPool) {
    let env = env_no_checkout(pool);
    let cookie = issue_session_cookie("cus_nosub");

    let (status, json) = req_json(&env, "GET", "/v1/customer/subscription", Some(&cookie)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(json["code"], "not_found");
}

#[sqlx::test]
async fn subscription_requires_session(pool: PgPool) {
    let env = env_no_checkout(pool);
    let (status, json) = req_json(&env, "GET", "/v1/customer/subscription", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(json["runbook_url"]
        .as_str()
        .unwrap()
        .ends_with("session-invalid.md"));
}

#[sqlx::test]
async fn subscription_works_for_canceled_state_too(pool: PgPool) {
    // Frontend should still be able to read the canceled status to
    // render the "your subscription was canceled, resubscribe" CTA.
    seed_customer_with_subscription(&pool, "cus_canc", "c@example.com", "team", "canceled").await;
    let env = env_no_checkout(pool);
    let cookie = issue_session_cookie("cus_canc");

    let (status, json) = req_json(&env, "GET", "/v1/customer/subscription", Some(&cookie)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["status"], "canceled");
    assert_eq!(json["tier"], "team");
}

// ---------- checkout endpoint ----------

#[sqlx::test]
async fn checkout_returns_503_when_secret_key_missing(pool: PgPool) {
    let env = env_no_checkout(pool); // Stripe webhook configured but no secret_key
    let (status, json) = post_json(&env, "/v1/checkout/session", json!({"tier": "dev"})).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(json["code"], "checkout_disabled");
    assert!(json["runbook_url"]
        .as_str()
        .unwrap()
        .ends_with("checkout-disabled.md"));
}

#[sqlx::test]
async fn checkout_rejects_unknown_tier(pool: PgPool) {
    // Configure with secret_key so the config gate passes and we
    // reach the tier-validation branch.
    let env = TestEnv::with_state_override(pool, TierName::Dev, |s| {
        s.with_stripe(StripeConfig {
            webhook_secret: Some("whsec_x".into()),
            price_dev: Some("price_dev".into()),
            price_team: Some("price_team".into()),
            secret_key: Some("sk_test_fake_for_validation_only".into()),
        })
    });
    let (status, json) =
        post_json(&env, "/v1/checkout/session", json!({"tier": "enterprise"})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json["code"], "bad_request");
}

#[sqlx::test]
async fn checkout_rejects_missing_tier_field(pool: PgPool) {
    let env = env_no_checkout(pool);
    let (status, _) = post_json(&env, "/v1/checkout/session", json!({})).await;
    // serde rejects with 422 (axum's JSON extractor)
    assert!(
        status == StatusCode::BAD_REQUEST || status == StatusCode::UNPROCESSABLE_ENTITY,
        "expected 400 or 422, got {status}"
    );
}

#[sqlx::test]
async fn checkout_does_not_require_auth(pool: PgPool) {
    // Anonymous browsers should be able to call the endpoint; we
    // validate they hit the config gate (or tier validation) without
    // first being rejected as unauthenticated.
    let env = env_no_checkout(pool);
    let req = Request::builder()
        .method("POST")
        .uri("/v1/checkout/session")
        .header("content-type", "application/json")
        .body(Body::from(json!({"tier": "dev"}).to_string()))
        .unwrap();
    let resp = env.app.clone().oneshot(req).await.unwrap();
    // Expected: 503 because secret_key is missing — NOT 401.
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}
