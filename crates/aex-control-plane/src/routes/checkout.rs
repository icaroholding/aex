//! Public Stripe Checkout endpoint (Sprint 4 PR 8).
//!
//! `POST /v1/checkout/session` is the backend half of the
//! `/pricing` page's Subscribe buttons. Anonymous browsers call it,
//! we call Stripe to mint a Checkout Session, return the URL, and
//! the frontend redirects the browser there. No auth required —
//! anyone can attempt a purchase.
//!
//! Subscription state is mirrored back into our DB by the
//! `customer.subscription.created` webhook AFTER the user completes
//! payment on Stripe's hosted page. This endpoint is fire-and-forget
//! from the control plane's perspective.

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Json, Response},
    routing::post,
    Router,
};
use serde::{Deserialize, Serialize};

use crate::{
    error::ApiError,
    stripe::{self as stripe_api, CreateCheckoutSession, StripeError},
    AppState,
};

pub fn router() -> Router<AppState> {
    Router::new().route("/session", post(create_session))
}

#[derive(Deserialize)]
pub struct CheckoutBody {
    /// Human-readable tier name. Today: `"dev"` or `"team"`. The
    /// backend resolves it to a Stripe `price_…` id via the
    /// `STRIPE_PRICE_DEV` / `STRIPE_PRICE_TEAM` env vars so the
    /// frontend never holds the raw ids.
    pub tier: String,
    /// Optional pre-fill for the Checkout email field. Used when
    /// an already-known customer is upgrading. Anonymous purchases
    /// pass `None` and let Stripe collect the email.
    #[serde(default)]
    pub email: Option<String>,
}

#[derive(Serialize)]
pub struct CheckoutResponse {
    /// URL the browser MUST be redirected to (typically via
    /// `window.location.href = url`). Stripe's hosted page handles
    /// card collection + 3DS + receipt.
    pub url: String,
}

async fn create_session(
    State(state): State<AppState>,
    Json(body): Json<CheckoutBody>,
) -> Result<Json<CheckoutResponse>, Response> {
    if !state.stripe.checkout_ready() {
        return Err(checkout_disabled_response());
    }

    let price_id = match body.tier.as_str() {
        "dev" => state.stripe.price_dev.as_deref().unwrap(),
        "team" => state.stripe.price_team.as_deref().unwrap(),
        other => {
            return Err(ApiError::BadRequest(format!(
                "unknown tier '{other}'; valid tiers: dev, team"
            ))
            .into_response());
        }
    };

    let frontend = state
        .customer_auth
        .frontend_base_url
        .as_deref()
        .unwrap_or("https://spize.io");
    let success_url = format!("{frontend}/login?welcome=true");
    let cancel_url = format!("{frontend}/pricing");

    let req = CreateCheckoutSession {
        price_id,
        success_url: &success_url,
        cancel_url: &cancel_url,
        customer_email: body.email.as_deref().filter(|e| !e.is_empty()),
    };

    match stripe_api::create_checkout_session(&state.stripe, &req).await {
        Ok(session) => {
            tracing::info!(
                tier = %body.tier,
                session_id = %session.id,
                "created stripe checkout session"
            );
            Ok(Json(CheckoutResponse { url: session.url }))
        }
        Err(StripeError::NotConfigured) => Err(checkout_disabled_response()),
        Err(e) => {
            tracing::error!(error = %e, "stripe checkout session creation failed");
            Err(ApiError::Internal(Box::new(crate::error::SimpleError(
                "stripe checkout creation failed; try again or contact support".into(),
            )))
            .into_response())
        }
    }
}

fn checkout_disabled_response() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(serde_json::json!({
            "code": "checkout_disabled",
            "message": "checkout not configured; set STRIPE_SECRET_KEY + STRIPE_PRICE_DEV + STRIPE_PRICE_TEAM and restart",
            "runbook_url": crate::error::runbook::runbook_url("checkout_disabled", "")
        })),
    )
        .into_response()
}
