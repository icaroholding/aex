//! Customer subscription status endpoint (Sprint 4 PR 8).
//!
//! Behind the session middleware. Returns the customer's current
//! plan + status so the dashboard can render a "Your plan: Dev —
//! active" banner without a separate Stripe round-trip.
//!
//! All data here is mirrored from Stripe via the `customer.subscription.*`
//! webhook handlers — Stripe is the source of truth, this table is
//! the read-cache.

use axum::{extract::Extension, extract::State, response::Json, routing::get, Router};
use serde::Serialize;

use crate::{error::ApiError, session::CustomerSession, AppState};

pub fn router() -> Router<AppState> {
    Router::new().route("/subscription", get(get_subscription))
}

#[derive(Serialize)]
pub struct SubscriptionResponse {
    /// Tier the customer is paying for (`dev` / `team` / future
    /// values). Free-text on the wire — frontend pattern-matches.
    pub tier: String,
    /// Stripe subscription status, copied verbatim. Common values:
    /// `active`, `trialing`, `past_due`, `canceled`, `incomplete`,
    /// `incomplete_expired`, `unpaid`. Frontend renders different
    /// banners per status (active = green, past_due = yellow,
    /// canceled = red + "resubscribe" CTA).
    pub status: String,
    /// Stripe subscription id (`sub_…`). Useful for support
    /// tickets — operator can search Stripe dashboard by it.
    pub stripe_subscription_id: String,
}

async fn get_subscription(
    State(state): State<AppState>,
    Extension(session): Extension<CustomerSession>,
) -> Result<Json<SubscriptionResponse>, ApiError> {
    let row: Option<(String, String, String)> = sqlx::query_as(
        r#"
        SELECT tier, status, stripe_subscription_id
        FROM subscriptions
        WHERE stripe_customer_id = $1
        "#,
    )
    .bind(&session.sub)
    .fetch_optional(&state.db)
    .await?;

    match row {
        Some((tier, status, stripe_subscription_id)) => Ok(Json(SubscriptionResponse {
            tier,
            status,
            stripe_subscription_id,
        })),
        None => Err(ApiError::NotFound(
            "no subscription on file for this customer".into(),
        )),
    }
}
