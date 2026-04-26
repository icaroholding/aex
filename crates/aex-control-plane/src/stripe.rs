//! Outbound Stripe API client (Sprint 4 PR 8).
//!
//! Same philosophy as `crate::email::resend`: provider-agnostic at
//! the call site, no SDK. Stripe's REST surface is form-encoded
//! POSTs with a Bearer token — we have `reqwest` for that.
//!
//! This module exposes the **two** outbound calls the dashboard
//! makes: creating a Checkout Session (for the `/pricing` Subscribe
//! buttons) and creating a Customer Portal Session (future, for
//! the dashboard "Manage subscription" button — not yet wired but
//! the helper is here so the next PR can drop it in).

use serde::Deserialize;

use crate::config::StripeConfig;

const STRIPE_API_BASE: &str = "https://api.stripe.com/v1";

#[derive(Debug, thiserror::Error)]
pub enum StripeError {
    #[error("stripe API not configured (STRIPE_SECRET_KEY unset)")]
    NotConfigured,
    #[error("transport error: {0}")]
    Transport(#[from] reqwest::Error),
    #[error("stripe returned {status}: {body}")]
    Provider {
        status: reqwest::StatusCode,
        body: String,
    },
}

/// What the dashboard needs from a Checkout Session creation. We
/// don't surface the full Stripe object — just the `url` the user's
/// browser must redirect to.
#[derive(Debug, Deserialize)]
pub struct CheckoutSession {
    pub id: String,
    pub url: String,
}

/// Configurable bits the caller controls per checkout.
#[derive(Debug, Clone)]
pub struct CreateCheckoutSession<'a> {
    /// Stripe `price.id` (`price_…`). The caller maps the human
    /// tier name (`dev` / `team`) to the actual id via env-var
    /// lookup.
    pub price_id: &'a str,
    /// Where Stripe sends the user on successful payment. Should
    /// land on a frontend page that prompts magic-link login —
    /// the user hasn't been authenticated yet on our side, just on
    /// Stripe's.
    pub success_url: &'a str,
    /// Where Stripe sends the user if they cancel mid-checkout.
    pub cancel_url: &'a str,
    /// Optional pre-fill for the email field in Checkout. When
    /// provided, the user can't change it (Stripe locks the
    /// field), so only set it if the caller is sure of the value
    /// (e.g. a logged-in user buying a different plan).
    pub customer_email: Option<&'a str>,
}

/// Create a Stripe Checkout Session for a subscription. Returns
/// the session with its `url` field — the caller should respond
/// to the browser with that URL so the customer can complete
/// payment on Stripe's hosted page.
pub async fn create_checkout_session(
    cfg: &StripeConfig,
    req: &CreateCheckoutSession<'_>,
) -> Result<CheckoutSession, StripeError> {
    let secret = cfg
        .secret_key
        .as_deref()
        .ok_or(StripeError::NotConfigured)?;

    // Stripe accepts form-encoded bodies for legacy reasons. Build
    // the (key, value) pairs explicitly — `serde_urlencoded` plays
    // poorly with nested Stripe-style brackets like `line_items[0][price]`.
    let mut form: Vec<(&'static str, String)> = vec![
        ("mode", "subscription".into()),
        ("line_items[0][price]", req.price_id.into()),
        ("line_items[0][quantity]", "1".into()),
        ("success_url", req.success_url.into()),
        ("cancel_url", req.cancel_url.into()),
        ("allow_promotion_codes", "true".into()),
    ];
    if let Some(email) = req.customer_email {
        form.push(("customer_email", email.into()));
    }

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{STRIPE_API_BASE}/checkout/sessions"))
        .bearer_auth(secret)
        .form(&form)
        .send()
        .await?;

    let status = resp.status();
    if !status.is_success() {
        let body = resp
            .text()
            .await
            .unwrap_or_else(|_| "<could not read upstream body>".into());
        return Err(StripeError::Provider { status, body });
    }
    let session: CheckoutSession = resp.json().await?;
    Ok(session)
}

/// What the dashboard needs from a Customer Portal session — just
/// the `url` to redirect the browser to.
#[derive(Debug, Deserialize)]
pub struct PortalSession {
    pub id: String,
    pub url: String,
}

/// Create a Stripe Customer Portal session so a logged-in customer
/// can manage their subscription (cancel, change card, view
/// invoices) on Stripe's hosted UI. NOT wired to a route yet; ships
/// with this module so the next dashboard PR can drop it in.
#[allow(dead_code)]
pub async fn create_portal_session(
    cfg: &StripeConfig,
    stripe_customer_id: &str,
    return_url: &str,
) -> Result<PortalSession, StripeError> {
    let secret = cfg
        .secret_key
        .as_deref()
        .ok_or(StripeError::NotConfigured)?;

    let form: Vec<(&'static str, String)> = vec![
        ("customer", stripe_customer_id.into()),
        ("return_url", return_url.into()),
    ];

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{STRIPE_API_BASE}/billing_portal/sessions"))
        .bearer_auth(secret)
        .form(&form)
        .send()
        .await?;

    let status = resp.status();
    if !status.is_success() {
        let body = resp
            .text()
            .await
            .unwrap_or_else(|_| "<could not read upstream body>".into());
        return Err(StripeError::Provider { status, body });
    }
    let session: PortalSession = resp.json().await?;
    Ok(session)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_checkout_returns_not_configured_when_secret_missing() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let cfg = StripeConfig::default();
        let req = CreateCheckoutSession {
            price_id: "price_x",
            success_url: "https://x/",
            cancel_url: "https://x/",
            customer_email: None,
        };
        let err = rt
            .block_on(create_checkout_session(&cfg, &req))
            .unwrap_err();
        assert!(matches!(err, StripeError::NotConfigured));
    }

    #[test]
    fn create_portal_returns_not_configured_when_secret_missing() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let cfg = StripeConfig::default();
        let err = rt
            .block_on(create_portal_session(&cfg, "cus_x", "https://x/"))
            .unwrap_err();
        assert!(matches!(err, StripeError::NotConfigured));
    }
}
