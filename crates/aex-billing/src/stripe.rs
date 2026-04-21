//! Stripe-backed billing provider (skeleton).
//!
//! The shape of the calls matches what the production implementation
//! will do — subscription status → tier, usage record → Billing Meter.
//! The HTTP calls themselves are TODOs pending:
//!
//! - Stripe secret key in env (`STRIPE_SECRET_KEY`)
//! - Product + Price + Meter configuration in the Stripe dashboard
//! - Org ↔ Stripe customer mapping (done at signup in the dashboard app)
//!
//! Until those exist, this provider falls back to a static table that
//! matches what we seed for alpha customers. When we ship the real
//! integration, swap the internals here without touching callers.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::RwLock;

use aex_policy::TierName;

use crate::{BillingError, BillingProvider, BillingResult};

pub struct StripeBilling {
    secret_key: String,
    #[allow(dead_code)]
    meter_event_name: String,
    org_to_customer: Arc<RwLock<HashMap<String, String>>>,
    customer_tiers: Arc<RwLock<HashMap<String, TierName>>>,
}

impl StripeBilling {
    pub fn from_env() -> BillingResult<Self> {
        let secret_key = std::env::var("STRIPE_SECRET_KEY").map_err(|_| {
            BillingError::Unavailable("STRIPE_SECRET_KEY env var is required".into())
        })?;
        Ok(Self::new(secret_key, "spize.transfers"))
    }

    pub fn new(secret_key: impl Into<String>, meter_event_name: impl Into<String>) -> Self {
        Self {
            secret_key: secret_key.into(),
            meter_event_name: meter_event_name.into(),
            org_to_customer: Arc::new(RwLock::new(HashMap::new())),
            customer_tiers: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Seed an org ↔ customer mapping at startup. Replaces the eventual
    /// "read from dashboard DB at startup" wiring.
    pub async fn register_org(
        &self,
        org: impl Into<String>,
        stripe_customer_id: impl Into<String>,
        tier: TierName,
    ) {
        let org = org.into();
        let cid = stripe_customer_id.into();
        self.org_to_customer.write().await.insert(org, cid.clone());
        self.customer_tiers.write().await.insert(cid, tier);
    }

    async fn customer_for(&self, org: &str) -> BillingResult<String> {
        self.org_to_customer
            .read()
            .await
            .get(org)
            .cloned()
            .ok_or_else(|| BillingError::UnknownOrg(org.to_string()))
    }
}

#[async_trait]
impl BillingProvider for StripeBilling {
    async fn tier_for(&self, org: &str) -> BillingResult<TierName> {
        let customer = self.customer_for(org).await?;
        // TODO(phase-h1-real): hit /v1/subscriptions?customer={customer}
        //                     and map price.lookup_key → TierName.
        Ok(self
            .customer_tiers
            .read()
            .await
            .get(&customer)
            .copied()
            .unwrap_or(TierName::FreeHuman))
    }

    async fn record_usage(
        &self,
        org: &str,
        transfer_id: &str,
        size_bytes: u64,
    ) -> BillingResult<()> {
        let customer = self.customer_for(org).await?;
        // TODO(phase-h1-real): POST /v1/billing/meter_events with
        //     event_name=self.meter_event_name,
        //     payload={stripe_customer_id: customer, value: 1},
        //     timestamp=unix_secs,
        //     identifier=transfer_id
        tracing::info!(
            target: "aex_billing::stripe",
            customer = %customer,
            org = org,
            transfer_id = transfer_id,
            size_bytes = size_bytes,
            meter = %self.meter_event_name,
            secret_configured = !self.secret_key.is_empty(),
            "usage recorded (skeleton — real Stripe call is TODO)"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn returns_free_when_org_unknown() {
        let b = StripeBilling::new("sk_test_xxx", "spize.transfers");
        let err = b.tier_for("acme").await.unwrap_err();
        assert!(matches!(err, BillingError::UnknownOrg(_)));
    }

    #[tokio::test]
    async fn registered_org_returns_seeded_tier() {
        let b = StripeBilling::new("sk_test_xxx", "spize.transfers");
        b.register_org("acme", "cus_123", TierName::Enterprise)
            .await;
        assert_eq!(b.tier_for("acme").await.unwrap(), TierName::Enterprise);
    }

    #[tokio::test]
    async fn record_usage_does_not_fail_in_skeleton_mode() {
        let b = StripeBilling::new("sk_test_xxx", "spize.transfers");
        b.register_org("acme", "cus_123", TierName::Dev).await;
        b.record_usage("acme", "tx_1", 42).await.unwrap();
    }
}
