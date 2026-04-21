//! Billing provider abstraction.
//!
//! The control plane asks the billing layer two things per transfer:
//!
//! 1. **What tier is this org on?** — drives which [`aex_policy::TierPolicy`]
//!    to apply (size cap, fail-open/closed, etc).
//! 2. **Here's a transfer that happened; record it.** — metered counter
//!    used for monthly invoices.
//!
//! # Implementations
//!
//! - [`InMemoryBilling`] — table-driven tier + in-process usage ring.
//!   Used by tests, self-hosted deploys, and the free tier.
//! - [`StripeBilling`] — reads tier from Stripe subscription status;
//!   records usage via `usage_record_summaries` / Stripe Billing Meters.
//!   M5-grade implementation is stubbed here; the shape is correct but
//!   the Stripe HTTP calls are TODOs until we have API keys.
//!
//! Pricing cents-per-transfer are not decided by this layer; the tier
//! mapping is "enterprise → flat fee", "dev → $0.002/transfer", "free →
//! zero". The price schedule itself lives in Stripe product configuration.

pub mod error;
pub mod memory;
pub mod stripe;

pub use error::{BillingError, BillingResult};
pub use memory::InMemoryBilling;
pub use stripe::StripeBilling;

use aex_policy::TierName;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// Identifier the billing backend uses for an org. Shape varies per
/// provider (Stripe = `cus_…`, in-memory = org name).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustomerId(pub String);

impl From<&str> for CustomerId {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageRecord {
    pub org: String,
    pub transfer_id: String,
    pub size_bytes: u64,
    #[serde(with = "time::serde::rfc3339")]
    pub at: time::OffsetDateTime,
}

#[async_trait]
pub trait BillingProvider: Send + Sync {
    /// Look up the tier for the org owning `org`. Providers decide
    /// what "owning" means (Stripe subscription, local config file,
    /// hard-coded dev tier).
    async fn tier_for(&self, org: &str) -> BillingResult<TierName>;

    /// Record that a transfer occurred. Called once per successful
    /// (non-rejected) transfer. Failures here MUST NOT block delivery
    /// — callers log warnings and continue.
    async fn record_usage(
        &self,
        org: &str,
        transfer_id: &str,
        size_bytes: u64,
    ) -> BillingResult<()>;
}
