//! In-memory billing provider.
//!
//! Fine for self-hosted deployments, integration tests, and the free
//! tier where metered billing isn't active anyway. Tiers can be seeded
//! from config; usage is appended to a capped ring buffer (usage numbers
//! are still useful for dashboards even without Stripe).

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::RwLock;

use aex_policy::TierName;

use crate::{BillingProvider, BillingResult, UsageRecord};

const USAGE_RING_MAX: usize = 10_000;

pub struct InMemoryBilling {
    tiers: Arc<RwLock<HashMap<String, TierName>>>,
    default_tier: TierName,
    usage: Arc<RwLock<Vec<UsageRecord>>>,
}

impl InMemoryBilling {
    pub fn new(default_tier: TierName) -> Self {
        Self {
            tiers: Arc::new(RwLock::new(HashMap::new())),
            default_tier,
            usage: Arc::new(RwLock::new(Vec::with_capacity(128))),
        }
    }

    pub async fn set_tier(&self, org: &str, tier: TierName) {
        self.tiers.write().await.insert(org.to_string(), tier);
    }

    pub async fn usage_snapshot(&self) -> Vec<UsageRecord> {
        self.usage.read().await.clone()
    }

    pub async fn usage_for_org(&self, org: &str) -> Vec<UsageRecord> {
        self.usage
            .read()
            .await
            .iter()
            .filter(|r| r.org == org)
            .cloned()
            .collect()
    }

    pub async fn total_bytes_for_org(&self, org: &str) -> u64 {
        self.usage
            .read()
            .await
            .iter()
            .filter(|r| r.org == org)
            .map(|r| r.size_bytes)
            .sum()
    }
}

#[async_trait]
impl BillingProvider for InMemoryBilling {
    async fn tier_for(&self, org: &str) -> BillingResult<TierName> {
        Ok(self
            .tiers
            .read()
            .await
            .get(org)
            .copied()
            .unwrap_or(self.default_tier))
    }

    async fn record_usage(
        &self,
        org: &str,
        transfer_id: &str,
        size_bytes: u64,
    ) -> BillingResult<()> {
        let mut guard = self.usage.write().await;
        if guard.len() >= USAGE_RING_MAX {
            // Drop oldest 10% — cheap, keeps recent history available.
            let drop_to = USAGE_RING_MAX / 10;
            guard.drain(..drop_to);
        }
        guard.push(UsageRecord {
            org: org.to_string(),
            transfer_id: transfer_id.to_string(),
            size_bytes,
            at: time::OffsetDateTime::now_utc(),
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn default_tier_returned_for_unknown_org() {
        let b = InMemoryBilling::new(TierName::Dev);
        assert_eq!(b.tier_for("unknown").await.unwrap(), TierName::Dev);
    }

    #[tokio::test]
    async fn set_tier_overrides_default() {
        let b = InMemoryBilling::new(TierName::Dev);
        b.set_tier("acme", TierName::Enterprise).await;
        assert_eq!(b.tier_for("acme").await.unwrap(), TierName::Enterprise);
        assert_eq!(b.tier_for("unknown").await.unwrap(), TierName::Dev);
    }

    #[tokio::test]
    async fn usage_sums_correctly_per_org() {
        let b = InMemoryBilling::new(TierName::Dev);
        b.record_usage("acme", "tx_1", 100).await.unwrap();
        b.record_usage("acme", "tx_2", 200).await.unwrap();
        b.record_usage("bigco", "tx_3", 500).await.unwrap();

        assert_eq!(b.total_bytes_for_org("acme").await, 300);
        assert_eq!(b.total_bytes_for_org("bigco").await, 500);
        assert_eq!(b.usage_for_org("acme").await.len(), 2);
    }
}
