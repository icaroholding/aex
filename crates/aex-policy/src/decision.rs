use serde::{Deserialize, Serialize};

/// The only two outcomes a policy can produce. Any richer signalling
/// (rate-limit, requires-mfa, needs-additional-scan) is represented as
/// `Deny` with a specific `code` plus guidance in `reason`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PolicyDecision {
    Allow,
    Deny {
        /// Stable machine-readable reason. Clients use it to branch;
        /// dashboards use it as the group-by key. Adding codes is safe,
        /// changing a code's meaning is not.
        code: &'static str,
        /// Human-readable explanation shown in logs and dashboards.
        reason: String,
    },
}

impl PolicyDecision {
    pub fn deny(code: &'static str, reason: impl Into<String>) -> Self {
        Self::Deny {
            code,
            reason: reason.into(),
        }
    }

    pub fn is_allow(&self) -> bool {
        matches!(self, Self::Allow)
    }
}

/// Name of a preset tier used by [`crate::TierPolicy::for_tier`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TierName {
    /// Dev tier: fail-open on scanner errors, 100 MB size cap, suspicious
    /// findings allowed (with warning in audit).
    Dev,
    /// Enterprise tier: fail-closed on scanner errors, 5 GB size cap,
    /// suspicious findings blocked.
    Enterprise,
    /// Free human-v1: tiny caps, no agent receive, used as hard default.
    FreeHuman,
}
