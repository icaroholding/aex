use serde::{Deserialize, Serialize};

/// Outcomes a policy engine can produce.
///
/// `Allow` and `Deny` are the historical synchronous outcomes — the
/// engine decides immediately.
///
/// `Pending` is the deferred-decision outcome introduced in v2.1
/// (ADR-0049): the engine cannot answer right now and the recipient
/// will respond later via a signed
/// `aex-decision-response:v2` message. Senders observing this
/// outcome must hold the transfer in a waiting state until the
/// response arrives or the decision TTL expires.
///
/// Any richer synchronous signalling (rate-limit, requires-mfa,
/// needs-additional-scan) continues to be represented as `Deny` with
/// a specific `code`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PolicyDecision {
    /// Synchronous accept: transfer proceeds immediately.
    Allow,
    /// Synchronous reject with a stable machine-readable code.
    Deny {
        /// Stable machine-readable reason. Clients use it to branch;
        /// dashboards use it as the group-by key. Adding codes is safe,
        /// changing a code's meaning is not.
        code: &'static str,
        /// Human-readable explanation shown in logs and dashboards.
        reason: String,
    },
    /// Deferred decision (v2.1 / ADR-0049). The engine has accepted
    /// the request for processing but cannot decide yet. The control
    /// plane should:
    /// 1. Persist the pending decision keyed by `decision_id`.
    /// 2. Sign and emit an `aex-decision-request:v2` to the sender.
    /// 3. Forward to the configured [`crate::DecisionSink`] (a
    ///    human prompt, a webhook, a secondary AI evaluator, ...).
    /// 4. Wait for the sink to call back with the final
    ///    accept/reject; emit a signed
    ///    `aex-decision-response:v2` to the sender and record the
    ///    receipt in the audit chain.
    Pending {
        /// Unique identifier for this pending decision. The same
        /// value lands in the `aex-decision-request:v2` and the
        /// corresponding `aex-decision-response:v2`.
        decision_id: String,
        /// Hint for the sender on how long to wait before treating
        /// the transfer as stalled. `0` means "as soon as
        /// practical".
        eta_seconds: u64,
    },
}

impl PolicyDecision {
    /// Construct a synchronous deny with the given stable code and
    /// human-readable reason.
    pub fn deny(code: &'static str, reason: impl Into<String>) -> Self {
        Self::Deny {
            code,
            reason: reason.into(),
        }
    }

    /// Construct a deferred-decision outcome.
    ///
    /// `decision_id` SHOULD be unique within the recipient's
    /// namespace. The convenience helper [`Self::pending_new`] mints
    /// a fresh UUID v4 for callers that don't have an external ID
    /// scheme.
    pub fn pending(decision_id: impl Into<String>, eta_seconds: u64) -> Self {
        Self::Pending {
            decision_id: decision_id.into(),
            eta_seconds,
        }
    }

    /// Construct a deferred-decision outcome with a fresh UUID v4
    /// decision id.
    pub fn pending_new(eta_seconds: u64) -> Self {
        Self::Pending {
            decision_id: format!("dec_{}", uuid::Uuid::new_v4().simple()),
            eta_seconds,
        }
    }

    /// True iff this decision is `Allow`. Pending and Deny both
    /// answer false; callers that want to distinguish synchronous
    /// reject from deferred wait must match on the variant directly.
    pub fn is_allow(&self) -> bool {
        matches!(self, Self::Allow)
    }

    /// True iff this decision is a `Pending` deferred-decision.
    pub fn is_pending(&self) -> bool {
        matches!(self, Self::Pending { .. })
    }

    /// Borrow the `decision_id` if this is a pending decision.
    pub fn decision_id(&self) -> Option<&str> {
        match self {
            Self::Pending { decision_id, .. } => Some(decision_id),
            _ => None,
        }
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
