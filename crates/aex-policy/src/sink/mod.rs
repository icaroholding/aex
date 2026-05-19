//! `DecisionSink` — pluggable backend that produces a final
//! accept/reject for a deferred-decision (ADR-0049).
//!
//! When the [`crate::PolicyEngine`] returns
//! [`crate::PolicyDecision::Pending`], the control plane forwards the
//! decision request to the configured sink. The sink is responsible
//! for collecting the decision from whoever decides — a human, a
//! secondary AI, a webhook on a compliance system, a consensus of
//! agents — and reporting back the outcome.
//!
//! Two reference implementations ship in the standard distribution:
//!
//! - [`InProcessDecisionSink`] — a closure-based sink. The decision
//!   is taken synchronously inside the same process: useful for
//!   in-process LLM evaluators, local prompts, deterministic policy
//!   functions.
//!
//! - [`WebhookDecisionSink`] — an HTTP POST sink. The sink calls a
//!   user-configured webhook URL; the webhook is expected to call
//!   back the control plane with a signed
//!   `aex-decision-response:v2`. Useful for enterprise approval
//!   systems, off-process orchestrators, multi-tenant routing.
//!
//! The protocol takes no position on who or what is the decider.
//! Both sinks are agnostic to that question.

use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub mod in_process;
pub mod webhook;

pub use in_process::InProcessDecisionSink;
pub use webhook::{WebhookDecisionSink, WebhookSinkError};

/// Final outcome of a deferred decision.
///
/// Matches the `outcome` field of an `aex-decision-response:v2`
/// canonical message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionOutcome {
    /// The decider accepted the transfer; it may proceed.
    Accepted,
    /// The decider rejected the transfer; it must be discarded.
    Rejected,
}

impl DecisionOutcome {
    /// Stable wire-string name. **Never rename** — it lands in
    /// the signed `aex-decision-response:v2` payload.
    pub const fn as_str(self) -> &'static str {
        match self {
            DecisionOutcome::Accepted => "accepted",
            DecisionOutcome::Rejected => "rejected",
        }
    }
}

impl fmt::Display for DecisionOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Payload the sink receives. Carries everything the decider needs
/// to make a choice plus the protocol-level identifier of the
/// pending decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionRequest {
    /// Identifier minted when the policy engine returned
    /// [`crate::PolicyDecision::Pending`].
    pub decision_id: String,
    /// Transfer id this decision belongs to.
    pub transfer_id: String,
    /// Agent id of the sender requesting the transfer.
    pub sender_agent_id: String,
    /// Agent id of the recipient that must decide.
    pub recipient_agent_id: String,
    /// Declared MIME type. May be empty.
    pub declared_mime: String,
    /// Declared filename. May be empty.
    pub filename: String,
    /// Declared size in bytes.
    pub size_bytes: u64,
    /// Operator-friendly summary the sink may surface to the
    /// decider. Free-text, not signed.
    pub summary: String,
}

/// Final response the sink reports back.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionResponse {
    /// Same `decision_id` from the corresponding [`DecisionRequest`].
    pub decision_id: String,
    /// Final outcome.
    pub outcome: DecisionOutcome,
    /// Optional human-readable reason. Empty allowed.
    pub reason: String,
}

/// Errors a sink can surface to the caller.
#[derive(Debug, Error)]
pub enum DecisionSinkError {
    /// The sink completed but rejected the request before the
    /// decider was even consulted (e.g. malformed input).
    #[error("decision sink rejected request: {0}")]
    Rejected(String),
    /// The decider timed out and the sink gave up waiting.
    #[error("decision sink timed out waiting for decider")]
    Timeout,
    /// The sink hit an unrelated infrastructure error
    /// (database, network, configuration).
    #[error("decision sink infrastructure error: {0}")]
    Infra(String),
}

/// The trait implementations of "where the decision is produced".
///
/// Sinks must be `Send + Sync` because the control plane drives
/// them from a Tokio-async context. The synchronous [`Self::submit`]
/// returns `Ok(())` when the sink has accepted responsibility for
/// the decision — the actual outcome arrives via a callback to the
/// control plane (typically as an `aex-decision-response:v2`).
///
/// Two delivery patterns are supported:
///
/// - **Synchronous**: the sink computes the outcome inside
///   `submit` and emits the response itself (see
///   [`InProcessDecisionSink`]).
///
/// - **Asynchronous**: the sink dispatches the request to an
///   external system and returns immediately. The external system
///   later POSTs the signed response to the control plane (see
///   [`WebhookDecisionSink`]).
#[async_trait::async_trait]
pub trait DecisionSink: Send + Sync {
    /// Hand the decision request to the sink. On success the sink
    /// has accepted responsibility for producing a response; the
    /// caller does not block on completion.
    ///
    /// The sink MUST NOT panic; any failure must surface via
    /// [`DecisionSinkError`].
    async fn submit(&self, request: DecisionRequest) -> Result<(), DecisionSinkError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outcome_strings_are_stable() {
        assert_eq!(DecisionOutcome::Accepted.as_str(), "accepted");
        assert_eq!(DecisionOutcome::Rejected.as_str(), "rejected");
    }

    #[test]
    fn outcome_serde_roundtrip() {
        let j = serde_json::to_string(&DecisionOutcome::Accepted).unwrap();
        assert_eq!(j, "\"accepted\"");
        let back: DecisionOutcome = serde_json::from_str(&j).unwrap();
        assert_eq!(back, DecisionOutcome::Accepted);
    }

    #[test]
    fn request_response_serde_roundtrip() {
        let req = DecisionRequest {
            decision_id: "dec_001".into(),
            transfer_id: "tx_abc".into(),
            sender_agent_id: "did:web:a.com#a".into(),
            recipient_agent_id: "did:web:b.com#b".into(),
            declared_mime: "application/pdf".into(),
            filename: "x.pdf".into(),
            size_bytes: 1024,
            summary: "Q3 invoice".into(),
        };
        let j = serde_json::to_string(&req).unwrap();
        let back: DecisionRequest = serde_json::from_str(&j).unwrap();
        assert_eq!(req.decision_id, back.decision_id);
        assert_eq!(req.size_bytes, back.size_bytes);

        let resp = DecisionResponse {
            decision_id: "dec_001".into(),
            outcome: DecisionOutcome::Rejected,
            reason: "budget exceeded".into(),
        };
        let j = serde_json::to_string(&resp).unwrap();
        let back: DecisionResponse = serde_json::from_str(&j).unwrap();
        assert_eq!(back.outcome, DecisionOutcome::Rejected);
        assert_eq!(back.reason, "budget exceeded");
    }
}
