//! Policy engine for the Agent Exchange Protocol (AEX).
//!
//! A [`PolicyEngine`] receives a [`PolicyRequest`] describing a proposed
//! transfer (sender, recipient, size, MIME, optional scan verdict) and
//! returns a [`PolicyDecision`]: `Allow` or `Deny { reason, code }`.
//!
//! # Evaluation points
//!
//! The control plane calls the engine at **two** points for each transfer:
//!
//! 1. **Pre-scan** — with `scanner_verdict = None`. Fast checks: size limit,
//!    MIME block-list, sender/recipient policy. Denials here skip the
//!    scanner entirely, saving resources.
//! 2. **Post-scan** — with `scanner_verdict = Some(...)`. The engine can
//!    combine scanner findings with policy: e.g. dev tier passes
//!    `Suspicious` but enterprise blocks it.
//!
//! # Implementations
//!
//! - [`TierPolicy`] — table-driven rules (size cap, MIME deny, suspicious
//!   tolerance). Covers the first year SaaS tiers.
//! - *(Phase G2)* `CedarPolicy` — Cedar DSL files deployed per org for
//!   SOC2/GDPR compliance packs. Uses the same trait, drops in without
//!   API changes.

pub mod decision;
pub mod request;
pub mod tier;

pub use decision::{PolicyDecision, TierName};
pub use request::{PolicyRequest, RecipientKind};
pub use tier::TierPolicy;

use async_trait::async_trait;

#[async_trait]
pub trait PolicyEngine: Send + Sync {
    async fn evaluate(&self, req: &PolicyRequest<'_>) -> PolicyDecision;
}
