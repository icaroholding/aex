//! Scanner pipeline for the Agent Exchange Protocol (AEX).
//!
//! A [`ScanPipeline`] runs N [`Scanner`] implementations in parallel over a
//! single input, aggregates their [`ScanVerdict`]s, and produces a single
//! [`PipelineVerdict`] that the control plane uses to gate delivery.
//!
//! # Aggregation rules
//!
//! - Any `Malicious` verdict → pipeline verdict is `Blocked`.
//! - Otherwise any `Error` → pipeline verdict is `Error` (fail-closed for
//!   enterprise, fail-open for dev — the *caller* interprets this).
//! - Otherwise any `Suspicious` → pipeline verdict is `Suspicious`.
//! - Otherwise → `Clean`.
//!
//! # MVP scanners
//!
//! - [`size::SizeLimitScanner`] — hard byte-count limit.
//! - [`magic::MagicByteScanner`] — verifies declared MIME against the first
//!   bytes of the payload (refuses renamed `.pdf.exe`-style smuggling).
//! - [`eicar::EicarScanner`] — flags the canonical EICAR malware test string.
//! - [`injection::RegexInjectionScanner`] — simple high-signal prompt
//!   injection patterns.
//!
//! Phase-2 scanners (Presidio, TruffleHog, fine-tuned classifier, Firecracker
//! isolation) plug into the same trait and can run alongside these.

pub mod eicar;
pub mod injection;
pub mod magic;
pub mod pipeline;
pub mod size;
pub mod verdict;

pub use pipeline::{ScanInput, ScanPipeline};
pub use verdict::{PipelineVerdict, ScanResult, ScanVerdict};

use async_trait::async_trait;

/// A single content-inspection stage.
#[async_trait]
pub trait Scanner: Send + Sync {
    /// Stable name that appears in audit entries. Do not rename in-place;
    /// add a new scanner and retire the old one.
    fn name(&self) -> &'static str;

    /// Run this scanner over the input and produce a verdict.
    async fn scan(&self, input: &ScanInput<'_>) -> ScanVerdict;
}
