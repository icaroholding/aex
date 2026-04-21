//! Sigstore Rekor transparency-log anchoring.
//!
//! Hash-chaining (see [`crate::AuditLog`]) makes retroactive tampering
//! detectable *locally* — any auditor with the latest chain head can
//! spot a rewrite. But "locally" is doing heavy lifting: we still trust
//! ourselves to publish the head honestly.
//!
//! Anchoring to [Sigstore Rekor](https://docs.sigstore.dev/logging/overview/)
//! breaks that trust assumption. Rekor is a public append-only Merkle
//! log operated by the Sigstore project. Once we push a chain head
//! there, we cannot claim a different head ever existed at that moment.
//! Anyone watching Rekor can independently detect forked histories.
//!
//! # What this module ships
//!
//! - [`RekorSubmitter`] trait — abstracts the actual submission.
//! - [`StubRekorSubmitter`] — in-memory; tests + dev-tier default.
//! - [`LoggingRekorSubmitter`] — just `tracing::info!`s each head; used
//!   until we wire the real REST client.
//! - [`RekorAnchoredAuditLog`] — wraps any [`AuditLog`] and periodically
//!   submits its current head via a background task.
//!
//! A real `HttpRekorSubmitter` (hitting `rekor.sigstore.dev`) is a
//! follow-up since it needs signed log entry metadata per Rekor's
//! rekord schema; not worth sticking a half-baked HTTP client in the
//! audit crate for M4.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use tokio::sync::Mutex;

use crate::{AuditError, AuditLog, AuditResult};

/// Receipt returned after a successful submission. Opaque payload —
/// Sigstore's actual response is tree-specific; callers only care about
/// the identifier to prove "we submitted this head".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RekorReceipt {
    pub submission_id: String,
    pub chain_head: String,
    pub position: u64,
    #[serde(with = "time::serde::rfc3339")]
    pub submitted_at: OffsetDateTime,
}

#[async_trait]
pub trait RekorSubmitter: Send + Sync {
    async fn submit(&self, chain_head: &str, position: u64) -> AuditResult<RekorReceipt>;
}

/// No-op submitter: remembers every head it's been asked to submit, so
/// tests can assert on frequency + payload.
#[derive(Default)]
pub struct StubRekorSubmitter {
    received: Arc<Mutex<Vec<RekorReceipt>>>,
}

impl StubRekorSubmitter {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn history(&self) -> Vec<RekorReceipt> {
        self.received.lock().await.clone()
    }
}

#[async_trait]
impl RekorSubmitter for StubRekorSubmitter {
    async fn submit(&self, chain_head: &str, position: u64) -> AuditResult<RekorReceipt> {
        let receipt = RekorReceipt {
            submission_id: format!("stub_{}", uuid::Uuid::new_v4().simple()),
            chain_head: chain_head.to_string(),
            position,
            submitted_at: OffsetDateTime::now_utc(),
        };
        self.received.lock().await.push(receipt.clone());
        Ok(receipt)
    }
}

/// Writes each submission to `tracing`. Useful in dev where we want to
/// see the chain head being published but don't have a Rekor endpoint.
pub struct LoggingRekorSubmitter;

#[async_trait]
impl RekorSubmitter for LoggingRekorSubmitter {
    async fn submit(&self, chain_head: &str, position: u64) -> AuditResult<RekorReceipt> {
        tracing::info!(
            target: "aex_audit::rekor",
            chain_head = chain_head,
            position = position,
            "chain head submitted (logging submitter)"
        );
        Ok(RekorReceipt {
            submission_id: format!("log_{}", uuid::Uuid::new_v4().simple()),
            chain_head: chain_head.to_string(),
            position,
            submitted_at: OffsetDateTime::now_utc(),
        })
    }
}

/// Wrap any [`AuditLog`] with a background task that periodically
/// submits the current chain head to a [`RekorSubmitter`].
pub struct RekorAnchoredAuditLog<Inner: AuditLog + Send + Sync + 'static> {
    inner: Arc<Inner>,
    submitter: Arc<dyn RekorSubmitter>,
    interval: Duration,
}

impl<Inner: AuditLog + Send + Sync + 'static> RekorAnchoredAuditLog<Inner> {
    pub fn new(inner: Inner, submitter: Arc<dyn RekorSubmitter>, interval: Duration) -> Self {
        Self {
            inner: Arc::new(inner),
            submitter,
            interval,
        }
    }

    /// Spawn the background submission loop. Returns the JoinHandle so
    /// callers can abort() on shutdown. The loop submits the CURRENT
    /// chain head every `interval`, whether or not it has changed.
    pub fn spawn_submission_loop(&self) -> tokio::task::JoinHandle<()> {
        let inner = self.inner.clone();
        let submitter = self.submitter.clone();
        let interval = self.interval;
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                ticker.tick().await;
                let head = match inner.current_head().await {
                    Ok(h) => h,
                    Err(e) => {
                        tracing::warn!(
                            target: "aex_audit::rekor",
                            error = %e,
                            "current_head failed; skipping Rekor submission tick"
                        );
                        continue;
                    }
                };
                let len = inner.len().await.unwrap_or(0);
                if let Err(e) = submitter.submit(&head, len).await {
                    tracing::warn!(
                        target: "aex_audit::rekor",
                        error = %e,
                        "Rekor submission failed (will retry on next tick)"
                    );
                }
            }
        })
    }

    /// Submit the current head once, synchronously. Handy for tests or
    /// for the graceful-shutdown path.
    pub async fn submit_now(&self) -> AuditResult<RekorReceipt> {
        let head = self.inner.current_head().await?;
        let len = self.inner.len().await?;
        self.submitter.submit(&head, len).await
    }

    pub fn inner(&self) -> &Inner {
        self.inner.as_ref()
    }
}

#[async_trait]
impl<Inner: AuditLog + Send + Sync + 'static> AuditLog for RekorAnchoredAuditLog<Inner> {
    async fn append(&self, event: crate::Event) -> AuditResult<crate::EventReceipt> {
        self.inner.append(event).await
    }

    async fn current_head(&self) -> AuditResult<String> {
        self.inner.current_head().await
    }

    async fn verify_chain(&self) -> AuditResult<()> {
        self.inner.verify_chain().await
    }

    async fn len(&self) -> AuditResult<u64> {
        self.inner.len().await
    }
}

// ---------- unused pass-through to keep thiserror happy ----------
#[allow(dead_code)]
fn _sanity_check(e: AuditError) -> AuditError {
    e
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Event, EventKind, MemoryAuditLog};

    #[tokio::test]
    async fn submit_now_captures_current_head() {
        let log = MemoryAuditLog::new();
        log.append(Event::new(
            EventKind::AgentRegistered,
            "actor",
            "subject",
            serde_json::json!({}),
        ))
        .await
        .unwrap();

        let stub = Arc::new(StubRekorSubmitter::new());
        let anchored = RekorAnchoredAuditLog::new(log, stub.clone(), Duration::from_secs(60));
        let receipt = anchored.submit_now().await.unwrap();
        assert_eq!(receipt.position, 1);
        assert_eq!(receipt.chain_head.len(), 64);

        let history = stub.history().await;
        assert_eq!(history.len(), 1);
    }

    #[tokio::test]
    async fn wrapping_passes_through_audit_log_trait() {
        let stub = Arc::new(StubRekorSubmitter::new());
        let anchored =
            RekorAnchoredAuditLog::new(MemoryAuditLog::new(), stub, Duration::from_secs(60));
        for i in 0..3 {
            anchored
                .append(Event::new(
                    EventKind::TransferInitiated,
                    "",
                    format!("tx_{}", i),
                    serde_json::json!({"i": i}),
                ))
                .await
                .unwrap();
        }
        assert_eq!(anchored.len().await.unwrap(), 3);
        anchored.verify_chain().await.unwrap();
    }

    #[tokio::test]
    async fn background_loop_emits_after_interval() {
        let stub = Arc::new(StubRekorSubmitter::new());
        let anchored = Arc::new(RekorAnchoredAuditLog::new(
            MemoryAuditLog::new(),
            stub.clone(),
            Duration::from_millis(50),
        ));
        let handle = anchored.spawn_submission_loop();
        tokio::time::sleep(Duration::from_millis(180)).await;
        handle.abort();

        let history = stub.history().await;
        assert!(
            history.len() >= 2,
            "expected >=2 submissions, got {}",
            history.len()
        );
    }
}
