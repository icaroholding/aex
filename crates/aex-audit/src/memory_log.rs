//! In-memory [`AuditLog`] used by tests and the M1 demo.

use std::sync::Arc;

use async_trait::async_trait;
use time::OffsetDateTime;
use tokio::sync::Mutex;

use crate::{
    event::{Event, EventReceipt, StoredEvent},
    AuditError, AuditLog, AuditResult, GENESIS_HEAD,
};

#[derive(Default)]
pub struct MemoryAuditLog {
    inner: Arc<Mutex<Inner>>,
}

#[derive(Default)]
struct Inner {
    events: Vec<StoredEvent>,
}

impl MemoryAuditLog {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn snapshot(&self) -> Vec<StoredEvent> {
        self.inner.lock().await.events.clone()
    }
}

#[async_trait]
impl AuditLog for MemoryAuditLog {
    async fn append(&self, event: Event) -> AuditResult<EventReceipt> {
        let mut guard = self.inner.lock().await;
        let position = guard.events.len() as u64;
        let prev_hash = guard
            .events
            .last()
            .map(|e| e.this_hash.clone())
            .unwrap_or_else(|| GENESIS_HEAD.to_string());

        let timestamp = OffsetDateTime::now_utc();
        let this_hash = event.compute_hash(timestamp, &prev_hash)?;
        let stored = StoredEvent {
            position,
            event_id: format!("evt_{}", uuid::Uuid::new_v4().simple()),
            timestamp,
            prev_hash,
            this_hash,
            event,
        };

        let receipt = EventReceipt::from(&stored);
        guard.events.push(stored);
        Ok(receipt)
    }

    async fn current_head(&self) -> AuditResult<String> {
        let guard = self.inner.lock().await;
        Ok(guard
            .events
            .last()
            .map(|e| e.this_hash.clone())
            .unwrap_or_else(|| GENESIS_HEAD.to_string()))
    }

    async fn verify_chain(&self) -> AuditResult<()> {
        let guard = self.inner.lock().await;
        let mut expected_prev = GENESIS_HEAD.to_string();
        for (i, ev) in guard.events.iter().enumerate() {
            if ev.prev_hash != expected_prev {
                return Err(AuditError::ChainBroken {
                    position: i as u64,
                    expected: expected_prev,
                    found: ev.prev_hash.clone(),
                });
            }
            ev.verify_hash()?;
            expected_prev = ev.this_hash.clone();
        }
        Ok(())
    }

    async fn len(&self) -> AuditResult<u64> {
        Ok(self.inner.lock().await.events.len() as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::EventKind;

    #[tokio::test]
    async fn empty_log_head_is_genesis() {
        let log = MemoryAuditLog::new();
        assert_eq!(log.current_head().await.unwrap(), GENESIS_HEAD);
        assert_eq!(log.len().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn append_advances_head() {
        let log = MemoryAuditLog::new();
        let r = log
            .append(Event::new(
                EventKind::AgentRegistered,
                "spize:acme/alice:a4f8b2",
                "spize:acme/alice:a4f8b2",
                serde_json::json!({"fingerprint": "a4f8b2"}),
            ))
            .await
            .unwrap();
        assert_eq!(r.position, 0);
        assert_ne!(r.chain_head, GENESIS_HEAD);
        assert_eq!(log.current_head().await.unwrap(), r.chain_head);
    }

    #[tokio::test]
    async fn chain_verifies_after_many_appends() {
        let log = MemoryAuditLog::new();
        for i in 0..20 {
            log.append(Event::new(
                EventKind::TransferInitiated,
                "spize:acme/alice:a4f8b2",
                format!("tx_{}", i),
                serde_json::json!({"seq": i}),
            ))
            .await
            .unwrap();
        }
        log.verify_chain().await.unwrap();
        assert_eq!(log.len().await.unwrap(), 20);
    }

    #[tokio::test]
    async fn tampering_breaks_chain() {
        let log = MemoryAuditLog::new();
        for i in 0..3 {
            log.append(Event::new(
                EventKind::TransferInitiated,
                "",
                format!("tx_{}", i),
                serde_json::json!({"seq": i}),
            ))
            .await
            .unwrap();
        }
        // Mutate event in place — simulates a disk tamper.
        {
            let mut g = log.inner.lock().await;
            g.events[1].event.subject = "tx_evil".into();
        }
        let err = log.verify_chain().await.unwrap_err();
        assert!(matches!(err, AuditError::HashMismatch { position: 1, .. }));
    }

    #[tokio::test]
    async fn broken_link_detected() {
        let log = MemoryAuditLog::new();
        for i in 0..3 {
            log.append(Event::new(
                EventKind::TransferInitiated,
                "",
                format!("tx_{}", i),
                serde_json::json!({"seq": i}),
            ))
            .await
            .unwrap();
        }
        {
            let mut g = log.inner.lock().await;
            g.events[2].prev_hash = "f".repeat(64);
        }
        let err = log.verify_chain().await.unwrap_err();
        assert!(matches!(err, AuditError::ChainBroken { position: 2, .. }));
    }
}
