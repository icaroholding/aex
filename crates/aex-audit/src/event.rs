//! Event types, canonical serialization, and hash computation.
//!
//! Canonical bytes (what gets hashed) use deterministic JSON with sorted
//! keys. This is the same discipline as [JCS](https://www.rfc-editor.org/rfc/rfc8785.html)
//! but limited to the small subset of JSON we emit — we don't accept
//! arbitrary user JSON in the payload, callers build it via structured
//! Rust types so ordering is under our control.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

use crate::{AuditError, AuditResult, GENESIS_HEAD};

/// High-level classification of the action recorded.
///
/// These strings are part of the canonical bytes hashed into the audit
/// chain. **Never rename a variant** — old events would stop verifying.
/// To extend, add a new variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    AgentRegistered,
    AgentRevoked,
    TransferInitiated,
    TransferPolicyDecision,
    TransferScannerVerdict,
    TransferAccepted,
    TransferDelivered,
    TransferRejected,
    TransferExpired,
}

impl EventKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            EventKind::AgentRegistered => "agent_registered",
            EventKind::AgentRevoked => "agent_revoked",
            EventKind::TransferInitiated => "transfer_initiated",
            EventKind::TransferPolicyDecision => "transfer_policy_decision",
            EventKind::TransferScannerVerdict => "transfer_scanner_verdict",
            EventKind::TransferAccepted => "transfer_accepted",
            EventKind::TransferDelivered => "transfer_delivered",
            EventKind::TransferRejected => "transfer_rejected",
            EventKind::TransferExpired => "transfer_expired",
        }
    }
}

/// The input half of an audit entry — everything the caller supplies.
///
/// Once persisted, the audit log attaches `position`, `prev_hash`, and
/// `this_hash`, producing a [`StoredEvent`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub kind: EventKind,
    /// Agent that triggered this event (sender, org admin, scanner).
    /// Empty string is permitted for system-level events.
    pub actor: String,
    /// Logical subject of the event: transfer_id, agent_id, etc. Empty
    /// means the actor itself is the subject.
    pub subject: String,
    /// Structured payload. Must be a JSON object; arrays/primitives at
    /// the top level are rejected to avoid ambiguous canonical output.
    pub payload: serde_json::Value,
}

impl Event {
    pub fn new(
        kind: EventKind,
        actor: impl Into<String>,
        subject: impl Into<String>,
        payload: serde_json::Value,
    ) -> Self {
        Self {
            kind,
            actor: actor.into(),
            subject: subject.into(),
            payload,
        }
    }

    /// Produce the canonical byte string that will be hashed into the
    /// chain. Format:
    ///
    /// ```text
    /// {"kind":"...","actor":"...","subject":"...","payload":<canonical>,"ts":"RFC3339","prev":"..."}
    /// ```
    ///
    /// Key order is fixed; payload is canonicalized recursively (sorted
    /// object keys, no whitespace). This bytestring uniquely determines
    /// `this_hash` given a stable input.
    pub fn canonical_bytes(
        &self,
        ts: OffsetDateTime,
        prev_hash: &str,
    ) -> AuditResult<Vec<u8>> {
        if !matches!(self.payload, serde_json::Value::Object(_)) {
            return Err(AuditError::InvalidEvent(
                "payload must be a JSON object".into(),
            ));
        }
        let payload_canonical = canonical_json(&self.payload);
        let ts_str = ts
            .format(&time::format_description::well_known::Rfc3339)
            .map_err(|e| AuditError::InvalidEvent(format!("ts format: {}", e)))?;

        let mut out = Vec::with_capacity(128);
        out.extend_from_slice(b"{\"kind\":\"");
        out.extend_from_slice(self.kind.as_str().as_bytes());
        out.extend_from_slice(b"\",\"actor\":");
        out.extend_from_slice(json_string(&self.actor).as_bytes());
        out.extend_from_slice(b",\"subject\":");
        out.extend_from_slice(json_string(&self.subject).as_bytes());
        out.extend_from_slice(b",\"payload\":");
        out.extend_from_slice(payload_canonical.as_bytes());
        out.extend_from_slice(b",\"ts\":");
        out.extend_from_slice(json_string(&ts_str).as_bytes());
        out.extend_from_slice(b",\"prev\":");
        out.extend_from_slice(json_string(prev_hash).as_bytes());
        out.extend_from_slice(b"}");
        Ok(out)
    }

    /// Compute the hash an event would carry given timestamp + previous
    /// chain head.
    pub fn compute_hash(&self, ts: OffsetDateTime, prev_hash: &str) -> AuditResult<String> {
        let bytes = self.canonical_bytes(ts, prev_hash)?;
        let digest = Sha256::digest(&bytes);
        Ok(hex::encode(digest))
    }
}

/// What's actually stored in the log — the input event plus the chain
/// metadata the log attaches.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredEvent {
    pub position: u64,
    pub event_id: String,
    #[serde(with = "time::serde::rfc3339")]
    pub timestamp: OffsetDateTime,
    pub prev_hash: String,
    pub this_hash: String,
    #[serde(flatten)]
    pub event: Event,
}

impl StoredEvent {
    /// Re-derive `this_hash` from stored inputs and compare to the stored
    /// value. Used by [`AuditLog::verify_chain`].
    pub fn verify_hash(&self) -> AuditResult<()> {
        let recomputed = self.event.compute_hash(self.timestamp, &self.prev_hash)?;
        if recomputed != self.this_hash {
            return Err(AuditError::HashMismatch {
                position: self.position,
                stored: self.this_hash.clone(),
                recomputed,
            });
        }
        Ok(())
    }
}

/// Receipt returned to callers on successful append. Useful to carry as
/// proof that a particular action was logged — e.g., bundled with a
/// delivery confirmation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventReceipt {
    pub event_id: String,
    pub position: u64,
    #[serde(with = "time::serde::rfc3339")]
    pub timestamp: OffsetDateTime,
    pub chain_head: String,
}

impl From<&StoredEvent> for EventReceipt {
    fn from(e: &StoredEvent) -> Self {
        EventReceipt {
            event_id: e.event_id.clone(),
            position: e.position,
            timestamp: e.timestamp,
            chain_head: e.this_hash.clone(),
        }
    }
}

// ---------- canonical JSON helpers ----------

/// Serialize any JSON value with sorted keys and no whitespace.
fn canonical_json(v: &serde_json::Value) -> String {
    let mut out = String::new();
    write_canonical(v, &mut out);
    out
}

fn write_canonical(v: &serde_json::Value, out: &mut String) {
    match v {
        serde_json::Value::Null => out.push_str("null"),
        serde_json::Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        serde_json::Value::Number(n) => out.push_str(&n.to_string()),
        serde_json::Value::String(s) => out.push_str(&json_string(s)),
        serde_json::Value::Array(xs) => {
            out.push('[');
            for (i, x) in xs.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(x, out);
            }
            out.push(']');
        }
        serde_json::Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&json_string(k));
                out.push(':');
                write_canonical(&map[*k], out);
            }
            out.push('}');
        }
    }
}

/// Produce a JSON-encoded string literal (surrounding quotes included).
fn json_string(s: &str) -> String {
    serde_json::Value::String(s.to_string()).to_string()
}

// ---------- utilities ----------

pub fn genesis_head() -> String {
    GENESIS_HEAD.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_event() -> Event {
        Event::new(
            EventKind::AgentRegistered,
            "spize:acme/alice:a4f8b2",
            "spize:acme/alice:a4f8b2",
            serde_json::json!({"fingerprint": "a4f8b2"}),
        )
    }

    #[test]
    fn canonical_bytes_stable_across_calls() {
        let e = sample_event();
        let ts = time::OffsetDateTime::UNIX_EPOCH;
        let a = e.canonical_bytes(ts, GENESIS_HEAD).unwrap();
        let b = e.canonical_bytes(ts, GENESIS_HEAD).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn canonical_bytes_include_all_fields() {
        let e = sample_event();
        let ts = time::OffsetDateTime::UNIX_EPOCH;
        let bytes = e.canonical_bytes(ts, GENESIS_HEAD).unwrap();
        let s = std::str::from_utf8(&bytes).unwrap();
        assert!(s.contains("\"kind\":\"agent_registered\""));
        assert!(s.contains("\"actor\":\"spize:acme/alice:a4f8b2\""));
        assert!(s.contains("\"fingerprint\":\"a4f8b2\""));
        assert!(s.contains("\"prev\":\"0000"));
    }

    #[test]
    fn payload_keys_sorted_in_canonical() {
        let e = Event::new(
            EventKind::TransferInitiated,
            "",
            "tx_1",
            serde_json::json!({"z": 1, "a": 2, "m": 3}),
        );
        let ts = time::OffsetDateTime::UNIX_EPOCH;
        let bytes = e.canonical_bytes(ts, GENESIS_HEAD).unwrap();
        let s = std::str::from_utf8(&bytes).unwrap();
        let a_pos = s.find("\"a\"").unwrap();
        let m_pos = s.find("\"m\"").unwrap();
        let z_pos = s.find("\"z\"").unwrap();
        assert!(a_pos < m_pos && m_pos < z_pos);
    }

    #[test]
    fn different_prev_hash_different_hash() {
        let e = sample_event();
        let ts = time::OffsetDateTime::UNIX_EPOCH;
        let h1 = e.compute_hash(ts, GENESIS_HEAD).unwrap();
        let h2 = e.compute_hash(ts, &"a".repeat(64)).unwrap();
        assert_ne!(h1, h2);
    }

    #[test]
    fn different_kind_different_hash() {
        let ts = time::OffsetDateTime::UNIX_EPOCH;
        let a = Event::new(EventKind::AgentRegistered, "", "", serde_json::json!({}))
            .compute_hash(ts, GENESIS_HEAD)
            .unwrap();
        let b = Event::new(EventKind::AgentRevoked, "", "", serde_json::json!({}))
            .compute_hash(ts, GENESIS_HEAD)
            .unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn non_object_payload_rejected() {
        let e = Event {
            kind: EventKind::AgentRegistered,
            actor: "".into(),
            subject: "".into(),
            payload: serde_json::json!([1, 2, 3]),
        };
        let err = e
            .canonical_bytes(time::OffsetDateTime::UNIX_EPOCH, GENESIS_HEAD)
            .unwrap_err();
        assert!(matches!(err, AuditError::InvalidEvent(_)));
    }
}
