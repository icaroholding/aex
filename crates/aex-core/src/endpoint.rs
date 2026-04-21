//! `Endpoint` — a single way a recipient can reach a sender's data plane.
//!
//! Introduced in Sprint 2 for transport plurality (`v1.3.0-beta.1`).
//! A transfer carries a list of endpoints (`reachable_at[]`); the recipient
//! SDK tries them in the sender's declared priority order per ADR-0012
//! (sender-ranked, serial, sticky) and stops at the first that works.
//!
//! ```text
//!     reachable_at[] (JSONB on transfers, JSON on the wire)
//!         │
//!         ├── { kind: "cloudflare_quick", url: "https://x.trycloudflare.com", priority: 0 }
//!         ├── { kind: "iroh",              url: "iroh:NodeID@relay:443",        priority: 1 }
//!         └── { kind: "frp",               url: "https://frp.example.com/x",    priority: 2 }
//!              │
//!              └── recipient tries in priority order, sticks with first success
//! ```
//!
//! ## Forward compatibility
//!
//! `kind` is a `String`, not an enum, so unknown kinds from a newer peer
//! are preserved losslessly. Recipients MUST skip endpoints whose `kind`
//! is not in [`Endpoint::KNOWN_KINDS`] rather than erroring. This mirrors
//! the capability-bit philosophy in ADR-0018 — new transports land
//! additively without requiring a wire bump.

use serde::{Deserialize, Serialize};

/// A single way to reach a sender's data plane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Endpoint {
    /// Transport kind. See [`Endpoint::KIND_*`] constants for known values.
    /// Unknown values are preserved but MUST be skipped by recipients.
    pub kind: String,
    /// Reachable address. Schema is transport-specific:
    /// - `cloudflare_quick`, `cloudflare_named`, `tailscale_funnel`, `frp`: `https://host/...`
    /// - `iroh`: `iroh:<NodeID>@<relay_host>:<port>`
    pub url: String,
    /// Sender's preference (lower = try first). Ties broken by array order.
    #[serde(default)]
    pub priority: i32,
    /// Optional last-known-good timestamp (Unix seconds) used by the control
    /// plane's health cache. Absent on fresh endpoints.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health_hint_unix: Option<i64>,
}

impl Endpoint {
    /// Cloudflare Quick Tunnel (`*.trycloudflare.com`, ephemeral).
    pub const KIND_CLOUDFLARE_QUICK: &'static str = "cloudflare_quick";
    /// Cloudflare Named Tunnel (`*.workers.dev` or custom hostname, persistent).
    pub const KIND_CLOUDFLARE_NAMED: &'static str = "cloudflare_named";
    /// Iroh peer-to-peer with DERP relay fallback.
    pub const KIND_IROH: &'static str = "iroh";
    /// Tailscale Funnel (public hostname on a tailnet).
    pub const KIND_TAILSCALE_FUNNEL: &'static str = "tailscale_funnel";
    /// FRP self-hosted reverse proxy.
    pub const KIND_FRP: &'static str = "frp";

    /// All kinds this crate knows how to reach. Adding a new transport in a
    /// later sprint adds a constant here + extends this array.
    pub const KNOWN_KINDS: &'static [&'static str] = &[
        Self::KIND_CLOUDFLARE_QUICK,
        Self::KIND_CLOUDFLARE_NAMED,
        Self::KIND_IROH,
        Self::KIND_TAILSCALE_FUNNEL,
        Self::KIND_FRP,
    ];

    /// True if `self.kind` is in [`Self::KNOWN_KINDS`]. Recipients use this
    /// to skip forward-incompatible endpoints without failing the transfer.
    pub fn is_known_kind(&self) -> bool {
        Self::KNOWN_KINDS.contains(&self.kind.as_str())
    }

    /// Convenience: Cloudflare Quick Tunnel endpoint at priority 0.
    pub fn cloudflare_quick(url: impl Into<String>) -> Self {
        Self {
            kind: Self::KIND_CLOUDFLARE_QUICK.into(),
            url: url.into(),
            priority: 0,
            health_hint_unix: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cloudflare_quick_builder() {
        let e = Endpoint::cloudflare_quick("https://foo.trycloudflare.com");
        assert_eq!(e.kind, "cloudflare_quick");
        assert_eq!(e.url, "https://foo.trycloudflare.com");
        assert_eq!(e.priority, 0);
        assert!(e.is_known_kind());
    }

    #[test]
    fn unknown_kind_preserved_and_flagged() {
        let e = Endpoint {
            kind: "future_transport_v9".into(),
            url: "future:alien@mars:443".into(),
            priority: 5,
            health_hint_unix: None,
        };
        assert!(!e.is_known_kind());
    }

    #[test]
    fn serde_roundtrip_minimal() {
        let original = Endpoint::cloudflare_quick("https://x.trycloudflare.com");
        let json = serde_json::to_string(&original).unwrap();
        // Priority 0 is the default but explicit in serialization; health_hint absent.
        assert!(json.contains(r#""kind":"cloudflare_quick""#));
        assert!(json.contains(r#""url":"https://x.trycloudflare.com""#));
        assert!(!json.contains("health_hint_unix"));
        let back: Endpoint = serde_json::from_str(&json).unwrap();
        assert_eq!(back, original);
    }

    #[test]
    fn serde_roundtrip_with_health_hint() {
        let original = Endpoint {
            kind: Endpoint::KIND_IROH.into(),
            url: "iroh:abc123@relay.aex.dev:443".into(),
            priority: 1,
            health_hint_unix: Some(1_700_000_000),
        };
        let json = serde_json::to_string(&original).unwrap();
        assert!(json.contains(r#""health_hint_unix":1700000000"#));
        let back: Endpoint = serde_json::from_str(&json).unwrap();
        assert_eq!(back, original);
    }

    #[test]
    fn deserialize_preserves_unknown_kind() {
        let json = r#"{"kind":"unknown_transport","url":"x://y","priority":9}"#;
        let e: Endpoint = serde_json::from_str(json).unwrap();
        assert_eq!(e.kind, "unknown_transport");
        assert!(!e.is_known_kind());
    }

    #[test]
    fn priority_defaults_to_zero_when_missing() {
        let json = r#"{"kind":"cloudflare_quick","url":"https://x.trycloudflare.com"}"#;
        let e: Endpoint = serde_json::from_str(json).unwrap();
        assert_eq!(e.priority, 0);
        assert_eq!(e.health_hint_unix, None);
    }

    #[test]
    fn known_kinds_covers_sprint_2_transports() {
        for k in [
            Endpoint::KIND_CLOUDFLARE_QUICK,
            Endpoint::KIND_CLOUDFLARE_NAMED,
            Endpoint::KIND_IROH,
            Endpoint::KIND_TAILSCALE_FUNNEL,
            Endpoint::KIND_FRP,
        ] {
            assert!(Endpoint::KNOWN_KINDS.contains(&k), "kind {k} missing");
        }
    }
}
