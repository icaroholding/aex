//! Capability bits advertised by agents in their JWS-signed agent card.
//!
//! Per ADR-0018, new protocol features ship as capability bits — not as
//! breaking wire-format bumps. An agent declares what it supports; senders
//! pick the highest mutually-supported feature at negotiation time.
//!
//! The bit-vector representation lets agent cards stay small while keeping
//! room for ~64 future capabilities. A new capability is added by
//! introducing a variant here; the variant's `as_bit()` discriminant must
//! never be reused or renumbered — capability bits are part of the signed
//! card payload and any reuse breaks historical signatures.
//!
//! # Serialization
//!
//! On the wire (inside JWS-signed agent cards), a [`CapabilitySet`] is
//! serialized as a JSON array of capability **string names** (not bit
//! positions) — see `to_string_array` / `from_string_array`. This keeps
//! cards human-readable and lets future readers ignore unknown
//! capabilities forward-compatibly.

use serde::{Deserialize, Serialize};

/// A protocol capability advertised by an agent.
///
/// Adding a variant:
/// 1. Append at the end — never insert in the middle.
/// 2. Pick the next free `as_bit()` discriminant.
/// 3. Pick a stable lowercase-kebab-case `as_str()` name.
/// 4. Add to [`Capability::ALL`].
/// 5. Document the semantics in `docs/protocol-v2.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Capability {
    /// Sender and recipient speak wire v2 (`aex-*:v2` prefix). Required
    /// for any v2 transfer; absence implies v1-only.
    WireV2,
    /// Agent publishes a JWS-signed `/.well-known/agent-card.json`
    /// per ADR-0025. Required for did:web binding.
    JwsAgentCard,
    /// Agent supports the cache freshness protocol (`If-None-Match`
    /// conditional GET on agent card; ADR-0046).
    CardEtag,
    /// Agent supports A2A delegation chain receive (bridge adapter from
    /// Google A2A v1.0 task protocol). Optional, v2.1+ in most deployments.
    A2ABridge,
    /// Agent's identity is verified by EtereCitizen reputation index
    /// on Base L2 (ADR-0040). Present only on did:ethr agent cards
    /// whose key is registered on-chain.
    EtereCitizenTrust,
    /// Agent supports SSRF-resistant outbound HTTP via `aex-net::safe_http`
    /// (ADR-0045) — relevant when this agent itself acts as a resolver
    /// for downstream did:web fetches.
    SafeHttp,
    /// Agent rejects clock skew > 60s on inbound messages (ADR-0044).
    /// Absence means v1-style 300s window is still accepted.
    ClockSkew60s,
    /// Agent supports the streaming transfer mode (chunked uploads
    /// with intermediate ack). Reserved for v2.2.
    StreamingTransfer,
}

impl Capability {
    /// All capabilities known to this build, in stable order.
    pub const ALL: &'static [Capability] = &[
        Capability::WireV2,
        Capability::JwsAgentCard,
        Capability::CardEtag,
        Capability::A2ABridge,
        Capability::EtereCitizenTrust,
        Capability::SafeHttp,
        Capability::ClockSkew60s,
        Capability::StreamingTransfer,
    ];

    /// Stable bit position in [`CapabilitySet`]. **Never renumber.**
    pub const fn as_bit(self) -> u8 {
        match self {
            Capability::WireV2 => 0,
            Capability::JwsAgentCard => 1,
            Capability::CardEtag => 2,
            Capability::A2ABridge => 3,
            Capability::EtereCitizenTrust => 4,
            Capability::SafeHttp => 5,
            Capability::ClockSkew60s => 6,
            Capability::StreamingTransfer => 7,
        }
    }

    /// Stable wire-string name. **Never rename.**
    pub const fn as_str(self) -> &'static str {
        match self {
            Capability::WireV2 => "wire-v2",
            Capability::JwsAgentCard => "jws-agent-card",
            Capability::CardEtag => "card-etag",
            Capability::A2ABridge => "a2a-bridge",
            Capability::EtereCitizenTrust => "etere-citizen-trust",
            Capability::SafeHttp => "safe-http",
            Capability::ClockSkew60s => "clock-skew-60s",
            Capability::StreamingTransfer => "streaming-transfer",
        }
    }

    /// Parse from the stable wire-string name. Returns `None` for unknown
    /// names — callers that read agent cards must tolerate forward-incompat
    /// capability names per ADR-0018, so unknown names are silently
    /// dropped rather than errored.
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|c| c.as_str() == s)
    }
}

/// Bitset of advertised capabilities.
///
/// Backed by a `u64` so we have room for 64 future capabilities without
/// changing the wire size of the agent card.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CapabilitySet(u64);

impl CapabilitySet {
    /// Empty set — agent advertises no v2 capabilities.
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Add a capability. Returns `self` for chaining.
    pub fn with(mut self, cap: Capability) -> Self {
        self.0 |= 1u64 << cap.as_bit();
        self
    }

    /// Check membership.
    pub fn has(self, cap: Capability) -> bool {
        (self.0 & (1u64 << cap.as_bit())) != 0
    }

    /// Iterator over the capabilities present in this set, in
    /// `Capability::ALL` order.
    pub fn iter(self) -> impl Iterator<Item = Capability> {
        Capability::ALL
            .iter()
            .copied()
            .filter(move |c| self.has(*c))
    }

    /// Render as the canonical JSON array of capability string names
    /// embedded in JWS-signed agent cards.
    pub fn to_string_array(self) -> Vec<&'static str> {
        self.iter().map(Capability::as_str).collect()
    }

    /// Build from the wire JSON array. Unknown names are silently
    /// skipped (forward-compat) per ADR-0018 — readers must tolerate
    /// capability names they don't recognize without erroring.
    pub fn from_string_array<I, S>(items: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut set = Self::empty();
        for item in items {
            if let Some(cap) = Capability::parse(item.as_ref()) {
                set = set.with(cap);
            }
        }
        set
    }

    /// Raw bitset (for testing / debug only).
    pub const fn bits(self) -> u64 {
        self.0
    }
}

impl Serialize for CapabilitySet {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        // Serialize as an array of stable string names — survives
        // re-numbering of variants because we never re-number, but
        // also survives readers from older builds that don't know
        // newer string names.
        self.to_string_array().serialize(s)
    }
}

impl<'de> Deserialize<'de> for CapabilitySet {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let v: Vec<String> = Vec::deserialize(d)?;
        Ok(Self::from_string_array(v))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_set_has_no_caps() {
        let set = CapabilitySet::empty();
        for cap in Capability::ALL {
            assert!(!set.has(*cap), "empty set should not have {:?}", cap);
        }
    }

    #[test]
    fn add_and_query() {
        let set = CapabilitySet::empty()
            .with(Capability::WireV2)
            .with(Capability::JwsAgentCard);
        assert!(set.has(Capability::WireV2));
        assert!(set.has(Capability::JwsAgentCard));
        assert!(!set.has(Capability::A2ABridge));
    }

    #[test]
    fn bits_are_stable() {
        // CRITICAL: changing these breaks deployed agent cards. If a
        // test here fails after a code change, you've renumbered a
        // capability — revert and ADD at the end instead.
        assert_eq!(Capability::WireV2.as_bit(), 0);
        assert_eq!(Capability::JwsAgentCard.as_bit(), 1);
        assert_eq!(Capability::CardEtag.as_bit(), 2);
        assert_eq!(Capability::A2ABridge.as_bit(), 3);
        assert_eq!(Capability::EtereCitizenTrust.as_bit(), 4);
        assert_eq!(Capability::SafeHttp.as_bit(), 5);
        assert_eq!(Capability::ClockSkew60s.as_bit(), 6);
        assert_eq!(Capability::StreamingTransfer.as_bit(), 7);
    }

    #[test]
    fn names_are_stable() {
        assert_eq!(Capability::WireV2.as_str(), "wire-v2");
        assert_eq!(Capability::JwsAgentCard.as_str(), "jws-agent-card");
        assert_eq!(Capability::CardEtag.as_str(), "card-etag");
        assert_eq!(Capability::A2ABridge.as_str(), "a2a-bridge");
        assert_eq!(Capability::EtereCitizenTrust.as_str(), "etere-citizen-trust");
        assert_eq!(Capability::SafeHttp.as_str(), "safe-http");
        assert_eq!(Capability::ClockSkew60s.as_str(), "clock-skew-60s");
        assert_eq!(Capability::StreamingTransfer.as_str(), "streaming-transfer");
    }

    #[test]
    fn parse_roundtrip() {
        for cap in Capability::ALL {
            let parsed = Capability::parse(cap.as_str()).unwrap();
            assert_eq!(parsed, *cap);
        }
        assert!(Capability::parse("does-not-exist").is_none());
    }

    #[test]
    fn iter_in_canonical_order() {
        let set = CapabilitySet::empty()
            .with(Capability::StreamingTransfer)
            .with(Capability::WireV2)
            .with(Capability::JwsAgentCard);
        let order: Vec<_> = set.iter().collect();
        assert_eq!(
            order,
            vec![
                Capability::WireV2,
                Capability::JwsAgentCard,
                Capability::StreamingTransfer
            ]
        );
    }

    #[test]
    fn serde_roundtrip_via_string_array() {
        let set = CapabilitySet::empty()
            .with(Capability::WireV2)
            .with(Capability::JwsAgentCard)
            .with(Capability::CardEtag);
        let json = serde_json::to_string(&set).unwrap();
        assert_eq!(json, r#"["wire-v2","jws-agent-card","card-etag"]"#);
        let back: CapabilitySet = serde_json::from_str(&json).unwrap();
        assert_eq!(set, back);
    }

    #[test]
    fn deserialize_skips_unknown_names() {
        // Forward-compat: a v2.3 agent advertising "post-quantum-sig"
        // must NOT cause a v2.0 reader to error.
        let json = r#"["wire-v2","post-quantum-sig","jws-agent-card"]"#;
        let set: CapabilitySet = serde_json::from_str(json).unwrap();
        assert!(set.has(Capability::WireV2));
        assert!(set.has(Capability::JwsAgentCard));
        // Set must not have any phantom capability for "post-quantum-sig".
        assert_eq!(set.to_string_array().len(), 2);
    }

    #[test]
    fn duplicate_names_idempotent() {
        let set = CapabilitySet::from_string_array(["wire-v2", "wire-v2", "wire-v2"]);
        assert!(set.has(Capability::WireV2));
        assert_eq!(set.to_string_array().len(), 1);
    }

    #[test]
    fn empty_array_is_empty_set() {
        let set: CapabilitySet = serde_json::from_str("[]").unwrap();
        assert_eq!(set, CapabilitySet::empty());
        assert_eq!(set.bits(), 0);
    }

    #[test]
    fn all_caps_set() {
        let mut set = CapabilitySet::empty();
        for cap in Capability::ALL {
            set = set.with(*cap);
        }
        for cap in Capability::ALL {
            assert!(set.has(*cap));
        }
    }
}
