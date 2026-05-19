use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::Error;

const MAX_AGENT_ID_LEN: usize = 256;

/// Canonical agent identifier.
///
/// Two format families are supported:
///
/// - **SpizeNative legacy** (wire v1): `spize:{org}/{name}:{fingerprint}`
///   e.g. `spize:acme/accountant-v3:a4f8b2`
/// - **W3C DID URI** (wire v2): `did:{method}:{method-specific-id}[#{fragment}]`
///   e.g. `did:ethr:0x14a34:0xabc...`, `did:web:example.com#agent-vendite`,
///   `did:spize:acme/alice#a4f8b2`, `did:key:z6Mki...`.
///
/// The identifier is opaque at this layer; the [`crate::IdentityProvider`]
/// implementation for a given scheme knows how to verify signatures and
/// resolve metadata. DID URIs follow the W3C DID Core spec §3.1.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AgentId(String);

impl AgentId {
    /// Construct, validating the format.
    pub fn new(s: impl Into<String>) -> Result<Self, Error> {
        let s = s.into();
        validate_agent_id(&s)?;
        Ok(Self(s))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Return the identity scheme this agent_id belongs to.
    pub fn scheme(&self) -> IdScheme {
        if self.0.starts_with("spize:") {
            IdScheme::SpizeNative
        } else if self.0.starts_with("did:spize:") {
            IdScheme::DidSpize
        } else if self.0.starts_with("did:ethr:") {
            IdScheme::DidEthr
        } else if self.0.starts_with("did:web:") {
            IdScheme::DidWeb
        } else if self.0.starts_with("did:key:") {
            IdScheme::DidKey
        } else {
            IdScheme::Unknown
        }
    }

    /// If this AgentId is a W3C DID URI, return its parsed components.
    /// Returns `None` for legacy `spize:` ids or malformed inputs.
    ///
    /// A DID URI has the form `did:{method}:{method-specific-id}[#{fragment}]`.
    /// Per W3C DID Core §3.1, the `did:` prefix and method are required;
    /// the fragment is optional.
    pub fn as_did_uri(&self) -> Option<DidUri<'_>> {
        DidUri::parse(&self.0)
    }
}

/// Known identity schemes.
///
/// `SpizeNative` is wire-v1-only (legacy). All other variants are W3C DID
/// methods supported by wire v2. `DidSpize` is the v2 namespace for what
/// was historically `spize:` — same trust root, W3C-compliant URI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IdScheme {
    /// Legacy wire-v1 prefix `spize:org/name:fingerprint`. Held for
    /// backward compatibility during the v1→v2 grace window.
    SpizeNative,
    /// W3C DID method `did:spize:` — Spize hosted registry, v2.
    DidSpize,
    /// W3C DID method `did:ethr:` — EtereCitizen / Ethereum-style identity.
    DidEthr,
    /// W3C DID method `did:web:` — domain-anchored identity via
    /// `/.well-known/did.json`.
    DidWeb,
    /// W3C DID method `did:key:` — offline / device-local self-certifying.
    DidKey,
    /// Unrecognized scheme. Valid syntactically but no resolver knows it.
    Unknown,
}

/// Parsed components of a W3C DID URI (`did:method:method-specific-id#fragment`).
///
/// Borrows from the source string; no allocations. Per W3C DID Core §3.1,
/// the prefix `did:` is required and the fragment (after `#`) is optional.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DidUri<'a> {
    /// The DID method, e.g. `"web"`, `"ethr"`, `"spize"`, `"key"`.
    pub method: &'a str,
    /// The method-specific identifier (between the second `:` and the
    /// optional `#`), e.g. `"acme.com"` for `did:web:acme.com#agent`.
    pub method_specific_id: &'a str,
    /// The fragment after `#` if present, e.g. `"agent-vendite"`.
    pub fragment: Option<&'a str>,
}

impl<'a> DidUri<'a> {
    fn parse(s: &'a str) -> Option<Self> {
        let rest = s.strip_prefix("did:")?;
        // Split on first `:` to get method.
        let (method, after_method) = rest.split_once(':')?;
        if method.is_empty() {
            return None;
        }
        // Method must match ABNF method-name = 1*method-char (W3C DID Core §3.1):
        // method-char = %x61-7A / DIGIT  (lowercase ASCII letters + digits).
        if !method
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        {
            return None;
        }
        // Split optional fragment.
        let (msi, fragment) = match after_method.split_once('#') {
            Some((id, frag)) => (id, Some(frag)),
            None => (after_method, None),
        };
        if msi.is_empty() {
            return None;
        }
        // Fragment, if present, must be non-empty (W3C DID Core uses RFC 3986
        // fragment grammar; an empty fragment is allowed by RFC 3986 but
        // semantically meaningless here, so we reject it for safety).
        if let Some(f) = fragment {
            if f.is_empty() {
                return None;
            }
        }
        Some(Self {
            method,
            method_specific_id: msi,
            fragment,
        })
    }
}

impl fmt::Display for AgentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for AgentId {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

fn validate_agent_id(s: &str) -> Result<(), Error> {
    if s.is_empty() {
        return Err(Error::InvalidAgentId("empty".into()));
    }
    if s.len() > MAX_AGENT_ID_LEN {
        return Err(Error::InvalidAgentId(format!(
            "length {} > {}",
            s.len(),
            MAX_AGENT_ID_LEN
        )));
    }
    for (i, c) in s.chars().enumerate() {
        if !c.is_ascii() || c.is_ascii_control() || c.is_whitespace() {
            return Err(Error::InvalidAgentId(format!(
                "invalid char at {}: {:?}",
                i, c
            )));
        }
    }
    if !s.contains(':') {
        return Err(Error::InvalidAgentId("missing scheme separator ':'".into()));
    }
    Ok(())
}

/// Globally unique identifier for a single transfer.
///
/// Format: `tx_{uuid-v4 simple form}`. We use UUID v4 initially; moving to
/// ULID (sortable by creation time) is a future optimization once we start
/// indexing by range in the audit ledger.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TransferId(String);

impl TransferId {
    pub fn new() -> Self {
        Self(format!("tx_{}", uuid::Uuid::new_v4().simple()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for TransferId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for TransferId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_spize_native_id() {
        let id = AgentId::new("spize:acme/alice:a4f8b2").unwrap();
        assert_eq!(id.scheme(), IdScheme::SpizeNative);
    }

    #[test]
    fn valid_did_ethr_id() {
        let id = AgentId::new("did:ethr:0x14a34:0xabc123").unwrap();
        assert_eq!(id.scheme(), IdScheme::DidEthr);
    }

    #[test]
    fn valid_did_web_id() {
        let id = AgentId::new("did:web:example.com:agents:bob").unwrap();
        assert_eq!(id.scheme(), IdScheme::DidWeb);
    }

    #[test]
    fn valid_did_key_id() {
        let id = AgentId::new("did:key:z6Mki...").unwrap();
        assert_eq!(id.scheme(), IdScheme::DidKey);
    }

    #[test]
    fn unknown_scheme_still_valid_but_flagged() {
        let id = AgentId::new("foo:bar").unwrap();
        assert_eq!(id.scheme(), IdScheme::Unknown);
    }

    #[test]
    fn empty_rejected() {
        assert!(matches!(AgentId::new(""), Err(Error::InvalidAgentId(_))));
    }

    #[test]
    fn too_long_rejected() {
        let long = "spize:acme/alice:".to_string() + &"a".repeat(300);
        assert!(matches!(AgentId::new(long), Err(Error::InvalidAgentId(_))));
    }

    #[test]
    fn whitespace_rejected() {
        assert!(matches!(
            AgentId::new("spize:acme/alice name:a4f8b2"),
            Err(Error::InvalidAgentId(_))
        ));
    }

    #[test]
    fn control_char_rejected() {
        assert!(matches!(
            AgentId::new("spize:acme/alice\n:a4f8b2"),
            Err(Error::InvalidAgentId(_))
        ));
    }

    #[test]
    fn non_ascii_rejected() {
        assert!(matches!(
            AgentId::new("spize:acme/aliçe:a4f8b2"),
            Err(Error::InvalidAgentId(_))
        ));
    }

    #[test]
    fn missing_colon_rejected() {
        assert!(matches!(
            AgentId::new("spizeacmealice"),
            Err(Error::InvalidAgentId(_))
        ));
    }

    #[test]
    fn roundtrip_fromstr_display() {
        let s = "spize:acme/alice:a4f8b2";
        let id: AgentId = s.parse().unwrap();
        assert_eq!(format!("{}", id), s);
    }

    #[test]
    fn transfer_ids_are_unique() {
        let a = TransferId::new();
        let b = TransferId::new();
        assert_ne!(a, b);
        assert!(a.as_str().starts_with("tx_"));
    }

    #[test]
    fn agent_id_serde_roundtrip() {
        let id = AgentId::new("spize:acme/alice:a4f8b2").unwrap();
        let json = serde_json::to_string(&id).unwrap();
        let back: AgentId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, back);
    }

    // ── DID URI W3C (v2) ──────────────────────────────────────────────

    #[test]
    fn did_spize_scheme_recognized() {
        let id = AgentId::new("did:spize:acme/alice#a4f8b2").unwrap();
        assert_eq!(id.scheme(), IdScheme::DidSpize);
    }

    #[test]
    fn did_web_with_fragment_parsed() {
        let id = AgentId::new("did:web:acme.com#agent-vendite").unwrap();
        let uri = id.as_did_uri().unwrap();
        assert_eq!(uri.method, "web");
        assert_eq!(uri.method_specific_id, "acme.com");
        assert_eq!(uri.fragment, Some("agent-vendite"));
    }

    #[test]
    fn did_ethr_no_fragment_parsed() {
        let id = AgentId::new("did:ethr:0x14a34:0xabc123").unwrap();
        let uri = id.as_did_uri().unwrap();
        assert_eq!(uri.method, "ethr");
        assert_eq!(uri.method_specific_id, "0x14a34:0xabc123");
        assert_eq!(uri.fragment, None);
    }

    #[test]
    fn did_key_parsed() {
        let id = AgentId::new("did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV").unwrap();
        let uri = id.as_did_uri().unwrap();
        assert_eq!(uri.method, "key");
        assert!(uri.method_specific_id.starts_with("z6Mk"));
        assert_eq!(uri.fragment, None);
    }

    #[test]
    fn did_spize_components_parsed() {
        let id = AgentId::new("did:spize:acme/alice#a4f8b2").unwrap();
        let uri = id.as_did_uri().unwrap();
        assert_eq!(uri.method, "spize");
        assert_eq!(uri.method_specific_id, "acme/alice");
        assert_eq!(uri.fragment, Some("a4f8b2"));
    }

    #[test]
    fn legacy_spize_not_a_did_uri() {
        let id = AgentId::new("spize:acme/alice:a4f8b2").unwrap();
        assert!(id.as_did_uri().is_none());
        assert_eq!(id.scheme(), IdScheme::SpizeNative);
    }

    #[test]
    fn did_with_uppercase_method_rejected() {
        // W3C DID Core §3.1: method must be lowercase.
        let id = AgentId::new("did:WEB:acme.com").unwrap();
        // String passes generic agent_id validation, but as_did_uri()
        // should reject because method is uppercase.
        assert!(id.as_did_uri().is_none());
    }

    #[test]
    fn did_with_empty_fragment_rejected_by_parser() {
        let id = AgentId::new("did:web:acme.com#").unwrap();
        // Passes generic agent_id validation. as_did_uri() rejects empty
        // fragment for safety.
        assert!(id.as_did_uri().is_none());
    }

    #[test]
    fn did_with_empty_method_specific_id_rejected_by_parser() {
        // `did:web:` (no MSI) — string-level valid (contains `:`), but
        // DID URI parser rejects.
        let id = AgentId::new("did:web:").unwrap();
        assert!(id.as_did_uri().is_none());
    }

    #[test]
    fn did_method_with_digits_accepted() {
        // W3C method-char allows lowercase + digits.
        let id = AgentId::new("did:web3:acme.com").unwrap();
        let uri = id.as_did_uri().unwrap();
        assert_eq!(uri.method, "web3");
    }

    #[test]
    fn scheme_dispatch_unaffected_for_unknown_did_method() {
        // did:plc isn't a recognized scheme yet (v2.1 roadmap).
        let id = AgentId::new("did:plc:abc123def456").unwrap();
        // Falls through to Unknown until we add a variant in v2.1.
        assert_eq!(id.scheme(), IdScheme::Unknown);
        // But it's still a parseable DID URI.
        let uri = id.as_did_uri().unwrap();
        assert_eq!(uri.method, "plc");
    }
}
