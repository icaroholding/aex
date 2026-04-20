use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::Error;

const MAX_AGENT_ID_LEN: usize = 256;

/// Canonical agent identifier.
///
/// Two format families are supported:
///
/// - **SpizeNative**: `spize:{org}/{name}:{fingerprint}`
///   e.g. `spize:acme/accountant-v3:a4f8b2`
/// - **DID**: `did:{method}:{method-specific}`
///   e.g. `did:ethr:0x14a34:0xabc...`, `did:web:example.com:agents:bob`
///
/// The identifier is opaque at this layer; the [`crate::IdentityProvider`]
/// implementation for a given scheme knows how to verify signatures and
/// resolve metadata.
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
}

/// Known identity schemes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdScheme {
    SpizeNative,
    DidEthr,
    DidWeb,
    DidKey,
    Unknown,
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
        assert!(matches!(
            AgentId::new(""),
            Err(Error::InvalidAgentId(_))
        ));
    }

    #[test]
    fn too_long_rejected() {
        let long = "spize:acme/alice:".to_string() + &"a".repeat(300);
        assert!(matches!(
            AgentId::new(long),
            Err(Error::InvalidAgentId(_))
        ));
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
}
