//! `did:web` identity provider.
//!
//! Resolves `did:web:<authority>[#<fragment>]` by fetching
//! `https://<authority>/.well-known/agent-card.json` via the
//! SSRF-resistant client from [`aex_net::safe_http`] (ADR-0045) and
//! verifying the response as a JWS (ADR-0025) using
//! [`aex_jws`].
//!
//! # Out of scope here
//!
//! Caching, single-flight stampede protection, and ETag-conditional
//! revalidation belong to the resolver chain (chunk 5). This module
//! does one fetch per `verify_peer` call; the resolver layer is what
//! wraps it for production use.

use std::sync::Arc;

use aex_core::{
    AgentId, Capability, CapabilitySet, Error, IdScheme, IdentityProvider, Result, Signature,
    SignatureAlgorithm,
};
use aex_jws::{Algorithm as JwsAlgorithm, VerifierKey};
use async_trait::async_trait;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

/// Multicodec prefix for Ed25519 public keys in `did:key` form.
const ED25519_MULTICODEC_PREFIX: [u8; 2] = [0xed, 0x01];

/// Provider for `did:web` identities.
///
/// Holds the agent's own Ed25519 signing key + the `did:web` URI it
/// claims (set externally because the URI binds to a domain the agent
/// or its operator controls — not derivable from the key alone).
///
/// Peers are resolved on-demand from their `did:web` URI. A small
/// optional cache keyed by `AgentId` lets test setups pre-seed peer
/// keys without going through the network.
pub struct DidWebProvider {
    agent_id: AgentId,
    signing_key: SigningKey,
    peers: Arc<RwLock<std::collections::HashMap<AgentId, VerifyingKey>>>,
    /// Component identifier passed to [`safe_http`] for user-agent.
    component_name: String,
}

impl DidWebProvider {
    /// Construct a provider that signs on behalf of `agent_id`.
    ///
    /// `agent_id` MUST be a `did:web:authority[#fragment]` URI;
    /// otherwise the constructor errors out.
    pub fn new(
        agent_id: AgentId,
        signing_key: SigningKey,
        component_name: impl Into<String>,
    ) -> Result<Self> {
        if agent_id.scheme() != IdScheme::DidWeb {
            return Err(Error::InvalidAgentId(format!(
                "DidWebProvider requires a did:web agent_id, got {}",
                agent_id.as_str()
            )));
        }
        Ok(Self {
            agent_id,
            signing_key,
            peers: Arc::new(RwLock::new(Default::default())),
            component_name: component_name.into(),
        })
    }

    /// Test-only / advanced: pre-register a peer's Ed25519 verifying
    /// key so `verify_peer` does not hit the network for that peer.
    pub async fn register_peer(&self, peer_id: AgentId, pubkey: VerifyingKey) {
        self.peers.write().await.insert(peer_id, pubkey);
    }

    /// Build the well-known URL for a `did:web` agent_id.
    ///
    /// Per the W3C did:web spec, `did:web:example.com` resolves to
    /// `https://example.com/.well-known/did.json`. AEX uses the
    /// `agent-card.json` variant per ADR-0025; both live under
    /// `/.well-known/`.
    pub fn well_known_url(agent_id: &AgentId) -> Result<String> {
        let uri = agent_id.as_did_uri().ok_or_else(|| {
            Error::InvalidAgentId(format!(
                "did:web id is not a valid DID URI: {}",
                agent_id.as_str()
            ))
        })?;
        if uri.method != "web" {
            return Err(Error::InvalidAgentId(format!(
                "expected did:web, got did:{}",
                uri.method
            )));
        }
        // W3C did:web allows `:` in the method-specific-id to encode
        // path segments (e.g. did:web:example.com:agents:bob →
        // https://example.com/agents/bob/did.json). For agent-card,
        // AEX puts the card at the *authority root* (no path), so
        // we take only the first `:`-segment as the authority.
        let authority = uri.method_specific_id.split(':').next().unwrap_or("");
        if authority.is_empty() {
            return Err(Error::InvalidAgentId("did:web authority is empty".into()));
        }
        // Defensive: reject schemes that snuck into the authority
        // (e.g. did:web:https://...) — they would let an attacker
        // smuggle a non-https URL through.
        if authority.contains('/') || authority.contains('?') || authority.contains('#') {
            return Err(Error::InvalidAgentId(format!(
                "did:web authority contains URL-reserved chars: {}",
                authority
            )));
        }
        Ok(format!("https://{}/.well-known/agent-card.json", authority))
    }

    /// Fetch the agent card for `peer_id`, verify its JWS signature,
    /// and return the (verifying-key, parsed-payload) pair.
    pub async fn fetch_and_verify_card(
        &self,
        peer_id: &AgentId,
    ) -> Result<(VerifyingKey, AgentCardPayload)> {
        let url = Self::well_known_url(peer_id)?;
        let resp = aex_net::safe_get(&url, &self.component_name)
            .await
            .map_err(|e| Error::NotFound(format!("did:web fetch failed for {}: {}", peer_id, e)))?;

        let jws = std::str::from_utf8(&resp.body)
            .map_err(|e| Error::Crypto(format!("agent card not UTF-8: {}", e)))?;

        // We verify the JWS by trusting the embedded `public_key` —
        // it's self-attesting at this layer. The trust anchor for
        // did:web is the DNS+TLS chain establishing the agent's
        // ownership of the domain; ADR-0026 layers an extra proof
        // block on top of that.
        let verified = aex_jws::verify(jws.trim(), |kid| {
            // Two-pass parse: peek at the payload to extract the
            // declared public_key, then verify with it.
            //
            // RFC 7515 doesn't allow us to peek inside the payload
            // before verifying, so we do a structural unpack: split
            // the JWS, base64-decode the payload, parse the
            // public_key, and return it as the verifier key.
            // The signature verification will then guarantee the
            // payload (including public_key) wasn't tampered with —
            // attacker swapping the public_key forces the
            // signature to break.
            let payload_b64 = jws
                .trim()
                .split('.')
                .nth(1)
                .ok_or(aex_jws::JwsError::InvalidStructure)?;
            use base64::engine::general_purpose::URL_SAFE_NO_PAD;
            use base64::Engine;
            let payload_bytes = URL_SAFE_NO_PAD
                .decode(payload_b64)
                .map_err(|e| aex_jws::JwsError::Base64Decode(format!("payload: {}", e)))?;
            let payload: AgentCardPayload = serde_json::from_slice(&payload_bytes)
                .map_err(|e| aex_jws::JwsError::InvalidHeader(format!("payload parse: {}", e)))?;

            // Sanity: kid in header matches agent_id in payload.
            // Reject otherwise — that's the kid-substitution attack.
            if payload.agent_id != kid {
                return Err(aex_jws::JwsError::KidAlgMismatch {
                    kid: kid.into(),
                    header_alg: "EdDSA".into(),
                    key_alg: format!("payload claims {}", payload.agent_id),
                });
            }
            let vk = decode_did_key_multibase(&payload.public_key.public_key_multibase)
                .map_err(|e| aex_jws::JwsError::InvalidHeader(format!("public_key: {}", e)))?;
            Ok(Some(VerifierKey::Ed25519(vk)))
        })
        .map_err(|e| Error::Crypto(format!("agent card JWS verify failed: {}", e)))?;

        if verified.header.alg != JwsAlgorithm::EdDsa {
            return Err(Error::Crypto(format!(
                "did:web cards must use EdDSA for now; got {:?}",
                verified.header.alg
            )));
        }

        let payload: AgentCardPayload = serde_json::from_slice(&verified.payload)
            .map_err(|e| Error::Crypto(format!("agent card payload parse: {}", e)))?;
        let vk = decode_did_key_multibase(&payload.public_key.public_key_multibase)?;

        Ok((vk, payload))
    }
}

#[async_trait]
impl IdentityProvider for DidWebProvider {
    fn agent_id(&self) -> &AgentId {
        &self.agent_id
    }

    async fn sign(&self, message: &[u8]) -> Result<Signature> {
        let sig = self.signing_key.sign(message);
        Ok(Signature {
            algorithm: SignatureAlgorithm::Ed25519,
            bytes: sig.to_bytes().to_vec(),
        })
    }

    async fn verify_peer(
        &self,
        peer_id: &AgentId,
        message: &[u8],
        signature: &Signature,
    ) -> Result<()> {
        if signature.algorithm != SignatureAlgorithm::Ed25519 {
            return Err(Error::SignatureFormat(format!(
                "did:web (Ed25519 keys) requires Ed25519 signature, got {:?}",
                signature.algorithm
            )));
        }

        // Cached?
        let cached = self.peers.read().await.get(peer_id).copied();
        let pubkey = match cached {
            Some(k) => k,
            None => {
                let (vk, _payload) = self.fetch_and_verify_card(peer_id).await?;
                self.peers.write().await.insert(peer_id.clone(), vk);
                vk
            }
        };

        use ed25519_dalek::Verifier;
        let sig_bytes: [u8; 64] = signature.bytes.as_slice().try_into().map_err(|_| {
            Error::SignatureFormat(format!(
                "Ed25519 signature must be 64 bytes, got {}",
                signature.bytes.len()
            ))
        })?;
        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        pubkey
            .verify(message, &sig)
            .map_err(|_| Error::SignatureInvalid)
    }
}

/// Parsed JWS payload of a JWS-signed agent card (ADR-0025).
///
/// Fields beyond these are tolerated (forward-compat); unknown fields
/// are dropped by `serde(deny_unknown_fields = false)` (the default).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentCardPayload {
    /// Issuer DID (typically the authority, e.g. `did:web:acme.com`).
    pub iss: String,
    /// Subject DID — same as `agent_id` for self-signed cards.
    pub sub: String,
    /// `iat` claim, Unix seconds.
    pub iat: i64,
    /// `exp` claim, Unix seconds.
    pub exp: i64,
    /// Full agent_id as advertised by this card.
    pub agent_id: String,
    /// Public key declaration (W3C Verifiable Credentials shape).
    pub public_key: PublicKeyDeclaration,
    /// Capability bits as wire strings (see [`aex_core::Capability`]).
    #[serde(default)]
    pub capabilities: CapabilitySet,
    /// Endpoint hints (control plane, data planes).
    #[serde(default)]
    pub endpoints: Endpoints,
}

/// Public key block embedded in [`AgentCardPayload`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyDeclaration {
    /// `"Ed25519VerificationKey2020"` for Ed25519 keys.
    #[serde(rename = "type")]
    pub key_type: String,
    /// Multibase-encoded public key (W3C did:key §2.1 form).
    #[serde(rename = "publicKeyMultibase")]
    pub public_key_multibase: String,
}

/// Endpoint hints advertised by an agent card.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Endpoints {
    /// Control plane URL.
    pub control_plane: Option<String>,
    /// Zero or more data-plane URLs (for P2P bytes).
    #[serde(default)]
    pub data_planes: Vec<String>,
}

impl AgentCardPayload {
    /// Convenience: does this card advertise the given capability?
    pub fn has_capability(&self, cap: Capability) -> bool {
        self.capabilities.has(cap)
    }
}

/// Decode a multibase `z6Mk...` Ed25519 public key into a [`VerifyingKey`].
///
/// Shared with [`crate::did_key`] but kept local to avoid a public
/// dependency between sibling modules — they may evolve different
/// validation rules.
fn decode_did_key_multibase(s: &str) -> Result<VerifyingKey> {
    let after_z = s
        .strip_prefix('z')
        .ok_or_else(|| Error::Crypto(format!("multibase must start with 'z', got '{}'", s)))?;
    let bytes = bs58::decode(after_z)
        .into_vec()
        .map_err(|e| Error::Crypto(format!("base58 decode: {}", e)))?;
    if bytes.len() != ED25519_MULTICODEC_PREFIX.len() + 32 {
        return Err(Error::Crypto(format!(
            "multibase length mismatch: {} bytes",
            bytes.len()
        )));
    }
    if bytes[..2] != ED25519_MULTICODEC_PREFIX {
        return Err(Error::Crypto(format!(
            "multicodec prefix mismatch: {:02x?}",
            &bytes[..2]
        )));
    }
    let pk: [u8; 32] = bytes[2..].try_into().expect("length checked above");
    VerifyingKey::from_bytes(&pk).map_err(|e| Error::Crypto(format!("Ed25519 key: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_did_web_provider() -> DidWebProvider {
        let sk = SigningKey::from_bytes(&[3u8; 32]);
        let id = AgentId::new("did:web:acme.com#agent-vendite").unwrap();
        DidWebProvider::new(id, sk, "test").unwrap()
    }

    #[test]
    fn well_known_url_simple() {
        let id = AgentId::new("did:web:acme.com#fatture").unwrap();
        let url = DidWebProvider::well_known_url(&id).unwrap();
        assert_eq!(url, "https://acme.com/.well-known/agent-card.json");
    }

    #[test]
    fn well_known_url_strips_fragment() {
        let id = AgentId::new("did:web:studio-rossi.it#clienti").unwrap();
        let url = DidWebProvider::well_known_url(&id).unwrap();
        assert!(!url.contains("clienti"));
        assert_eq!(url, "https://studio-rossi.it/.well-known/agent-card.json");
    }

    #[test]
    fn well_known_url_takes_authority_root() {
        // did:web supports path-style msi (`example.com:agents:bob`)
        // but AEX puts the card at the authority root.
        let id = AgentId::new("did:web:example.com:agents:bob").unwrap();
        let url = DidWebProvider::well_known_url(&id).unwrap();
        assert_eq!(url, "https://example.com/.well-known/agent-card.json");
    }

    #[test]
    fn well_known_url_rejects_non_web() {
        let id = AgentId::new("did:key:zabc").unwrap();
        let err = DidWebProvider::well_known_url(&id).unwrap_err();
        assert!(matches!(err, Error::InvalidAgentId(_)));
    }

    #[test]
    fn well_known_url_rejects_authority_with_slash() {
        // did:web id constructed by hand carrying suspicious chars.
        // AgentId::new lets this through because slashes are valid;
        // well_known_url is the guard.
        let id = AgentId::new("did:web:evil.com/path").unwrap();
        let err = DidWebProvider::well_known_url(&id).unwrap_err();
        assert!(matches!(err, Error::InvalidAgentId(_)));
    }

    #[test]
    fn constructor_rejects_non_did_web_id() {
        let sk = SigningKey::from_bytes(&[1u8; 32]);
        let id = AgentId::new("did:key:zabc").unwrap();
        match DidWebProvider::new(id, sk, "test") {
            Err(Error::InvalidAgentId(_)) => {}
            Err(other) => panic!("wrong error variant: {other:?}"),
            Ok(_) => panic!("expected rejection of non-did:web agent_id"),
        }
    }

    #[test]
    fn agent_id_returns_did_web() {
        let p = fixed_did_web_provider();
        assert_eq!(p.agent_id().scheme(), IdScheme::DidWeb);
        assert_eq!(p.agent_id().as_str(), "did:web:acme.com#agent-vendite");
    }

    #[tokio::test]
    async fn sign_and_verify_self_with_registered_key() {
        let p = fixed_did_web_provider();
        let vk = p.signing_key.verifying_key();
        // Pre-register own key for self-verification (would normally
        // be done by the resolver chain).
        p.register_peer(p.agent_id().clone(), vk).await;
        let sig = p.sign(b"hi").await.unwrap();
        p.verify_peer(p.agent_id(), b"hi", &sig).await.unwrap();
    }

    #[tokio::test]
    async fn rejects_wrong_signature_algorithm() {
        let p = fixed_did_web_provider();
        let bogus = Signature {
            algorithm: SignatureAlgorithm::EcdsaSecp256k1,
            bytes: vec![0u8; 64],
        };
        let err = p.verify_peer(p.agent_id(), b"x", &bogus).await.unwrap_err();
        assert!(matches!(err, Error::SignatureFormat(_)));
    }

    #[tokio::test]
    async fn rejects_tampered_signature() {
        let p = fixed_did_web_provider();
        let vk = p.signing_key.verifying_key();
        p.register_peer(p.agent_id().clone(), vk).await;
        let mut sig = p.sign(b"x").await.unwrap();
        sig.bytes[0] ^= 0xff;
        let err = p.verify_peer(p.agent_id(), b"x", &sig).await.unwrap_err();
        assert!(matches!(err, Error::SignatureInvalid));
    }

    #[test]
    fn agent_card_payload_serde_roundtrip() {
        let card = AgentCardPayload {
            iss: "did:web:acme.com".into(),
            sub: "did:web:acme.com#fatture".into(),
            iat: 1_716_100_000,
            exp: 1_716_186_400,
            agent_id: "did:web:acme.com#fatture".into(),
            public_key: PublicKeyDeclaration {
                key_type: "Ed25519VerificationKey2020".into(),
                public_key_multibase: "z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV".into(),
            },
            capabilities: CapabilitySet::empty()
                .with(Capability::WireV2)
                .with(Capability::JwsAgentCard),
            endpoints: Endpoints {
                control_plane: Some("https://acme.com/aex".into()),
                data_planes: vec!["https://data.acme.com".into()],
            },
        };
        let json = serde_json::to_string(&card).unwrap();
        let back: AgentCardPayload = serde_json::from_str(&json).unwrap();
        assert_eq!(card.agent_id, back.agent_id);
        assert!(back.has_capability(Capability::WireV2));
        assert!(back.has_capability(Capability::JwsAgentCard));
        assert!(!back.has_capability(Capability::A2ABridge));
    }

    #[test]
    fn decode_did_key_multibase_roundtrip() {
        let sk = SigningKey::from_bytes(&[5u8; 32]);
        let vk = sk.verifying_key();
        let mut buf: Vec<u8> = ED25519_MULTICODEC_PREFIX.to_vec();
        buf.extend_from_slice(vk.as_bytes());
        let encoded = format!("z{}", bs58::encode(buf).into_string());
        let decoded = decode_did_key_multibase(&encoded).unwrap();
        assert_eq!(decoded.as_bytes(), vk.as_bytes());
    }

    #[test]
    fn decode_rejects_missing_z_prefix() {
        let err = decode_did_key_multibase("ab12cd").unwrap_err();
        assert!(matches!(err, Error::Crypto(_)));
    }

    #[test]
    fn decode_rejects_bad_multicodec() {
        // 0x12 0x20 = sha2-256 + 32 zero bytes — wrong codec.
        let mut buf: Vec<u8> = vec![0x12, 0x20];
        buf.extend_from_slice(&[0u8; 32]);
        let s = format!("z{}", bs58::encode(buf).into_string());
        let err = decode_did_key_multibase(&s).unwrap_err();
        assert!(matches!(err, Error::Crypto(_)));
    }
}
