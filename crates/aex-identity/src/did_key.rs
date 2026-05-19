//! `did:key` identity provider.
//!
//! A `did:key` identifier encodes an Ed25519 public key directly inside
//! the DID string — no network call is ever required to resolve it.
//! The encoding (W3C `did:key` Method Specification, §2.1) is:
//!
//! ```text
//! did:key:z<base58btc(<multicodec-varint-prefix> || <raw-pubkey-bytes>)>
//! ```
//!
//! For Ed25519, the multicodec prefix is `0xed01` (two bytes,
//! `varint(0xed)` = `[0xed, 0x01]`). The provider currently supports
//! only Ed25519 (`did:key:z6Mk...`); other key types would be additive
//! variants.
//!
//! # Use case
//!
//! `did:key` is the canonical *offline* identity in AEX v2: tests, CI,
//! device-local agents that intentionally do not publish a card. Per
//! ADR-0047 it ships in v2.0 GA alongside `did:spize`, `did:web`, and
//! `did:ethr`.

use std::sync::Arc;

use aex_core::{
    AgentId, Error, IdScheme, IdentityProvider, Result, Signature, SignatureAlgorithm,
};
use async_trait::async_trait;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use tokio::sync::RwLock;

/// Multicodec prefix bytes for Ed25519 public keys.
///
/// Source: W3C DID Method `did:key` §2.1 + the multicodec table —
/// `ed25519-pub` is decimal 237 (`0xED`); when encoded as a varint
/// (single byte under 0x80 would be `0xED`, but the spec uses the
/// 2-byte form `0xED 0x01`).
const ED25519_MULTICODEC_PREFIX: [u8; 2] = [0xed, 0x01];

/// Length of a raw Ed25519 public key in bytes.
const ED25519_PUBKEY_LEN: usize = 32;

/// Provider for `did:key` identities.
///
/// Holds the agent's own signing key (so it can `sign()`) and an
/// in-memory cache of peer Ed25519 keys decoded from `did:key`
/// strings. Cache exists only to avoid re-running base58 decode on
/// every verify; cache misses fall back to decoding the input
/// agent_id on the spot.
pub struct DidKeyProvider {
    agent_id: AgentId,
    signing_key: SigningKey,
    peers: Arc<RwLock<std::collections::HashMap<AgentId, VerifyingKey>>>,
}

impl DidKeyProvider {
    /// Build a provider from an existing Ed25519 signing key. The
    /// agent_id is derived deterministically from the corresponding
    /// public key.
    pub fn from_signing_key(signing_key: SigningKey) -> Result<Self> {
        let verifying = signing_key.verifying_key();
        let id_str = encode_did_key(&verifying);
        let agent_id = AgentId::new(id_str)?;
        Ok(Self {
            agent_id,
            signing_key,
            peers: Arc::new(RwLock::new(Default::default())),
        })
    }

    /// Generate a fresh `did:key` identity from system entropy.
    pub fn generate() -> Result<Self> {
        let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
        Self::from_signing_key(signing_key)
    }

    /// Decode a `did:key:z...` string into its Ed25519 verifying key.
    ///
    /// Returns an error if the input is not a `did:key`, if the
    /// multibase prefix is not `z` (base58btc), if the multicodec
    /// prefix is not Ed25519, or if the key length is wrong.
    pub fn decode_pubkey(agent_id: &AgentId) -> Result<VerifyingKey> {
        if agent_id.scheme() != IdScheme::DidKey {
            return Err(Error::InvalidAgentId(format!(
                "not a did:key agent_id: {}",
                agent_id.as_str()
            )));
        }
        let uri = agent_id.as_did_uri().ok_or_else(|| {
            Error::InvalidAgentId(format!(
                "did:key id is not a valid DID URI: {}",
                agent_id.as_str()
            ))
        })?;
        let msi = uri.method_specific_id;
        // method_specific_id starts with the multibase prefix character;
        // `z` = base58btc per W3C did:key §2.1.
        let after_z = msi
            .strip_prefix('z')
            .ok_or_else(|| Error::InvalidAgentId("did:key must use base58btc (z prefix)".into()))?;

        let bytes = bs58::decode(after_z)
            .into_vec()
            .map_err(|e| Error::InvalidAgentId(format!("base58 decode failed: {}", e)))?;

        if bytes.len() != ED25519_MULTICODEC_PREFIX.len() + ED25519_PUBKEY_LEN {
            return Err(Error::InvalidAgentId(format!(
                "did:key length mismatch: got {} bytes, expected {}",
                bytes.len(),
                ED25519_MULTICODEC_PREFIX.len() + ED25519_PUBKEY_LEN
            )));
        }
        if bytes[..2] != ED25519_MULTICODEC_PREFIX {
            return Err(Error::InvalidAgentId(format!(
                "did:key multicodec prefix mismatch: got {:02x?}, expected {:02x?} (Ed25519)",
                &bytes[..2],
                ED25519_MULTICODEC_PREFIX
            )));
        }
        let pubkey_bytes: [u8; ED25519_PUBKEY_LEN] = bytes[2..]
            .try_into()
            .expect("length checked just above");
        VerifyingKey::from_bytes(&pubkey_bytes)
            .map_err(|e| Error::InvalidAgentId(format!("invalid Ed25519 public key: {}", e)))
    }

    /// Register a peer's public key. Useful when the caller has already
    /// decoded a peer's `did:key` and wants to avoid repeated decoding.
    pub async fn register_peer(&self, peer_id: AgentId, pubkey: VerifyingKey) {
        self.peers.write().await.insert(peer_id, pubkey);
    }
}

/// Encode an Ed25519 verifying key as a `did:key:z...` string.
fn encode_did_key(vk: &VerifyingKey) -> String {
    let mut buf = Vec::with_capacity(ED25519_MULTICODEC_PREFIX.len() + ED25519_PUBKEY_LEN);
    buf.extend_from_slice(&ED25519_MULTICODEC_PREFIX);
    buf.extend_from_slice(vk.as_bytes());
    format!("did:key:z{}", bs58::encode(buf).into_string())
}

#[async_trait]
impl IdentityProvider for DidKeyProvider {
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
                "did:key requires Ed25519 signature, got {:?}",
                signature.algorithm
            )));
        }

        // Cached path: peer key already registered.
        let cached = self.peers.read().await.get(peer_id).copied();
        let pubkey = match cached {
            Some(k) => k,
            None => {
                // Fallback: decode the agent_id itself. did:key is
                // self-certifying so we always have the key in-line.
                let pk = Self::decode_pubkey(peer_id)?;
                self.peers.write().await.insert(peer_id.clone(), pk);
                pk
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_yields_did_key_scheme() {
        let p = DidKeyProvider::generate().unwrap();
        assert_eq!(p.agent_id().scheme(), IdScheme::DidKey);
        assert!(p.agent_id().as_str().starts_with("did:key:z"));
    }

    #[test]
    fn from_signing_key_deterministic() {
        let sk1 = SigningKey::from_bytes(&[7u8; 32]);
        let sk2 = SigningKey::from_bytes(&[7u8; 32]);
        let p1 = DidKeyProvider::from_signing_key(sk1).unwrap();
        let p2 = DidKeyProvider::from_signing_key(sk2).unwrap();
        assert_eq!(p1.agent_id(), p2.agent_id());
    }

    #[test]
    fn roundtrip_encode_decode() {
        let sk = SigningKey::from_bytes(&[42u8; 32]);
        let original_vk = sk.verifying_key();
        let p = DidKeyProvider::from_signing_key(sk).unwrap();
        let decoded = DidKeyProvider::decode_pubkey(p.agent_id()).unwrap();
        assert_eq!(decoded.as_bytes(), original_vk.as_bytes());
    }

    #[test]
    fn reject_non_did_key_id() {
        let id = AgentId::new("did:web:acme.com#agent").unwrap();
        let err = DidKeyProvider::decode_pubkey(&id).unwrap_err();
        assert!(matches!(err, Error::InvalidAgentId(_)));
    }

    #[test]
    fn reject_wrong_multibase_prefix() {
        // 'f' = base16, not the 'z' we require.
        let id = AgentId::new("did:key:fab12cd").unwrap();
        let err = DidKeyProvider::decode_pubkey(&id).unwrap_err();
        assert!(matches!(err, Error::InvalidAgentId(_)));
    }

    #[test]
    fn reject_truncated_id() {
        // 'z' + few base58 chars → too short after decoding.
        let id = AgentId::new("did:key:zabc").unwrap();
        let err = DidKeyProvider::decode_pubkey(&id).unwrap_err();
        assert!(matches!(err, Error::InvalidAgentId(_)));
    }

    #[test]
    fn reject_wrong_multicodec_prefix() {
        // Encode bytes with a NON-Ed25519 multicodec prefix (0x12 = sha2-256).
        let mut buf: Vec<u8> = vec![0x12, 0x20];
        buf.extend_from_slice(&[0u8; 32]);
        let s = format!("did:key:z{}", bs58::encode(buf).into_string());
        let id = AgentId::new(s).unwrap();
        let err = DidKeyProvider::decode_pubkey(&id).unwrap_err();
        assert!(matches!(err, Error::InvalidAgentId(_)));
    }

    #[tokio::test]
    async fn sign_and_verify_self() {
        let p = DidKeyProvider::generate().unwrap();
        let msg = b"hello did:key";
        let sig = p.sign(msg).await.unwrap();
        p.verify_peer(p.agent_id(), msg, &sig).await.unwrap();
    }

    #[tokio::test]
    async fn verify_peer_decodes_inline_on_cache_miss() {
        let alice = DidKeyProvider::generate().unwrap();
        let bob = DidKeyProvider::generate().unwrap();
        let msg = b"from bob to alice";
        let sig = bob.sign(msg).await.unwrap();
        // Alice has never seen Bob — decode from did:key on the fly.
        alice
            .verify_peer(bob.agent_id(), msg, &sig)
            .await
            .expect("did:key peer verifies without prior registration");
    }

    #[tokio::test]
    async fn rejects_wrong_signature_algorithm() {
        let p = DidKeyProvider::generate().unwrap();
        let bogus = Signature {
            algorithm: SignatureAlgorithm::EcdsaSecp256k1,
            bytes: vec![0u8; 64],
        };
        let err = p.verify_peer(p.agent_id(), b"x", &bogus).await.unwrap_err();
        assert!(matches!(err, Error::SignatureFormat(_)));
    }

    #[tokio::test]
    async fn rejects_tampered_signature() {
        let p = DidKeyProvider::generate().unwrap();
        let msg = b"x";
        let mut sig = p.sign(msg).await.unwrap();
        sig.bytes[0] ^= 0xff;
        let err = p.verify_peer(p.agent_id(), msg, &sig).await.unwrap_err();
        assert!(matches!(err, Error::SignatureInvalid));
    }

    #[tokio::test]
    async fn rejects_wrong_signature_length() {
        let p = DidKeyProvider::generate().unwrap();
        let short = Signature {
            algorithm: SignatureAlgorithm::Ed25519,
            bytes: vec![0u8; 32], // not 64
        };
        let err = p.verify_peer(p.agent_id(), b"x", &short).await.unwrap_err();
        assert!(matches!(err, Error::SignatureFormat(_)));
    }
}
