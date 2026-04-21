use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use async_trait::async_trait;
use ed25519_dalek::{
    Signature as DalekSignature, Signer, SigningKey, Verifier, VerifyingKey, PUBLIC_KEY_LENGTH,
    SECRET_KEY_LENGTH, SIGNATURE_LENGTH,
};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

use aex_core::{AgentId, Error, IdentityProvider, Result, Signature, SignatureAlgorithm};

/// In-memory peer public-key registry.
///
/// This is the dev-tier stand-in for the control plane's Identity Registry.
/// When the control plane is wired up, this will be replaced by an async
/// client that talks to `/v1/agents/{id}` and caches results.
///
/// Shared across providers so Alice and Bob can mutually verify each other
/// in tests and local demos without a server.
#[derive(Default)]
pub struct PeerRegistry {
    peers: RwLock<HashMap<AgentId, VerifyingKey>>,
}

impl PeerRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&self, agent_id: AgentId, public_key: VerifyingKey) {
        self.peers.write().unwrap().insert(agent_id, public_key);
    }

    pub fn lookup(&self, agent_id: &AgentId) -> Option<VerifyingKey> {
        self.peers.read().unwrap().get(agent_id).copied()
    }

    pub fn len(&self) -> usize {
        self.peers.read().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.peers.read().unwrap().is_empty()
    }
}

/// Spize native identity provider backed by Ed25519.
///
/// The agent_id takes the canonical form `spize:{org}/{name}:{fingerprint}`
/// where `fingerprint` is the first 6 hex chars of SHA-256 over the public
/// key. This means the agent_id is DERIVED from the key — you cannot forge
/// an agent_id without holding the matching private key, which gives strong
/// binding at the naming layer on top of the signature verification layer.
pub struct SpizeNativeProvider {
    agent_id: AgentId,
    signing_key: SigningKey,
    peer_registry: Arc<PeerRegistry>,
}

impl SpizeNativeProvider {
    /// Generate a fresh keypair with a new random secret.
    pub fn generate(org: &str, name: &str, peer_registry: Arc<PeerRegistry>) -> Result<Self> {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self::from_signing_key(org, name, signing_key, peer_registry)
    }

    /// Load a provider from an existing raw secret key (e.g., from disk).
    pub fn from_secret_bytes(
        org: &str,
        name: &str,
        secret: [u8; SECRET_KEY_LENGTH],
        peer_registry: Arc<PeerRegistry>,
    ) -> Result<Self> {
        let signing_key = SigningKey::from_bytes(&secret);
        Self::from_signing_key(org, name, signing_key, peer_registry)
    }

    fn from_signing_key(
        org: &str,
        name: &str,
        signing_key: SigningKey,
        peer_registry: Arc<PeerRegistry>,
    ) -> Result<Self> {
        validate_label(org, "org")?;
        validate_label(name, "name")?;
        let verifying_key = signing_key.verifying_key();
        let fingerprint = compute_fingerprint(&verifying_key);
        let id_str = format!("spize:{}/{}:{}", org, name, fingerprint);
        let agent_id = AgentId::new(id_str)?;
        Ok(Self {
            agent_id,
            signing_key,
            peer_registry,
        })
    }

    /// The public key bytes. Share these to let peers verify this agent's
    /// signatures (in a real deployment, via registration at
    /// `POST /v1/agents/register`).
    pub fn public_key_bytes(&self) -> [u8; PUBLIC_KEY_LENGTH] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// The verifying key struct (for tests and direct registry insertion).
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Raw secret key bytes (32). Used by platforms that own their own
    /// identity file — the desktop app, for example, must persist this
    /// to a 0600 file. NEVER transmit these over the wire.
    pub fn secret_key_bytes(&self) -> [u8; SECRET_KEY_LENGTH] {
        self.signing_key.to_bytes()
    }
}

/// Org and name labels must be ASCII alphanumeric plus `-` / `_`, 1-64 chars.
/// This is stricter than AgentId's overall parser because we control the
/// format at creation time.
fn validate_label(s: &str, field: &str) -> Result<()> {
    if s.is_empty() {
        return Err(Error::InvalidAgentId(format!("{} is empty", field)));
    }
    if s.len() > 64 {
        return Err(Error::InvalidAgentId(format!(
            "{} too long: {}",
            field,
            s.len()
        )));
    }
    for (i, c) in s.chars().enumerate() {
        let ok = c.is_ascii_alphanumeric() || c == '-' || c == '_';
        if !ok {
            return Err(Error::InvalidAgentId(format!(
                "{} char at {}: {:?} (allowed: a-z 0-9 - _)",
                field, i, c
            )));
        }
    }
    Ok(())
}

/// Compute the 6-hex-char fingerprint (first 3 bytes of SHA-256 over the
/// public key). Collisions at this length are acceptable because the org/name
/// tuple disambiguates; the fingerprint is a tie-breaker and integrity check
/// when copying agent_ids manually.
fn compute_fingerprint(key: &VerifyingKey) -> String {
    let hash = Sha256::digest(key.as_bytes());
    hex::encode(&hash[..3])
}

#[async_trait]
impl IdentityProvider for SpizeNativeProvider {
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
                "SpizeNative only accepts Ed25519, got {:?}",
                signature.algorithm
            )));
        }
        if signature.bytes.len() != SIGNATURE_LENGTH {
            return Err(Error::SignatureFormat(format!(
                "expected {} bytes, got {}",
                SIGNATURE_LENGTH,
                signature.bytes.len()
            )));
        }

        let verifying_key = self
            .peer_registry
            .lookup(peer_id)
            .ok_or_else(|| Error::NotFound(format!("peer {} not in registry", peer_id)))?;

        let sig_bytes: [u8; SIGNATURE_LENGTH] = signature
            .bytes
            .as_slice()
            .try_into()
            .map_err(|_| Error::SignatureFormat("length mismatch".into()))?;
        let dalek_sig = DalekSignature::from_bytes(&sig_bytes);

        verifying_key
            .verify(message, &dalek_sig)
            .map_err(|_| Error::SignatureInvalid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_pair() -> (Arc<PeerRegistry>, SpizeNativeProvider, SpizeNativeProvider) {
        let reg = Arc::new(PeerRegistry::new());
        let alice = SpizeNativeProvider::generate("acme", "alice", reg.clone()).unwrap();
        let bob = SpizeNativeProvider::generate("acme", "bob", reg.clone()).unwrap();
        reg.register(alice.agent_id().clone(), alice.verifying_key());
        reg.register(bob.agent_id().clone(), bob.verifying_key());
        (reg, alice, bob)
    }

    #[tokio::test]
    async fn sign_and_verify_roundtrip() {
        let (_reg, alice, bob) = setup_pair();
        let msg = b"hello bob, from alice";
        let sig = alice.sign(msg).await.unwrap();
        bob.verify_peer(alice.agent_id(), msg, &sig).await.unwrap();
    }

    #[tokio::test]
    async fn tampered_message_rejected() {
        let (_reg, alice, bob) = setup_pair();
        let msg = b"hello";
        let sig = alice.sign(msg).await.unwrap();
        let err = bob
            .verify_peer(alice.agent_id(), b"hxllo", &sig)
            .await
            .unwrap_err();
        assert!(matches!(err, Error::SignatureInvalid));
    }

    #[tokio::test]
    async fn tampered_signature_rejected() {
        let (_reg, alice, bob) = setup_pair();
        let msg = b"hello";
        let mut sig = alice.sign(msg).await.unwrap();
        sig.bytes[0] ^= 0xff;
        let err = bob
            .verify_peer(alice.agent_id(), msg, &sig)
            .await
            .unwrap_err();
        assert!(matches!(err, Error::SignatureInvalid));
    }

    #[tokio::test]
    async fn unknown_peer_rejected() {
        let reg = Arc::new(PeerRegistry::new());
        let alice = SpizeNativeProvider::generate("acme", "alice", reg.clone()).unwrap();
        let bob = SpizeNativeProvider::generate("acme", "bob", reg.clone()).unwrap();
        // Alice is NOT registered
        let sig = alice.sign(b"hi").await.unwrap();
        let err = bob
            .verify_peer(alice.agent_id(), b"hi", &sig)
            .await
            .unwrap_err();
        assert!(matches!(err, Error::NotFound(_)));
    }

    #[tokio::test]
    async fn wrong_algorithm_rejected() {
        let (_reg, alice, bob) = setup_pair();
        let wrong = Signature {
            algorithm: SignatureAlgorithm::EcdsaSecp256k1,
            bytes: vec![0u8; SIGNATURE_LENGTH],
        };
        let err = bob
            .verify_peer(alice.agent_id(), b"hi", &wrong)
            .await
            .unwrap_err();
        assert!(matches!(err, Error::SignatureFormat(_)));
    }

    #[tokio::test]
    async fn wrong_signature_length_rejected() {
        let (_reg, alice, bob) = setup_pair();
        let wrong = Signature {
            algorithm: SignatureAlgorithm::Ed25519,
            bytes: vec![0u8; 32], // too short
        };
        let err = bob
            .verify_peer(alice.agent_id(), b"hi", &wrong)
            .await
            .unwrap_err();
        assert!(matches!(err, Error::SignatureFormat(_)));
    }

    #[test]
    fn generate_produces_expected_agent_id_format() {
        let reg = Arc::new(PeerRegistry::new());
        let p = SpizeNativeProvider::generate("acme", "alice", reg).unwrap();
        let id = p.agent_id().as_str();
        assert!(id.starts_with("spize:acme/alice:"));
        let fingerprint = id.rsplit(':').next().unwrap();
        assert_eq!(fingerprint.len(), 6);
        assert!(fingerprint.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn deterministic_id_from_same_secret() {
        let reg = Arc::new(PeerRegistry::new());
        let secret = [7u8; SECRET_KEY_LENGTH];
        let p1 =
            SpizeNativeProvider::from_secret_bytes("acme", "alice", secret, reg.clone()).unwrap();
        let p2 = SpizeNativeProvider::from_secret_bytes("acme", "alice", secret, reg).unwrap();
        assert_eq!(p1.agent_id(), p2.agent_id());
        assert_eq!(p1.public_key_bytes(), p2.public_key_bytes());
    }

    #[test]
    fn different_secrets_yield_different_ids() {
        let reg = Arc::new(PeerRegistry::new());
        let a = SpizeNativeProvider::from_secret_bytes(
            "acme",
            "alice",
            [1u8; SECRET_KEY_LENGTH],
            reg.clone(),
        )
        .unwrap();
        let b =
            SpizeNativeProvider::from_secret_bytes("acme", "alice", [2u8; SECRET_KEY_LENGTH], reg)
                .unwrap();
        assert_ne!(a.agent_id(), b.agent_id());
    }

    #[test]
    fn empty_org_rejected() {
        let reg = Arc::new(PeerRegistry::new());
        assert!(matches!(
            SpizeNativeProvider::generate("", "alice", reg),
            Err(Error::InvalidAgentId(_))
        ));
    }

    #[test]
    fn empty_name_rejected() {
        let reg = Arc::new(PeerRegistry::new());
        assert!(matches!(
            SpizeNativeProvider::generate("acme", "", reg),
            Err(Error::InvalidAgentId(_))
        ));
    }

    #[test]
    fn bad_label_chars_rejected() {
        let reg = Arc::new(PeerRegistry::new());
        assert!(matches!(
            SpizeNativeProvider::generate("acme corp", "alice", reg),
            Err(Error::InvalidAgentId(_))
        ));
    }

    #[tokio::test]
    async fn cross_verification_between_many_peers() {
        let reg = Arc::new(PeerRegistry::new());
        let agents: Vec<SpizeNativeProvider> = (0..10)
            .map(|i| {
                let p = SpizeNativeProvider::generate("acme", &format!("agent-{}", i), reg.clone())
                    .unwrap();
                reg.register(p.agent_id().clone(), p.verifying_key());
                p
            })
            .collect();

        // Every agent signs the same message; every other agent verifies.
        let msg = b"broadcast";
        for signer in &agents {
            let sig = signer.sign(msg).await.unwrap();
            for verifier in &agents {
                verifier
                    .verify_peer(signer.agent_id(), msg, &sig)
                    .await
                    .expect("cross-verification failed");
            }
        }
    }
}
