use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::{AgentId, Result, Signature};

/// The pluggable identity provider interface.
///
/// An `IdentityProvider` represents a holder of ONE agent's signing key
/// plus its view onto the wider registry of peer public keys. The same
/// trait is implemented by:
///
/// - `SpizeNativeProvider` — Ed25519 + Spize's central Identity Registry.
/// - `EtereCitizenProvider` — did:ethr wallet + EtereCitizen on-chain
///   registry and reputation.
/// - `DidWebProvider` — did:web resolution via HTTPS.
///
/// The control plane dispatches to the right provider based on the scheme
/// of the incoming agent_id.
#[async_trait]
pub trait IdentityProvider: Send + Sync {
    /// The agent this provider represents (i.e., the identity that
    /// `sign()` will produce signatures for).
    fn agent_id(&self) -> &AgentId;

    /// Sign an arbitrary byte string with the agent's private key.
    ///
    /// Errors if the key is unavailable (file missing, HSM offline, user
    /// unlocked required).
    async fn sign(&self, message: &[u8]) -> Result<Signature>;

    /// Verify that `signature` was produced by `peer_id` over `message`.
    ///
    /// Implementations are responsible for:
    /// 1. Resolving `peer_id` to a public key (via their registry of choice)
    /// 2. Verifying the signature cryptographically
    /// 3. Checking revocation status (e.g., CRL lookup)
    async fn verify_peer(
        &self,
        peer_id: &AgentId,
        message: &[u8],
        signature: &Signature,
    ) -> Result<()>;

    /// Optional: fetch trust metadata about a peer (reputation, verification
    /// level, capabilities). Returns `None` if this provider does not support
    /// trust metadata — callers must handle that gracefully.
    ///
    /// Policies that depend on reputation must use `has_reputation()` style
    /// guards rather than requiring metadata presence unconditionally.
    async fn trust_metadata(&self, _peer_id: &AgentId) -> Option<TrustMetadata> {
        None
    }
}

/// Opaque trust metadata about a peer, returned by providers that support it
/// (primarily `EtereCitizenProvider`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TrustMetadata {
    /// Creator verification level, typically 0-3 (0 = unverified, 3 = KYC).
    pub verification_level: Option<u8>,
    /// Reputation score. Scale is provider-defined; EtereCitizen uses
    /// weighted composite in the [0.0, 5.0] range.
    pub reputation_score: Option<f32>,
    /// Number of reviews backing the reputation score.
    pub review_count: Option<u32>,
    /// Declared capabilities (e.g. "code-generation", "research").
    pub capabilities: Vec<String>,
    /// Flags provided by the registry (e.g. "NEW_AGENT", "NO_REVIEWS").
    pub flags: Vec<String>,
}
