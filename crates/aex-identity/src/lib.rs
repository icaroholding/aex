//! Identity providers for the Agent Exchange Protocol (AEX).
//!
//! Currently shipping:
//! - [`SpizeNativeProvider`] — Ed25519 keypair + in-memory peer registry.
//! - [`EtereCitizenProvider`] — `did:ethr` + ECDSA secp256k1 (Ethereum-
//!   compatible wallet signatures). In-memory registry + stub reputation
//!   fetcher; Phase 2 swaps the registry for a Base L2 RPC client with
//!   EtereCitizen's on-chain reputation.
//! - [`DidKeyProvider`] — `did:key` (Ed25519, self-certifying, offline).
//! - [`DidWebProvider`] — `did:web` via HTTPS `/.well-known/agent-card.json`
//!   fetched through [`aex_net::safe_http`] + verified as JWS via
//!   [`aex_jws`].

pub mod did_key;
pub mod did_web;
pub mod etere_citizen;
pub mod native;
pub mod resolver_chain;

pub use did_key::DidKeyProvider;
pub use did_web::{AgentCardPayload, DidWebProvider, Endpoints, PublicKeyDeclaration};
pub use etere_citizen::{EtereCitizenProvider, EtereCitizenRegistry, ReputationFetcher};
pub use native::{PeerRegistry, SpizeNativeProvider};
pub use resolver_chain::{
    AgentResolver, ResolvedAgent, ResolveOutcome, ResolverChain, ResolverError, DEFAULT_CAPACITY,
    DEFAULT_TTL,
};
