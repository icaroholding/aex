//! Identity providers for the Agent Exchange Protocol (AEX).
//!
//! Currently shipping:
//! - [`SpizeNativeProvider`] — Ed25519 keypair + in-memory peer registry.
//! - [`EtereCitizenProvider`] — `did:ethr` + ECDSA secp256k1 (Ethereum-
//!   compatible wallet signatures). In-memory registry + stub reputation
//!   fetcher; Phase 2 swaps the registry for a Base L2 RPC client with
//!   EtereCitizen's on-chain reputation.
//!
//! Planned:
//! - `DidWebProvider` — did:web resolution via HTTPS `.well-known/did.json`.

pub mod etere_citizen;
pub mod native;

pub use etere_citizen::{EtereCitizenProvider, EtereCitizenRegistry, ReputationFetcher};
pub use native::{PeerRegistry, SpizeNativeProvider};
