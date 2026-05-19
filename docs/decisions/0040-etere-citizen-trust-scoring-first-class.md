# ADR-0040: EtereCitizen (`did:ethr`) promoted to first-class trust-scoring layer in v2

## Status

Accepted 2026-05-19.

## Context

ADR-0006 introduced `did:ethr` as a minimal, optional identity scheme to be
expanded "on adoption signal". The v2 wire format (ADR-0042) takes the
opportunity to commit to multi-issuer identity end-to-end: instead of one
canonical registry (`spize.io`), agent identities can be claimed via any of
several DID methods, federated by the W3C resolver chain.

Among those methods, `did:ethr` is the only one that ships a reputation
index — the EtereCitizen on-chain registry on Base L2 — out of the box. Every
other DID method (`did:web`, `did:key`, `did:spize`) verifies *who* a key
belongs to but says nothing about *whether the holder is trustworthy*. That
gap is what compliance teams care about most when an agent presents itself.

## Decision

In v2, EtereCitizen-backed identities (`did:ethr:<chainId>:<address>`) are
treated as **first-class trust-scoring agents** in AEX. Specifically:

1. The reference resolver chain (ADR-0047) always includes `DidEthrProvider`
   in its default configuration; opting out requires explicit configuration.
2. `aex-core::Capability::EtereCitizenTrust` is reserved for agent cards
   whose issuer is `did:ethr` and whose key is observed on-chain. The bit is
   set automatically by the resolver, not declared by the agent.
3. The reputation score exposed by the EtereCitizen registry is surfaced as
   a structured field on the resolver's `ResolvedAgent` output. Downstream
   policy hooks (`aex-policy`) consume it as a trust signal.
4. The on-chain RPC pool used by `DidEthrProvider` consists of three
   independent endpoints (Base official, Alchemy, QuickNode); a 2-of-3
   consensus is required for a response to be considered authoritative.

## Consequences

- AEX gains a differentiating capability (trust scoring) that competing
  agent identity stacks (Google A2A, did:web alone, did:plc) do not.
- EtereCitizen becomes load-bearing for AEX adoption decisions. ADR-0010
  funding remains independent, but operational availability of EtereCitizen
  endpoints (RPC pool health) becomes a tracked SLO.
- The Phase-2 in-memory stub in `aex-identity/src/etere_citizen.rs` is
  promoted to a real Base L2 RPC client by v2.0 GA.
- Compliance teams adopting AEX can rely on the trust signal without
  building their own out-of-band reputation infrastructure.
- The reputation index becomes a stable, signed-once-per-update wire
  contract; changes to its on-chain schema require their own ADR.
