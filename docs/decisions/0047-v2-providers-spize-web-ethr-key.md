# ADR-0047: v2.0 GA ships four DID providers: `spize`, `web`, `ethr`, `key`

## Status

Accepted 2026-05-19.

## Context

ADR-0041 commits AEX v2 to W3C DID URIs as the canonical agent-handle
shape. That decision is independent of *which* DID methods AEX ships at
GA. The universe of DID methods is large — `did:plc` (Bluesky AT Protocol),
`did:ans` (GoDaddy/Infoblox, 2026-05-14), `did:ens` (Ethereum Name Service),
`did:peer`, `did:ion`, and more — and shipping all of them by v2.0 GA would
expand the surface area beyond what we can test, document, and operate.

Each DID method we ship adds:
- A provider implementation in `aex-identity`
- Cache + resolver chain integration
- Conformance tests
- Runbooks for operational debugging
- A "we promise this works" surface that has to keep working

The right scope at GA is the *minimum* set that covers the realistic v2
deployment scenarios. Other methods stage as v2.1 and beyond.

## Decision

AEX v2.0 GA ships these four DID providers:

| Method | Use case | Why first |
|---|---|---|
| `did:spize` | Hosted convenience for users without a domain | The continuity path for `spize:` legacy ids (ADR-0042). Lowest friction onboarding. |
| `did:web` | Organisations with a domain | The path that lets AEX adopt without dragging customers into our registry. Aligns with A2A v1.0 and ANS. |
| `did:ethr` | EtereCitizen reputation (ADR-0040) | Trust scoring. Differentiator vs every other agent stack. |
| `did:key` | Offline / device-local self-certifying | Required for tests, CI, and any agent that can't (or won't) publish a card. |

These four cover: hosted, federated, reputation-anchored, and offline —
the four axes of identity that any realistic AEX deployment will need at
GA.

Deferred to v2.1 (post-GA): `did:plc`, `did:ans`, `did:ens`, `did:peer`,
`did:ion`. They land as additive `IdScheme` variants without breaking the
wire format — the v2 protocol does not depend on the method count.

## Consequences

- The conformance suite (ADR-0048) at GA exercises the four GA methods.
  v2.1 methods get tests as they ship.
- `aex-identity` ships four provider implementations at GA; each is
  small (`did:key` < 150 LOC, `did:web` ~400, `did:ethr` reuses the
  existing EtereCitizen provider, `did:spize` reuses the existing
  SpizeNative provider).
- Documentation in `protocol-v2.md` §1 names all four with one
  resolution example each.
- The `RecommendedDidMethods` capability advertisement on the Spize
  reference control plane lists exactly these four; operators can extend
  via config.
- Operators surprised by an unsupported `did:plc` handle see a clear
  `ResolverError::UnsupportedDidMethod` error message that points to the
  v2.1 roadmap, not a generic 500.
