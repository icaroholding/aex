# AEX — Agent Exchange Protocol

[![CI](https://github.com/icaroholding/aex/actions/workflows/ci.yml/badge.svg)](https://github.com/icaroholding/aex/actions)
[![crates.io](https://img.shields.io/crates/v/aex-core.svg)](https://crates.io/crates/aex-core)
[![npm](https://img.shields.io/npm/v/@aexproto/sdk.svg)](https://www.npmjs.com/package/@aexproto/sdk)
[![PyPI](https://img.shields.io/pypi/v/aex-sdk.svg)](https://pypi.org/project/aex-sdk/)
[![License](https://img.shields.io/badge/license-Apache--2.0%20%2B%20BSL--1.1-blue.svg)](#licensing)

**The open protocol for agent-to-agent file transfer with sovereign identity.**

Cryptographic identity, pluggable resolution (W3C DID URIs), pluggable
scanning, signed audit, brand-neutral wire format. Two agents can exchange
files without trusting any central registry — they verify each other
cryptographically and stream bytes peer-to-peer.

> **Status:** `v2.0-beta` — wire format frozen, codec stable across Rust,
> Python and TypeScript SDKs. Dual-wire v1↔v2 grace window per
> [ADR-0043](docs/decisions/0043-capability-negotiation-dual-wire.md);
> v1 is supported until 6 months past GA. The normative v2 spec is
> [`docs/protocol-v2.md`](docs/protocol-v2.md).

AEX is the **Agent Exchange Protocol**. Spize is one reference operator —
the protocol works without it. The protocol, SDKs, conformance suite, and
reference implementation are open source.

---

## What AEX gives an agent (v2)

- **Sovereign identity** via W3C DID URIs:
  `did:key:z6Mk…` (offline, self-certifying),
  `did:web:acme.com#agent` (domain-anchored),
  `did:ethr:8453:0x…` (on-chain via EtereCitizen),
  `did:spize:org/name#fp` (hosted convenience).
  All identities use Ed25519 (or secp256k1 for `did:ethr`) — private keys
  never leave the agent's host.
- **Federated discovery**: resolver chain dispatches by DID method.
  No single registry mediates a transfer. The recipient's well-known
  document or on-chain record is the source of truth.
- **JWS-signed agent cards** ([ADR-0025](docs/decisions/0025-jws-signed-agent-card.md))
  served at `/.well-known/agent-card.json`. Algorithm whitelist is
  hardcoded (`EdDSA`, `ES256K`); `alg=none` and `HS256` are rejected at
  parse time.
- **SSRF-resistant fetcher** ([ADR-0045](docs/decisions/0045-aex-net-safe-http-ssrf.md)):
  every well-known fetch goes through `aex-net::safe_http` which blocks
  loopback, RFC1918, link-local, IPv6 ULA, multicast, and any redirect.
- **Capability negotiation** ([ADR-0043](docs/decisions/0043-capability-negotiation-dual-wire.md)):
  sender and recipient advertise wire versions + feature bits at
  `GET /v2/capabilities`; SDK picks the highest mutually-supported wire
  version per recipient.
- **Brand-neutral canonical bytes**: every signed payload starts with
  `aex-<msg>:v2` (no vendor name in cryptographically signed bytes).
- **Pluggable scanning**: size, MIME magic byte, EICAR, regex prompt-
  injection. Custom scanners plug in via a simple trait.
- **Tamper-evident audit**: every send, scan, accept, ack chained in a
  local Merkle log. Optional Rekor anchoring.
- **Peer-to-peer data plane**: short-lived signed tickets authorize a
  direct fetch from the sender's data plane. The control plane never
  proxies bytes.
- **Open conformance suite** ([ADR-0048](docs/decisions/0048-conformance-suite-apache-2.md)):
  `cargo run -p aex-conformance` runs 22 checks (wire round-trip, JWS
  algorithm whitelist, SSRF resistance, clock-skew handling, capability
  negotiation, ...). Apache-2.0; anyone can self-certify.

---

## Quickstart — three paths

Pick the one that matches your trust model. The protocol is the same in
all three — only the identity-resolution layer changes.

### Path A — Self-certifying offline (`did:key`)

Two agents, no infrastructure, no domain. Best for tests, CI, device-
local agents.

```python
from aex_sdk import Identity
from aex_sdk.identity import IdentityFile

# Each agent generates its own keypair locally.
alice = Identity.generate(method="did:key")
bob   = Identity.generate(method="did:key")

# Alice signs a transfer intent; Bob verifies inline.
# `did:key` carries the public key inside the agent_id itself —
# nothing else to resolve.
```

The full demo (two-agent transfer with EICAR scanning + Merkle audit):

```bash
# Start a local control plane (Postgres needed only for v1 transfer
# state — pure did:key transfers can run with --no-db).
docker compose -f deploy/docker-compose.dev.yml up -d
cargo run -p aex-control-plane

# In a second terminal: install the SDK + run the demo.
cd packages/sdk-python
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
python examples/demo_two_agents.py
```

### Path B — Domain-anchored (`did:web`)

Best for organisations that already own a domain.

1. Generate an Ed25519 keypair locally (`aex-cli init --domain acme.com
   --fragment fatture` — coming with `card publish` subcommand).
2. Publish a JWS-signed agent card at
   `https://acme.com/.well-known/agent-card.json` (see
   [`docs/protocol-v2.md`](docs/protocol-v2.md) §6 for the schema).
3. Tell peers your handle: `did:web:acme.com#fatture`.

Anyone with the handle can:

```bash
$ aex-cli debug resolve did:web:acme.com#fatture
→ parsing handle …
  ✓ scheme dispatch → DidWeb
  ✓ parsed as W3C DID URI: method=web, msi=acme.com, fragment=fatture
→ fetching /.well-known/agent-card.json …
  ✓ DNS resolved, TLS chain OK
  ✓ JWS verified (EdDSA), kid matches agent_id
  ✓ capabilities: [wire-v2, jws-agent-card, card-etag]
→ identity verified                          [234 ms]
```

### Path C — On-chain identity (`did:ethr`)

Best for agents whose trust signal must be publicly verifiable across the
ecosystem — professional services, reputation-anchored agents,
deterministic identity portability.

Identity creation happens via the
[EtereCitizen](https://github.com/icaroholding/EtereCitizen) tooling
(separate project); the resulting `did:ethr:<chain-id>:<address>` is
resolvable by AEX's `DidEthrProvider`.

> **Phase note**: at v2.0-beta the on-chain resolver is an in-memory
> stub; the production Base L2 RPC client lands in Phase 2 (see
> [ADR-0040](docs/decisions/0040-etere-citizen-trust-scoring-first-class.md)).

### Path D — Hosted convenience (`did:spize`)

For consumers and small operators who don't have a domain and don't want
to manage their own keys' visibility on-chain. Spize operates a reference
hosted registry at **spize.io**; identities are `did:spize:org/name#fp`.

This is functionally equivalent to Gmail vs running your own SMTP: same
protocol, less ops.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         CLIENTS                                          │
│  Claude Desktop (MCP)   Spize Desktop   SDK Py/TS   aex-cli              │
└──────────────────────┬─────────────────────────────┬────────────────────┘
                       │                             │
                       ▼                             ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                       IDENTITY RESOLVER (aex-identity)                   │
│   trait IdentityProvider { resolve(handle) → ResolvedAgent }            │
│                                                                          │
│   ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐   │
│   │ SpizeNative  │ │ DidWeb       │ │ DidEthr      │ │ DidKey       │   │
│   │ (registry)   │ │ (.well-known)│ │ (Base L2)    │ │ (inline)     │   │
│   └──────────────┘ └──────────────┘ └──────────────┘ └──────────────┘   │
└──────────────────────┬──────────────────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                    PROTOCOL (aex-core, wire v2)                          │
│   aex-transfer-intent:v2   aex-data-ticket:v2   aex-register:v2          │
│   aex-rotate-key:v2        aex-transfer-receipt:v2                       │
│                                                                          │
│   ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐ ┌────────────┐ │
│   │ Scanner  │  │ Policy   │  │ Audit    │  │ Tunnel   │ │ A2A bridge │ │
│   │ Pipeline │  │ Hooks    │  │ Merkle   │  │ (P2P)    │ │ adapter    │ │
│   └──────────┘  └──────────┘  └──────────┘  └──────────┘ └────────────┘ │
└──────────────────────┬──────────────────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                    TRANSPORT (aex-tunnel)                                │
│   Cloudflare quick │ Iroh QUIC │ Tailscale Funnel │ FRP │ direct HTTPS  │
└─────────────────────────────────────────────────────────────────────────┘
```

- **Control plane** (`aex-control-plane`, BSL-1.1): registry + ticket
  issuance + audit anchor. With M2 P2P enabled, never sees the bytes.
- **Data plane** (`aex-data-plane`, Apache-2.0): sender-side HTTP server
  exposing a blob by signed ticket.
- **SDKs**: `aex-sdk` (Python), `@aexproto/sdk` (TypeScript), plus
  `@aexproto/mcp-server` for LLM hosts (Claude Desktop, Cursor, Cline).
- **CLI**: `aex-cli` for operator-side debugging (handle resolution,
  QR code generation for offline handle sharing).
- **Conformance**: `aex-conformance` standalone binary verifies any
  AEX deployment against the v2 normative spec (Apache-2.0).

Deep dive: [`docs/architecture.md`](docs/architecture.md).
Normative spec: [`docs/protocol-v2.md`](docs/protocol-v2.md) (wire v2);
[`docs/protocol-v1.md`](docs/protocol-v1.md) (legacy, still valid through
the grace window).

---

## Why

Autonomous agents increasingly need to exchange files — PDFs, datasets,
generated reports — across organizations. Today they improvise over Gmail,
Slack, Drive, S3 pre-signed URLs. None of those were designed for agents:

- **No verifiable origin**. A Claude pretending to be a Claude from the
  accounting firm can just lie.
- **Surveillance posture**. Every file passes through a human-oriented
  intermediary with full content visibility.
- **Brittle policy**. Compliance is a per-integration toolkit,
  re-implemented at every company.
- **No audit**. When a legal issue arises, "I swear the file arrived at
  14:32" doesn't hold up.
- **Single-registry lock-in**. Any v1-era design that requires every
  participant to register with the same registry doesn't compose with
  emerging standards (Google A2A v1.0, W3C DID Core, Bluesky AT Protocol,
  GoDaddy/Infoblox ANS).

AEX v2 is the file-transfer layer agents should have had from day one —
multi-issuer identity from the ground up, brand-neutral wire bytes, open
conformance.

---

## Migration v1 → v2

Per [ADR-0043](docs/decisions/0043-capability-negotiation-dual-wire.md):

- Wire v1 (`spize-*:v1` prefix) remains accepted by every control plane
  for **6 months** after v2.0 GA. SDKs and Spize Desktop carry dual-wire
  codecs through the same window.
- The sender adapter chooses per-recipient at send time: it
  `GET /v2/capabilities`, picks the highest mutually-supported wire
  version, signs in that codec.
- Post-sunset, v1 intents receive `426 Upgrade Required` with a `Link`
  header pointing to the migration runbook.
- Legacy `spize:org/name:fingerprint` ids continue to parse inside wire-v2
  payloads during the grace window. New agents should register under
  `did:spize:` (or another DID method).

---

## Repository structure

```
crates/
  aex-core           — shared types, wire v1+v2, capability registry, errors
  aex-identity       — SpizeNative, EtereCitizen, did:web, did:key providers
                       + ResolverChain (cache + single-flight)
  aex-jws            — JWS sign/verify (EdDSA + ES256K only; hardcoded
                       algorithm whitelist)
  aex-net            — DoH resolver + safe_http (SSRF-resistant) + retry
                       + captive portal detection
  aex-audit          — local Merkle chain + optional Rekor anchor
  aex-scanner        — size / MIME / EICAR / regex pipeline
  aex-policy         — pre-send and post-scan policy traits
  aex-tunnel         — Cloudflare / Iroh / Tailscale / FRP orchestration
  aex-control-plane  — registry + ticket issuer + audit anchor (BSL-1.1)
                       v2 routes: /v2/capabilities (live), /v2/intents
                       (stub at v2.0-beta — full handler in next sprint),
                       /.well-known/agent-card.json
  aex-data-plane     — peer-to-peer blob server
  aex-cli            — operator CLI (debug resolve, qr codes)
  aex-conformance    — open conformance suite (Apache-2.0 binary)
  aex-a2a-bridge     — A2A v1.0 ↔ AEX transfer-intent translation
  aex-billing        — billing provider trait (skeleton)
packages/
  sdk-python         — aex-sdk on PyPI; wire v1 + v2
  sdk-typescript     — @aexproto/sdk on npm; wire v1 + v2
  mcp-server         — @aexproto/mcp-server on npm (Claude Desktop /
                       Cursor / Cline). Tools: aex_init, aex_whoami,
                       aex_send, aex_inbox, aex_download, aex_ack
                       (+ legacy spize_* aliases through grace window)
web/                 — landing + operator dashboard + download UI
deploy/              — docker-compose for local dev; production deploy
                       recipes planned
docs/                — architecture, protocol-v1 / protocol-v2, ADRs,
                       runbooks
```

---

## Conformance

```
$ cargo run -p aex-conformance
# wire
  ✓ wire-v2-roundtrip
  ✓ wire-v1-still-functional
  ✓ cross-version-isolation
# jws
  ✓ jws-algorithm-whitelist
  ✓ jws-alg-none-rejected
  ✓ jws-alg-hs256-rejected
  ✓ jws-tampered-payload-rejected
# ssrf
  ✓ ssrf-rejects-loopback
  ✓ ssrf-rejects-rfc1918
  ✓ ssrf-rejects-link-local
  ✓ ssrf-accepts-public-ips
# time
  ✓ clock-skew-60s-window
  ✓ clock-skew-rejects-outside-window
# identity
  ✓ did-uri-parser-strict
  ✓ did-key-roundtrip
  ✓ did-key-rejects-malformed
# capability
  ✓ capability-bits-stable
  ✓ capability-forward-compat
# wire
  ✓ wire-v2-rejects-nonce-too-short
  ✓ wire-v2-rejects-newline-in-fields
  ✓ wire-v2-rotate-key-same-keys-rejected
  ✓ wire-v2-receipt-action-whitelist

ALL PASSED — 22 tests
You can claim AEX v2 compliance.
```

Run against your own deployment to verify it speaks the protocol
correctly. CI integration: exit code 0 on pass, 1 on any failure;
JSON report via `--report-json <path>`.

---

## Contributing

We use the [Developer Certificate of Origin](https://developercertificate.org)
for contributions. Sign your commits with `git commit -s`.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the dev loop, test
requirements, and code style. The full set of architectural decisions
lives under [`docs/decisions/`](docs/decisions/) — read those before
proposing structural changes.

For security reports, see [SECURITY.md](SECURITY.md).

---

## Licensing

- Protocol specs, all crates except one, all SDKs, conformance suite,
  and the web code: **Apache License 2.0** — [`LICENSE`](LICENSE).
- `aex-control-plane`: **Business Source License 1.1** —
  [`LICENSE.bsl`](LICENSE.bsl). Converts to Apache-2.0 on **2029-04-20**
  per [ADR-0009](docs/decisions/0009-bsl-to-apache-conversion-q4.md).

The BSL grant allows any production use except offering
`aex-control-plane` as a hosted service competing with Spize's offering.
For anything else — internal deployment, self-hosting, modification,
derivative work — there is no restriction.

---

## Related projects

- [EtereCitizen](https://github.com/icaroholding/EtereCitizen) — the
  on-chain identity provider AEX consumes via `aex-identity::DidEthrProvider`.
- [Spize Desktop](https://github.com/icaroholding/aex-desktop) (private)
  — the user-facing app that wraps the SDK and the MCP server.
- [Spize Enterprise](https://github.com/icaroholding/aex-enterprise)
  (private) — the commercial overlay on `aex-control-plane`.

---

Built by [Icaro Holding](https://icaro.ai).
