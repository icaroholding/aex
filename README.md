# AEX — Agent Exchange Protocol

[![CI](https://github.com/icaroholding/spize/actions/workflows/ci.yml/badge.svg)](https://github.com/icaroholding/spize/actions)
[![crates.io](https://img.shields.io/crates/v/aex-core.svg)](https://crates.io/crates/aex-core)
[![npm](https://img.shields.io/npm/v/@aex/sdk.svg)](https://www.npmjs.com/package/@aex/sdk)
[![PyPI](https://img.shields.io/pypi/v/aex-sdk.svg)](https://pypi.org/project/aex-sdk/)
[![License](https://img.shields.io/badge/license-Apache--2.0%20%2B%20BSL--1.1-blue.svg)](#licensing)

**The open protocol for agent-to-agent file transfer.** Cryptographic identity, pluggable scanning, signed audit, pluggable policy. Files travel peer-to-peer — bytes never touch our servers.

AEX is the **Agent Exchange Protocol**. Spize is the company that authors the protocol and operates the reference hosted registry at [spize.ai](https://spize.ai).

## What AEX gives an agent

- **Verifiable identity.** Every transfer is signed with the sender's Ed25519 key. Recipients cryptographically verify origin before accepting bytes.
- **Routing without coordination.** `@bob.studio-rossi` resolves to a crypto-anchored agent ID. Senders don't need to know where Bob's agent runs.
- **Mandatory scanning.** Files flow through a pluggable pipeline (size, MIME, YARA, regex, Firecracker sandbox) before reaching the recipient.
- **Org-wide policy.** Pre-send and post-scan policies are enforced by the protocol, not per-app. Block by MIME, size, recipient class, anything.
- **Tamper-evident audit.** Every send, scan, accept, and ack is chained in a local Merkle log, optionally anchored to Rekor.
- **Peer-to-peer data plane.** The control plane signs a 60-second ticket. Bytes stream through a Cloudflare tunnel from sender → recipient.

## Quick start — two Python agents exchange a file (3 minutes)

```bash
# 1. Start a local control plane
docker compose -f deploy/docker-compose.dev.yml up -d
DATABASE_URL=postgres://aex:aex_dev@localhost:5432/aex \
  cargo run -p aex-control-plane

# 2. Install the Python SDK and run the demo
pip install aex-sdk
python -m aex_sdk.examples.two_agents
```

The demo:
1. Generates two identities (Alice and Bob), registers them with proof-of-possession.
2. Alice signs an intent and sends a clean file → scanner passes → Bob downloads and acks.
3. Alice tries to send EICAR → scanner blocks → transfer rejected → audit chain records the rejection.

Full walkthrough: [`docs/getting-started.md`](docs/getting-started.md).

## Architecture

```
┌──────────────┐        control plane         ┌──────────────┐
│  Agent A     │  ─── register, intent  ──►   │ aex-control- │
│  (Alice)     │  ◄── ticket, audit head ──   │    plane     │
└──────┬───────┘                              └──────┬───────┘
       │                                             │
       │       tunnel handshake + ticket             │
       ▼                                             ▼
┌──────────────┐        data plane          ┌──────────────┐
│  aex-data-   │  ─────── blob ──────────►  │  Agent B     │
│  plane       │                            │  (Bob)       │
│  (on Alice)  │  ◄─ signed receipt ──────  │              │
└──────────────┘                            └──────────────┘
```

- **Control plane** (`aex-control-plane`, BSL-1.1): registry + ticket issuance + audit. Metadata only — never sees the bytes.
- **Data plane** (`aex-data-plane`, Apache-2.0): sender-side HTTP server exposing a blob by signed ticket. Cloudflare tunnel for NAT traversal.
- **SDKs** (`aex-sdk` Python, `@aex/sdk` TypeScript, `@aex/mcp-server` for LLM hosts): wrap the wire format + tunnel handshake.

Deep dive: [`docs/architecture.md`](docs/architecture.md). Wire format spec: [`docs/protocol-v1.md`](docs/protocol-v1.md).

## Why

Autonomous agents increasingly need to exchange files — PDFs, datasets, generated reports — across organizations. Today they improvise over Gmail, Slack, Drive, S3 pre-signed URLs. None of those were designed for agents:

- **No verifiable origin.** A Claude pretending to be a Claude from the accounting firm can just lie.
- **Surveillance posture.** Every file passes through a human-oriented intermediary with full content visibility.
- **Brittle policy.** Compliance is a per-integration toolkit, re-implemented at every company.
- **No audit.** When a legal issue arises, "I swear the file arrived at 14:32" doesn't hold up.

AEX is the file-transfer layer agents should have had from day one. Stripe standardized payment APIs; AEX standardizes agentic file exchange.

## Self-host vs hosted (spize.ai)

| | Hosted at **spize.ai** | Self-hosted |
|---|---|---|
| Setup time | 2 minutes | 2–4 hours |
| Handle | `@name.spize.ai` | `@name.your-domain.com` |
| Free tier | 100 transfers/mo, 10 MB max | Unlimited — you decide |
| Metadata visibility | Spize + you | You only |
| Scanner rules | Shared global ruleset | Your rules |
| SOC2 / HIPAA | Included | Your responsibility |
| Cost to start | $0 | $10–50/mo server |

The protocol reference implementation (`aex-control-plane`) is BSL-1.1 licensed — you may run it in production for internal use; you may not resell it as a competing hosted service until the BSL-to-Apache conversion date (2029-04-20).

## Repository structure

```
crates/
  aex-core          — shared types, wire formats, errors
  aex-identity      — Ed25519 + EtereCitizen DID provider
  aex-audit         — local Merkle chain + optional Rekor anchor
  aex-scanner       — size / MIME / YARA / regex pipeline
  aex-policy        — pre-send and post-scan policy traits
  aex-tunnel        — Cloudflare tunnel orchestration
  aex-billing       — billing provider trait (skeleton)
  aex-data-plane    — peer-to-peer blob server
  aex-control-plane — registry + ticket issuer + audit anchor (BSL-1.1)
packages/
  sdk-python        — aex-sdk on PyPI
  sdk-typescript    — @aex/sdk on npm
  mcp-server        — @aex/mcp-server on npm (Claude Desktop / Cursor integration)
web/                — landing + operator dashboard + download UI
deploy/             — docker-compose + (future) Fly.io / Render deploys
docs/               — architecture, protocol spec, getting started, self-host
```

## Contributing

We use the [Developer Certificate of Origin](https://developercertificate.org) for contributions. Sign your commits with `git commit -s`.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the dev loop, test requirements, and code style.

For security reports, see [SECURITY.md](SECURITY.md).

## Licensing

- The protocol, specs, all crates except one, all SDKs, and the web code: **Apache License 2.0** — [`LICENSE`](LICENSE).
- `aex-control-plane`: **Business Source License 1.1** — [`LICENSE.bsl`](LICENSE.bsl). Converts to Apache-2.0 on **2029-04-20**.

The BSL grant allows internal production use and non-competitive derivative work. What it prevents: standing up a commercial hosted AEX registry that competes with spize.ai. This is the same pattern used by MongoDB, Sentry, and CockroachDB.

## Related projects

- [EtereCitizen](https://github.com/icaroholding/EtereCitizen) — the DID-based identity provider AEX consumes via `aex-identity`.
- [Spize Desktop](https://github.com/icaroholding/spize-desktop) (private) — the Tauri consumer app.

---

Built by [Icaro Holding](https://icaro.ai). The Spize company bets on AEX becoming the HTTP of agent interoperability.
