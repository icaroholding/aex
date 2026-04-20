# Spize Architecture

**Status:** Living document — last updated 2026-04-20.
**Scope:** Covers both Spize (human file delivery, v1 WIP) and Agent Exchange Protocol (AEX, the agentic track starting 2026-04-19).

---

## Product vision

Spize is **the default file transfer channel in a world where AI agents are everywhere**.

Three transfer modes coexist and compose:

1. **Human ↔ Human** — the current Spize v1 product. Desktop app, Cloudflare tunnel, share link, download page. Works today.
2. **Agent ↔ Human** — bridge mode. An AI agent (running anywhere) sends a file to a human recipient. The sender's identity is cryptographically verified, the file is scanned, policies apply. The *recipient* sees exactly the same Spize download page they'd see from a human sender — no account required.
3. **Agent ↔ Agent** — full AEX. Both sides have Spize identities (or DIDs via EtereCitizen). Cryptographic verification both ends, signed receipts, tamper-evident audit, optional reputation layer.

The product handles all three transparently. A sender doesn't need to know whether the recipient is an agent or a human — Spize figures out the right delivery channel from the address format.

---

## The critical distinction: **identity** vs. **logic**

"Agent" is a loaded word. We split it into two orthogonal concepts:

### Agent identity
A cryptographic keypair plus a registered name (`spize:studio-rossi/desktop:a4f8b2`) that can sign outgoing messages and receive incoming transfers addressed to it. **Spize creates and manages this.**

### Agent logic
Whoever (or whatever) decides what to do with incoming files. Could be:
- A human clicking "Accept" in the desktop app
- Claude/GPT/Cursor driving the identity via the MCP server
- A Python script running on a server

**Spize does not create this.** The user brings their own driver.

One identity can be driven by different logics over time, or by multiple logics simultaneously (user + Claude). The identity is the stable addressable thing; the logic is how the user chooses to handle activity on that identity.

---

## Three adoption levels for a Spize user

| Level | Install | Can send | Can receive | Logic driver |
|-------|---------|----------|-------------|--------------|
| **0 — Non-user** | Nothing | — | Via email link (bridge from agent senders) | None — recipient never has Spize |
| **1 — Identity-only** | Spize Desktop (current app) + identity wizard | Human flow (link) + agent flow (to any recipient) | Both human (via link) and agent (via in-app inbox) | **Human** (manual accept in app) |
| **2 — AI-driven** | Spize Desktop + MCP server in Claude/Cursor/etc. | Same as L1, but orchestrated by LLM | Same as L1, but LLM can auto-process incoming | **Human + LLM** |

Progression from 0 → 1 → 2 is incremental and optional. Every install creates the identity (`SpizeNativeProvider::generate`), registration is opt-in during first-run wizard, AI driver is a later choice. The identity becomes the substrate that everything else builds on without the user having to re-onboard.

---

## Recipient address resolution (routing)

When a sender calls `agent.send(file, to=X)`, the `X` can take several forms. Spize routes based on format:

| Format | Example | Route |
|--------|---------|-------|
| Spize native agent_id | `spize:studio-rossi/desktop:a4f8b2` | **Agent↔Agent** full AEX |
| DID (any method) | `did:ethr:0x14a34:0xabc...`, `did:web:studio-rossi.it:agents:desktop` | **Agent↔Agent** via identity provider |
| Email | `rossi@studiolegalerossi.it` | **Agent↔Human** bridge (link + email) |
| Phone | `+39 333 1234567` | **Agent↔Human** bridge (link + SMS) — Phase 2 |
| Bare handle | `@rossi` | Discovery: DNS SRV / well-known lookup / fallback to human bridge |

The routing layer lives in the control plane. SDKs pass the `to` field opaquely; the control plane decides the mode and provisions accordingly.

---

## System architecture (target state, 12-month horizon)

```
┌────────────────────────────────────────────────────────────────────┐
│                           CLIENTS                                  │
│                                                                    │
│   Spize Desktop App        Python SDK       TypeScript SDK         │
│   (Tauri, end users)       (agents)         (agents)               │
│        │                        │                │                 │
│        └──── Tauri IPC          │                │                 │
│        │    (local use)         │                │                 │
│        │                        ▼                ▼                 │
│        │                  MCP Server                               │
│        │                  (Claude Desktop, Cursor, etc.)           │
│        │                        │                                  │
│        └────────────┬───────────┘                                  │
└─────────────────────┼──────────────────────────────────────────────┘
                      │ HTTP/2 + mTLS + agent signatures
                      ▼
┌────────────────────────────────────────────────────────────────────┐
│                      CONTROL PLANE (SaaS)                          │
│                                                                    │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌─────────────┐│
│  │   Identity   │ │    Policy    │ │   Scanner    │ │   Audit     ││
│  │   Resolver   │ │    Engine    │ │ Orchestrator │ │   Ledger    ││
│  │              │ │              │ │              │ │             ││
│  │ • SpizeNative│ │ Cedar DSL    │ │ Firecracker  │ │ Postgres +  ││
│  │ • EtereCitz. │ │ per-org pack │ │ VM pool      │ │ Sigstore    ││
│  │ • DID-web    │ │              │ │              │ │ Rekor       ││
│  └──────────────┘ └──────────────┘ └──────────────┘ └─────────────┘│
│                                                                    │
│  Routing + Tunnel orchestration + Storage (Postgres + Redis)       │
└────────────────────────────────────────────────────────────────────┘
                      │ (tickets, verdicts, coordination)
                      ▼
┌────────────────────────────────────────────────────────────────────┐
│                 DATA PLANE (stateless, Cloudflare)                 │
│                                                                    │
│   Sender ─▶ Scanner Sandbox ─▶ Recipient                           │
│   (bytes never touch Spize servers — privacy + scale)              │
└────────────────────────────────────────────────────────────────────┘
```

### Principles

- **Control plane coordinates; data plane transfers.** File bytes never hit Spize-owned servers. They flow through Cloudflare tunnels to per-transfer Firecracker sandboxes (for scanning) and then to the recipient. This is the same separation as Stripe (API) vs card networks (money).
- **Provider pattern everywhere.** Identity, scanner, policy, audit, tunnel — each is a trait with multiple implementations. Third-party plug-ins are possible long-term.
- **Stateless data plane, stateful control plane.** Horizontal scaling follows.
- **Audit is source of truth.** Everything important is an event in the ledger. Full event sourcing at the business layer.

---

## Security model

### Identity (what the code in `crates/aex-identity` provides)

- Ed25519 keypair per agent, generated locally, private key never leaves the device
- Agent ID is *derived* from the public key: `spize:{org}/{name}:{fingerprint}` where fingerprint is the first 6 hex chars of SHA-256 over the pubkey
- Registration publishes only the public key, signed by the org's root key (3-level chain: Spize root → Org root → Agent)
- Revocation via signed entries in a CRL-style log
- DID schemes are delegated to specialized providers (EtereCitizen for `did:ethr`, future `did:web` for self-hosted)

### Authorization (Cedar policy engine)

- Policies are Cedar files deployed per org, signed by org root
- Evaluated server-side before and after scanning
- Policies can reference: agent identities, verification levels, reputation scores (if provider supports), file metadata, quotas, time, destination

### Content inspection (scanner pipeline)

- Cascade of scanners running in parallel inside per-transfer Firecracker VMs
- MVP scanners (Phase 1): file-magic MIME verify, size limit, YARA (EICAR + basic malware rules), regex-based prompt-injection detection
- Phase 2 scanners: Presidio (PII), TruffleHog (secrets), fine-tuned prompt-injection classifier, custom org-specific rules
- Verdicts are signed, stored, and inform the post-scan policy decision
- Sandbox is destroyed after each transfer; bytes never persist

### Audit (tamper-evident ledger)

- Every event (send_attempt, policy_result, scanner_verdict, delivery, receipt, revoke) is a signed JSON entry
- Entries batched into a local Merkle tree
- Root hashes submitted to [Sigstore Rekor](https://docs.sigstore.dev/logging/overview/) transparency log every 60s
- Consequence: Spize itself cannot rewrite history without public detection

---

## Current state (what exists in this repo as of 2026-04-20)

### Already built (v1 human track)
- Tauri desktop app: `src/` (React) + `src-tauri/` (Rust)
- HTTP streaming server, Cloudflare quick-tunnel integration
- SQLite share/access_log/session database
- Token-based share links, bcrypt password protection
- Security hardening completed 2026-04-15 (commit `feb0135`): symlink traversal, rate limiting, session TTL, URL injection, header injection fixes
- Next.js landing page under `web/`

### Built (AEX foundation + M1/M2 scaffold, 2026-04-20)

**Rust workspace (`crates/`):**
- `aex-core` — shared types + errors + canonical wire formats for registration, transfer intent, transfer receipts, data-plane tickets.
- `aex-identity` — `SpizeNativeProvider` (Ed25519) + `EtereCitizenProvider` (did:ethr + ECDSA secp256k1) behind a common `IdentityProvider` trait.
- `aex-audit` — hash-chained append-only event log with `MemoryAuditLog` + `FileAuditLog` + `RekorAnchoredAuditLog<Inner>` wrapper for Sigstore anchoring.
- `aex-scanner` — parallel pipeline running size-limit + magic-bytes + EICAR + regex prompt-injection scanners.
- `aex-policy` — `PolicyEngine` trait + `TierPolicy` (FreeHuman / Dev / Enterprise).
- `aex-tunnel` — Cloudflare quick-tunnel wrapper + `StubTunnel`, extracted from `src-tauri/`.
- `aex-billing` — `BillingProvider` trait + `InMemoryBilling` + Stripe skeleton.
- `aex-control-plane` — axum server with:
  - `GET /healthz`, `GET /v1/public-key`
  - `POST /v1/agents/register`, `GET /v1/agents/*agent_id`
  - `POST /v1/transfers` (initiate + upload + scan + policy + audit in one round-trip), `GET /v1/transfers/:id`, `POST /v1/transfers/:id/download`, `POST /v1/transfers/:id/ack`
  - `POST /v1/inbox`
  - Postgres schema: `agents`, `registration_nonces`, `transfers`, `transfer_intent_nonces`
  - `ControlPlaneSigner` for future data-plane tickets (D2 seed)

**Packages (`packages/`):**
- `sdk-python` — `spize` pip package: `Identity`, `SpizeClient`, canonical wire helpers. 19 tests (cross-language vectors).
- `sdk-typescript` — `@aex/sdk` npm package: same API surface, Node 18+/Bun. 13 tests.
- `mcp-server` — `@aex/mcp-server` stdio MCP server exposing `spize_whoami`, `spize_init`, `spize_send`, `spize_inbox`, `spize_download`, `spize_ack` to Claude Desktop / Cursor.

**Desktop (`src-tauri/`):**
- Extended Tauri app with an "Agent" tab: identity wizard, control-plane registration, inbox listing. 0600-perm identity file under `$CONFIG/Spize/`.

**Web (`web/`):**
- `/dashboard` — operator read-only view (health + placeholders for admin cards).
- `/waitlist` — alpha signup form with Supabase-backed `/api/waitlist`.

**Deploy (`deploy/`):**
- `docker-compose.dev.yml` — Postgres 16 for dev + integration tests.

**Demo verified end-to-end 2026-04-20:** Alice registers → sends clean file to Bob → Bob downloads + acks (chain head returned). Alice sends EICAR → scanner_malicious, delivery blocked, blob never persisted.

### Not yet built (next push)

- Live data-plane server (currently bytes still flow through the control plane). D2 wire format and signing infra already shipped; the stateless data-plane binary is the last piece.
- Cedar DSL binding inside `aex-policy` (trait is ready).
- Live Rekor submission (stub + wrapper shipped; needs the actual rekord schema HTTP client).
- Live Stripe HTTP calls (skeleton shipped; needs dashboard config).
- Desktop download + ack actions in the Agent panel (listing works; interactive operations are next).
- Admin REST endpoints that back the dashboard cards (agents list, transfers list, audit read view).

---

## Roadmap milestones

| Milestone | ETA (relative) | What's demoable |
|-----------|----------------|------------------|
| M1 — Hello World | ~Week 4 | Two local Python scripts exchange a file via control plane. Scanner blocks EICAR. Audit log (local). |
| M2 — Cross-network | ~Week 8 | Same as M1 but across the internet via Cloudflare. Desktop app has identity wizard + Agent Inbox. |
| M3 — EtereCitizen bridge | ~Week 12 | Agent with `did:ethr` can transfer to/from Spize native. Cross-identity works. |
| M4 — Compliance-grade | ~Week 16 | Rekor-backed audit. Policy packs for GDPR/SOC2 starters. Dashboard alpha. |
| M5 — Alpha launch | ~Week 20 | Invite-only 500 devs. Public landing. Feedback loop active. |

Each milestone assumes founder full-time on AEX + Claude pair-programming. Calendar time may stretch if part-time.

---

## Related project: EtereCitizen

[github.com/icaroholding/EtereCitizen](https://github.com/icaroholding/EtereCitizen) — same founder, open protocol for AI agent identity/trust/commerce. W3C DIDs + Verifiable Credentials + Base L2 reputation + x402 payments.

Integrates with Spize as a **first-class identity provider** via the pluggable `IdentityProvider` trait. Not a hard dependency — Spize works without EtereCitizen (SpizeNative is the default), EtereCitizen works without Spize (it's a general identity protocol). The two compose when both are present:

- EtereCitizen supplies verified identity + on-chain reputation + optional x402 payments
- Spize supplies transport + scanner + policy + audit

Strategic posture: two distinct products, marketed separately, deeply interoperable. See the conversation log 2026-04-19 for the architectural decision record.

---

## Open questions (to resolve before GA)

Tracked properly in `TODOS.md` once that file is created. Current open items:

- Decompression bomb limits in scanner sandbox
- Tunnel fallback strategy (multi-provider beyond Cloudflare)
- Log sanitization to prevent downstream prompt injection
- Store-and-forward design for offline recipients
- Audit sign failure policy (fail-open dev tier, fail-closed enterprise — committed but needs tier-detection logic)
- Spize root key ceremony documentation
- Runbook library for 7 critical incident types
- Scanner adversarial evaluation suite
- Supabase → Identity Registry migration plan
- Multi-provider Base RPC with circuit breaker (for EtereCitizen)
- SBOM generation + Sigstore signing of SDK releases
- Cost model for 100× scale
