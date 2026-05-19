# ADR-0042: Wire v2 — brand-neutral `aex-*:v2` prefix; sender carries its own namespace

## Status

Accepted 2026-05-19. Supersedes ADR-0018 (wire-v2 RFC moved from Q1 2027 to
Q3 2026).

## Context

ADR-0018 froze wire v1 after `v1.3.0-beta.1` and deferred a formal v2 to
"Phase 6, Q1 2027 late". Two events compress that timeline:

1. **External standards convergence (2026 Q1–Q2)**. Google A2A v1.0 ships
   production-grade in early 2026. NIST launches its AI Agent Standards
   Initiative in February. GoDaddy and Infoblox announce ANS (Agent Name
   Service) on 2026-05-14 — five days before this ADR. By Q1 2027 the
   landscape will already have consolidated around `did:web`-style
   identifiers and `/.well-known/agent-card.json` discovery. Waiting that
   long forfeits AEX's chance to be cited inside that converged stack.

2. **Brand embedded in cryptographic bytes**. Every v1 signed payload starts
   with `spize-<msg>:v1` (e.g. `spize-transfer-intent:v1`). The string
   `spize-` is part of the byte sequence that gets signed and verified —
   any third party adopting AEX has to embed the Spize brand in its own
   signed traffic. That is not how a credible interop protocol behaves.

## Decision

Wire v2 changes two things versus v1:

1. **Prefix is brand-neutral.** Every canonical message in v2 starts with
   `aex-<msg>:v2`:
   - `aex-register:v2`
   - `aex-transfer-intent:v2`
   - `aex-data-ticket:v2`
   - `aex-rotate-key:v2`
   - `aex-transfer-receipt:v2`

2. **AgentId values inside the payload are W3C DID URIs (ADR-0041).** During
   the v1→v2 grace window (ADR-0043), the v2 codec also accepts legacy
   `spize:org/name:fingerprint` strings at the parse layer so that an
   organization mid-migration can sign a v2 intent on behalf of a v1
   identity without re-registering.

The byte-level framing — line-based, LF terminator, no trailing LF,
ASCII-only fields — is unchanged from v1. Signers and verifiers only need
to swap the bytes-producing function (`wire::*_bytes` → `wire_v2::*_bytes_v2`).

## Consequences

- AEX becomes adoptable by third parties without embedding a vendor brand
  in their signed traffic.
- v1 and v2 wire payloads are byte-distinguishable from the first character;
  any verifier that picks the wrong codec rejects the signature, which is
  exactly the failure mode we want.
- The wire-v2 sunset of v1 follows ADR-0043: 6-month dual-wire grace,
  hard-stop at 426 Upgrade Required.
- The clock-skew window tightens from v1's 300 s to v2's 60 s (ADR-0044).
- Spize remains the reference hosted control plane; what was
  `spize:org/name:fp` becomes `did:spize:org/name#fp` in v2 — same trust
  root, W3C-compliant shape (ADR-0041).
- Anchored on workspace `1.3.0-beta.4`; the `1.x` line continues until v2
  GA, after which the workspace bumps to `2.0.0-beta.1`.
