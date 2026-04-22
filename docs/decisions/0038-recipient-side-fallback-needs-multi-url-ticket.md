# ADR-0038: Recipient-side transport fallback requires multi-URL tickets (deferred)

## Status

Deferred 2026-04-21 — noted in Sprint 2 PR C review, implementation postponed to a later PR (likely E1 alongside key rotation).

## Context

Sprint 2 PR C landed sender-side transport plurality (`send_via_transports` / `sendViaTransports`) and control-plane validation of `reachable_at[]`. The recipient SDK, however, currently fetches over a single URL — the `data_plane_url` the control plane bakes into the signed data-ticket (`aex_core::wire::data_ticket_bytes` canonicalises `data_plane=<URL>` as part of the Ed25519-signed payload).

A first pass at recipient-side fallback (`fetch_via_transports` in Python, `fetchViaTransports` in TypeScript) substituted each candidate endpoint's URL into the ticket before dialing. That is wrong: the data plane verifies the ticket signature against the `data_plane_url` it receives, so any attempt against a URL other than the one signed fails with `Unauthorized`. The fallback was structurally broken — only the first endpoint (identical to `ticket.data_plane_url`) could ever succeed.

## Decision

Remove the broken fallback methods from the recipient SDK. Ship PR C with:

- Sender-side: `send_via_transports` / `sendViaTransports` (works).
- Recipient-side: unchanged — `request_ticket` + `fetch_from_tunnel` using the single `legacy_tunnel_url` the CP selected (first HTTPS-scheme healthy endpoint).

Resilience comes from the validation step at `create_transfer`: unhealthy endpoints are dropped before the recipient ever sees the transfer. A live failure *after* validation still fails the transfer — we'll address that with a follow-up.

## Follow-up options

Pick one in a later PR:

1. **Multi-URL ticket.** Extend `data_ticket_bytes` to canonicalise an ordered list of URLs (`data_plane[0]=…\ndata_plane[1]=…`). One signature covers the whole list; the recipient can try each URL in order. Requires a wire bump (slot into `v1.3.0-beta.1`). Simplest.
2. **Per-endpoint ticket issuance.** `request_ticket(transfer_id, target_url)` — recipient requests one ticket per endpoint on demand. No wire change; costs a control-plane round-trip per fallback attempt and doubles the nonce-consumption rate.
3. **Ticket audience = transfer_id only.** Drop `data_plane_url` from the canonical bytes entirely. Simplest wire-wise but weakens the ticket — a compromised data plane could accept tickets intended for a sibling URL. Probably not acceptable.

Option 1 is the current favourite; document the chosen approach in a new ADR when we implement it.

## Consequences

- PR C ships without true recipient-side fallback. A sender with `reachable_at = [A, B, C]` effectively only serves via A (the first HTTPS-scheme healthy endpoint) from the recipient's perspective.
- The sender-side `reachable_at[]` infrastructure is still load-bearing: it gates ingestion on at-least-1-healthy, drops dead entries, and persists the full array in the DB. The follow-up just needs to wire the ticket and SDK to use the stored list.
- `try_endpoints` / `tryEndpoints` helpers stay in the SDKs — they're reusable for the eventual fallback implementation.
