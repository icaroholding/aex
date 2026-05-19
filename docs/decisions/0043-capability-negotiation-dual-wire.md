# ADR-0043: Capability negotiation across v1↔v2; 6-month dual-wire grace

## Status

Accepted 2026-05-19. Extends the rollout pattern from ADR-0036 to the
v1→v2 transition.

## Context

ADR-0042 makes v2 a breaking change of the wire prefix (`spize-*:v1` →
`aex-*:v2`). Any v1 client talking to a v2-only control plane (or vice
versa) fails crypto-verification with no recovery. ADR-0036 already proved
the dual-wire approach for `v1.3.0-beta.1`: ship a temporary parser that
accepts both formats, advertise capability bits, sunset after 30 days.

The v1→v2 transition is larger in blast radius — every SDK, every control
plane, every desktop install needs to migrate — so the grace window
extends, but the mechanism is identical.

## Decision

1. **Capability advertisement.** Each control plane exposes
   `GET /v2/capabilities` returning a JSON document of the form
   `{"wire_versions": ["v1", "v2"], "capabilities": [...]}`. The
   `capabilities` array contains stable string names from
   `aex-core::Capability` (ADR-0018 capability bit pattern).

2. **Sender adapter selects the wire version**. Before sending a transfer
   intent to a recipient, the sending client GETs
   `/v2/capabilities` on the recipient's control plane and chooses the
   highest mutually-supported wire version. v2 if both advertise it; v1
   otherwise. Explicit, no probing-by-failing.

3. **Recipient-side dual parser**. Every control plane during the grace
   window verifies incoming intents using either wire codec:
   - Inspect the first line (`spize-transfer-intent:v1` vs
     `aex-transfer-intent:v2`).
   - Dispatch to the matching verifier.
   This is implemented as `routes::v2_router` for v2 endpoints, merged
   alongside the existing v1 routes. Both stay live until sunset.

4. **Grace window.** Six months from v2 GA. Counted from the `2.0.0-beta.1`
   tag push; the CHANGELOG calls out the exact sunset date prominently.
   Day-after sunset, any v1-format intent receives `426 Upgrade Required`
   with a `Link` header pointing to the migration runbook.

5. **Clients ship dual-wire too.** SDKs (Python, TypeScript) and the
   desktop carry both codecs for the duration of the grace window; they
   choose per-recipient at send time, not globally.

## Consequences

- Existing v1 users get six months to migrate. No hard cliff.
- Dual-parsing complexity lives in `aex-control-plane` for six months,
  then is deleted in the GA+6m sunset commit; ADR-0036 documents the
  exact delete-recipe.
- The capability negotiation introduces one extra round-trip per recipient,
  per session. Cached by the resolver chain (ADR-0046).
- `aex_wire_v1_legacy_transfers_total` Prometheus counter tracks remaining
  v1 traffic; the sunset alert (ADR-0035 P2) fires if v1 share is > 20%
  one week before the sunset date.
- Post-sunset, the v1 codec stays in a branch `legacy/wire-v1` for audit
  replay, but is removed from `main`.
