# TODOS

Work explicitly deferred during plan reviews. Each entry includes enough context
that someone picking it up 3 months later can act without re-discovering the why.

---

## Sprint 2 retrospective items

### Evaluate `SubprocessTunnelBase` extraction

**What.** After Sprint 2 ships IrohTunnel + NamedCloudflareTunnel +
TailscaleFunnelTunnel + FrpTunnel, look at Quick / Named / Tailscale /
FRP and check whether they share >60% of their `start()` / `stop()`
LOC. If yes, extract `SubprocessTunnelBase` holding the common
"spawn → parse stdout for URL → Drop kills process" shape.

**Why.** Sprint 2 plan-eng-review (2026-04-21) deferred this extraction
under YAGNI — writing it up front before three concrete impls existed
would have been premature. The right time is the Sprint 2 `/retro`,
when we can compare real code side-by-side.

**Pros.** Likely removes a few hundred LOC of duplicated subprocess /
signal / stdout handling. DRY win proportional to the overlap.

**Cons.** Abstraction is trap-laden — every shared line that makes sense
in 2 tunnels can become a forced fit in the 3rd. If overlap is <60 %,
don't extract.

**Depends on.** Sprint 2 tasks 2, 3, 4, 5 landed. Review during
`/retro` at Sprint 2 end.

**Where to start.** Diff `crates/aex-tunnel/src/cloudflare.rs` against
`named_cloudflare.rs` and `tailscale.rs`. If the `start()` bodies are
mostly the same up to a config struct and a regex, extract.

---

## Sprint 2 — aex-net follow-ups

### Extract `verify_tunnel_reachable` into `aex-net::dns::wait_for_host_reachable`

**What.** Move the 80-LOC DNS+TCP readiness wait from
`crates/aex-data-plane/src/main.rs:222-301` into a reusable
`aex_net::dns::wait_for_host_reachable(host, port, timeout)` helper.

**Why.** Sprint 1.5 plan-eng-review (2026-04-21, Section C decision) kept the
function in-place because there was only one caller and the
"this binary owns readiness" locality argument was strong. Sprint 2 introduces
IrohTunnel / NamedCloudflareTunnel / TailscaleFunnelTunnel / FrpTunnel — each
with its own readiness probe. Without extraction, the 80-LOC block will be
duplicated 3+ times and the Sprint 1 edge-case fixes
(`b080d41` search-domain suffix, `a95334d` NXDOMAIN cache, `7daf2a6` widened
retries) will need to be re-rediscovered every time.

**Pros.** DRY across 4+ callers. Single source of DNS resolver configuration.
Reduces drift between tunnel implementations.

**Cons.** Weakens the locality narrative of the data-plane binary. Adds one
trivial cross-dep.

**Depends on.** Sprint 2 task 2 (IrohTunnel) landing in `crates/aex-tunnel/`.
The new tunnel impl is the second caller that triggers extraction.

**Where to start.** Open `aex-data-plane/src/main.rs:222`, read the existing
function + the 4 Sprint 1 commit messages (b080d41, a95334d, 7daf2a6,
ae159df). Port verbatim into `crates/aex-net/src/dns.rs` as a free function.
Update main.rs to delegate. Add a matching test in `aex-net/src/dns.rs`.

---

### Centralize `verify_tunnel_http_healthz` retry loop into `retry_with_backoff`

**What.** Replace the hand-tuned 6-attempt × 3s sleep loop in
`crates/aex-control-plane/src/routes/transfers.rs:911-933` with
`retry_with_backoff(&RetryPolicy::normative(), should_retry, op)`.

**Why.** Sprint 1.5 plan-eng-review (2026-04-21, Section B decision) kept the
loop in place because the 6×3s budget was empirically tuned during Sprint 1
on a real Cloudflare quick-tunnel — switching to `RetryPolicy::normative()`
(3 attempts, 1s base, 2× multiplier, ±100ms jitter = ~7s total budget) would
halve the propagation window and risks regression on slow networks.

**Empirical calibration required** before flipping. Normative §5.1 may need
to bump `max_attempts` to 5 or 6 for Cloudflare tunnel DNS propagation window
specifically, OR we expose a caller-specific override on `RetryPolicy`.

**Pros.** Single retry implementation across all HTTP paths. Normative spec
applies uniformly.

**Cons.** Regression risk on real Cloudflare quick-tunnel DNS propagation
edge (observed in Sprint 1 demo). Requires empirical measurement.

**Depends on.** (1) Sprint 2 task "Normative retry spec §5.1 finalized in
docs/protocol-v1.md". (2) Sprint 3 Issue 22 (dedicated Fly.io testbed) so
we can measure real propagation-window distribution.

**Where to start.** Before flipping, run ≥10 back-to-back
`demo_two_agents_cloudflare.py` executions with both policies
(6×3s vs normative). Record attempt count to success per run. If normative's
p95 ≥ policy budget, bump normative max_attempts and re-justify §5.1.

---

## Sprint 3 — Observability + resilience follow-ups

### Real captive-portal integration test in chaos testbed

**What.** Add a container scenario to the Sprint 3 `aex-testbed` Fly.io app
that simulates a common captive-portal setup (302 redirect on
`/hotspot-detect.html`, 200 with body mismatch on `/generate_204`, HTTP 511
on `/ncsi.txt`). Verify `aex_net::captive::detect_network_state` classifies
each correctly.

**Why.** Sprint 1.5 plan-eng-review (2026-04-21, Issue 2) chose axum mock
tests for captive-portal detection. Axum mocks exercise the response-shape
grammar but miss real-world interactions with certificate pinning, MITM
proxy injection, HTTP 511 specifically, and DNS hijacking by the portal.

**Pros.** Catches regressions that unit mocks can't see. Confidence in
real-world captive behavior before users hit it.

**Cons.** CI flakiness potential. Tooling complexity for container
networking. Partial overlap with existing Sprint 3 Issue 22 chaos scope.

**Depends on.** Sprint 3 task 7 — Fly.io `aex-testbed` app landing with
toxiproxy. This test lives inside that testbed as a sub-scenario, not as a
standalone.

**Where to start.** Extend the Sprint 3 chaos suite definition with a
`captive-portal` scenario. Reference the three probe endpoints used by
`detect_network_state` and use nginx or caddy config to emulate each failure
mode. Expected outcome matrix:

| Scenario | Expected NetworkState |
|---|---|
| All 3 probes 200/204/ok.txt | Direct |
| Apple redirects to login.wifi.local | CaptivePortal |
| Google returns 200 instead of 204 | Limited |
| MS NCSI body ≠ "Microsoft NCSI" | Limited |
| All probes timeout | Unknown |
| HTTP 511 from any probe | CaptivePortal |

---

## v2.2 — Deferred decisions follow-up

### Multi-party deferred decisions (N-of-M signed responses)

**What.** Extend the deferred-decision pattern (ADR-0049) so that
multiple deciders may need to concur before the final outcome is
issued. The wire format would gain an aggregate response carrying
N signatures, plus a capability bit advertising the recipient's
threshold (e.g. `multi-party-decision-2-of-3`).

**Why.** Real use cases:
- Corporate spending above a threshold requires CFO + procurement
  + legal approval.
- Legal contract review by two specialist agents (clauses +
  liability) plus one human counsel.
- AI ensemble voting (three specialist models concur or the
  transfer is held).
Without standard support these flows are implemented bilaterally
between sender and recipient — non-interoperable and
non-verifiable in conformance.

**Pros.** Natural generalisation of the v2.1 deferred-decision
pattern. Reuses the same `decision_id` correlation, the same
audit-receipt mechanics. Differentiator vs other agent stacks
that lack multi-party primitives.

**Cons.** State machine grows (partial decisions, dissent
handling, dissenter weight). Wire format gets an aggregate
container — first non-trivial extension to v2 canonical bytes.
Conformance burden roughly doubles for this capability.

**Depends on.** v2.1 deferred-decision in production with real
operator feedback on edge cases. Do not design v2.2 in the
abstract; collect concrete N-of-M scenarios from adopters first.

**Where to start.** Re-read ADR-0049 §Consequences for the
explicit acknowledgement that multi-party is out of v2.1 scope.
Draft a follow-up ADR with: aggregate response shape, threshold
advertisement, partial-decision audit semantics, sender-side
behaviour when threshold is missed.

**Effort estimate.** L (4-6 weeks once design is locked).
**Priority.** P2.

