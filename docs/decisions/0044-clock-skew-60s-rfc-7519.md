# ADR-0044: Clock skew window tightens from 300 s (v1) to 60 s (v2), RFC 7519 §4.1.4 compliant

## Status

Accepted 2026-05-19.

## Context

Wire v1 (`aex-core::wire::MAX_CLOCK_SKEW_SECS`) accepts a clock-skew window
of 300 seconds between sender and verifier — the time difference between
the sender's `ts` field and the verifier's `now()`. This was chosen as a
generous default during early development, when laptop clocks could drift
several minutes between NTP syncs.

The 300 s window is also the replay window. An attacker who captures a
signed intent has up to 5 minutes to replay it against a different
recipient or path. For a protocol that aspires to be cited in agent-to-
agent stacks, that window is too wide. RFC 7519 (JWT) §4.1.4 and the
`exp` claim semantics it standardized are: 60 s leeway is the norm; less is
better; more invites trouble.

Tightening v1 retroactively would break working deployments. v2 is the
opportunity to set a stricter default.

## Decision

Wire v2 (`aex-core::wire_v2::MAX_CLOCK_SKEW_SECS_V2`) sets the accepted
clock-skew window to 60 seconds. Specifically:

1. Verifiers reject any wire-v2 intent whose `ts` differs from `now()` by
   more than 60 seconds in either direction.
2. JWS-signed agent cards (ADR-0025) use the same window for `iat` and
   `exp` claims.
3. Verifiers SHOULD emit a structured `clock_skew.detected` log line
   (level `WARN`) for any successful verification whose `|now - ts|` is
   within 60 s but above 30 s. This is the early warning before drift
   reaches the rejection threshold.
4. Verifiers MUST emit `clock_skew.detected` at level `ERROR` for any
   rejected message, with `peer_id`, `skew_seconds`, `direction` fields.

The 60 s window applies to v2 only; v1 retains its 300 s window through
the dual-wire grace window (ADR-0043).

## Consequences

- The replay window for v2 intents shrinks 5× compared to v1.
- Hosts with clock drift > 60 s discover the problem at the first failed
  send, not after audit-time forensics. Operators have a runbook
  (`runbooks/clock-skew-recovery.md`) to fix it.
- VMs without NTP-syncing become an explicit operational error rather
  than silent acceptance. The deploy template includes an NTP service
  by default.
- Prometheus exposes `aex_clock_skew_seconds` histogram; ADR-0035 P2 alert
  fires when p99 exceeds 30 s for 5 minutes.
- Adopters are aligned with the JWT/OAuth2 norm — one less surprise in
  audits.
