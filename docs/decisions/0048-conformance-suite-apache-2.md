# ADR-0048: `aex-conformance` suite is Apache-2.0 open binary; badge URL pattern

## Status

Accepted 2026-05-19.

## Context

ADR-0029 introduced the idea of a normative spec plus per-language
conformance suite, scoped to wire-v1 within the Rust workspace. For v2,
the conformance suite becomes a strategic asset: it is the artefact that
lets a third-party deployment claim "AEX v2 compliant" without involving
Spize. That claim has to be (a) verifiable by anyone and (b) costless to
produce for both compliant and non-compliant deployments.

W3C, IETF, Matrix, and ACME all converged on the same pattern: open-
licence reference test suite, anyone runs it, results are public. Closed
test suites or BSL-encumbered ones do not get cited as the canonical
arbiter of compliance and end up bypassed by alternative suites from
larger vendors.

The conformance suite is also the place where we operationalise
ADR-0045 (SSRF), ADR-0044 (clock skew), ADR-0046 (cache ETag), and the
algorithm whitelist (no `alg=none`, no `alg=HS256`) — it is the test
that catches a regression in any of those before the regression reaches
production.

## Decision

1. **License.** Apache-2.0, same as the rest of `aex-core`, `aex-net`,
   etc. The conformance binary is published on the same release channels
   as the SDKs: `crates.io` (`aex-conformance`), `npm`
   (`@aexproto/conformance`), `PyPI` (`aex-conformance`). The same test
   set runs in all three distributions.

2. **Binary contract.**

   ```
   $ aex-conformance --target <URL>
   Running 30 conformance tests…
   ✓ wire-v2-roundtrip
   ✓ jws-algorithm-whitelist
   ✓ ssrf-resistance
   ✓ clock-skew-handling
   …
   ALL PASSED — You can claim AEX v2 compliance.
   Badge URL: https://aex.dev/badge/v2/<sha256-of-results>
   ```

   Exit code 0 on pass, 1 on any failure. JSON report available via
   `--report-json <path>`.

3. **Test categories at v2.0 GA.** Wire-v2 round-trip; JWS algorithm
   whitelist; SSRF resistance; clock-skew handling; agent-card cache
   ETag; capability negotiation; single-flight stampede protection;
   nonce replay rejection; v1↔v2 dual-wire fallback; DID URI parser
   strictness; A2A bridge minimum (if advertised). Total: 30 tests at
   GA, growing with each capability ADR.

4. **Badge URL is informational, not authoritative.** The badge URL
   pattern is reserved for a future v2.1 "directory of compliant
   deployments" (deferred to TODOS.md). At GA, the URL is a stable
   reference for "we ran the suite and got these results" — but the
   results themselves stand on their own, not on Spize hosting them.

5. **Reference deployment passes.** Both `aex-control-plane` (open,
   BSL-1.1) and `spize-cp` (commercial overlay) MUST pass the suite at
   every release; CI gates on the suite output before tagging.

## Consequences

- Any AEX deployment can self-certify. The cost of compliance is one
  `aex-conformance --target $URL` command; the cost of non-compliance is
  publicly visible failure messages.
- Third parties writing alternative AEX implementations (a Go control
  plane, a Rust SDK, an Elixir client) have an objective bar to hit. Their
  passing the suite is a marketing asset for them and for the protocol.
- The conformance binary is small (~2 MB stripped) so it can ship in CI
  images without bloating them.
- Adding a new conformance test is a one-PR change: drop a file in
  `crates/aex-conformance/src/tests/`, update the count in the README.
  No coordination with other repos.
- The "verifiable compliance" claim becomes part of AEX's pitch to
  standards bodies (NIST, Linux Foundation A2A working group) — the
  suite is exactly what they ask for.
