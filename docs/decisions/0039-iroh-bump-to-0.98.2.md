# ADR-0039: Bump Iroh from `=0.96.0` to `=0.98.2`

## Status

Accepted 2026-05-16. Supersedes the `=0.96.0` pin defined in ADR-0015.

## Context

ADR-0015 requires that any Iroh version bump go through its own ADR.
This one is forced by an upstream defect, not by appetite for new
features.

`iroh-base` (a transitive dep of `iroh 0.96.0`) declares
`ed25519-dalek =3.0.0-pre.1` — an exact pin on a single prerelease
build. That prerelease has a known compile error in `signing.rs`:
its `?` returns a `KeyError` constructor where the surrounding
function expects `ed25519::pkcs8::Error`. The cargo resolver picks
the pinned `=3.0.0-pre.1`, the build fails, and there is no patch
override path inside spize-desktop that satisfies the exact-pin
constraint without forking the upstream crate. Subsequent
prereleases (`3.0.0-pre.2` … `3.0.0-pre.7`) fixed the bug, but
`iroh-base 0.96.x` will never relax that pin.

The first iroh-base line whose ed25519-dalek pin moved off the
broken `3.0.0-pre.1` is `0.98.0` (pinned to `=3.0.0-pre.6`).
`0.98.x` is the most recent stable minor in the 0.9x line; `1.0.0`
is still at `-rc.0`.

## Decision

`iroh = "=0.98.2"`. Same exact-pin discipline as ADR-0015 — the bump
is a one-time, audited event, not the start of a caret range.

Behaviour-wise this preserves the previous default: `IrohEndpoint::builder`
now requires an explicit `Preset` argument, and we pass
`iroh::endpoint::presets::N0` which expands to n0.computer DNS
publishing + the default relay mode — exactly what `0.96.0` did
implicitly.

## Consequences

- The upstream defect is gone. The Spize desktop can now consume
  `aex-tunnel` again.
- Public API of `IrohTunnel` is unchanged; no downstream code needs
  to move.
- We absorbed one extra line in `aex-tunnel/src/iroh.rs` (the `N0`
  import and the `builder(N0)` call) and updated ADR-0015's status
  to point here. Any future bump still follows the ADR cadence.
- ADR-0002 and the README index were updated to reflect `=0.98.2`.
