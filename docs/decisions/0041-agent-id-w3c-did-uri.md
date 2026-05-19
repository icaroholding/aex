# ADR-0041: `AgentId` v2 format follows W3C DID Core §3.1

## Status

Accepted 2026-05-19.

## Context

Wire v1 hardcodes the agent identifier format `spize:org/name:fingerprint`.
That string is embedded inside cryptographically signed payloads (intent,
ticket, receipt, register, rotate-key) and inside every API key issued
through `spize-cp`. The `spize:` prefix is therefore part of the wire
contract, not just a label.

This prefix is in tension with where the agent-identity ecosystem has moved
since v1 was frozen: A2A v1.0 (Linux Foundation, early 2026), GoDaddy/Infoblox
ANS (announced 2026-05-14), and the W3C DID Core spec all converge on
`did:<method>:<method-specific-id>[#fragment]` as the canonical agent-handle
shape. Tooling — `did-resolver`, `didkit`, the Decentralized Identity
Foundation universal resolver — is built against that shape.

## Decision

In wire v2 (ADR-0042), agent identifiers follow W3C DID Core §3.1 ABNF:

```
did-uri        = "did:" method ":" method-specific-id [ "#" fragment ]
method         = 1*method-char
method-char    = %x61-7A / DIGIT          ; lowercase ASCII letters + digits
method-specific-id = 1*idchar
fragment       = 1*fragment-char
```

The legacy `spize:org/name:fingerprint` form continues to parse during the
v1→v2 grace window (ADR-0043), but new agents register under `did:spize:`
(or another method) and the in-protocol canonical handle is the DID URI.

`aex-core::AgentId::as_did_uri()` exposes the parsed `(method,
method-specific-id, fragment)` tuple to callers that need to dispatch on
the method or extract the fragment.

## Consequences

- AEX agent handles drop into A2A, did-resolver, and verifiable-credentials
  tooling without translation.
- The historical `spize:` namespace becomes `did:spize:` — same trust root,
  W3C-compliant URI. Existing `spize:` ids stay valid (`IdScheme::SpizeNative`
  variant) through the grace window.
- Method names are lowercase ASCII per the spec; the parser rejects
  `did:WEB:...` even though our byte validator would let the raw string
  through. Capability test enforces this.
- Empty fragments are rejected at parse time to avoid ambiguity even though
  RFC 3986 technically permits them.
- Future DID methods (`did:plc`, `did:ans`, `did:ens`) plug in through new
  `IdScheme` variants without breaking the wire format.
