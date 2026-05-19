# AEX Protocol v2

**Status**: Draft. Targets `2.0.0-beta.1` tag push (Q3 2026). Supersedes
ADR-0018's Q1-2027 timeline per ADR-0042.

**Scope**: this document defines the wire format and identity model that
AEX implementations MUST follow in v2. It is normative. The wire-v1 spec
(`docs/protocol-v1.md`) remains authoritative for the duration of the
v1→v2 grace window defined in [ADR-0043](decisions/0043-capability-negotiation-dual-wire.md).

**Authoritative byte-exact reference**: `crates/aex-core/src/wire_v2.rs`.
Whenever this document and the reference implementation disagree, the
test vectors in `wire_v2::tests::*_stable` win — open an issue.

---

## §1. Identity

### §1.1 AgentId format

A v2 `AgentId` is a W3C DID URI per DID Core §3.1:

```
agent-id           = did-uri
did-uri            = "did:" method ":" method-specific-id [ "#" fragment ]
method             = 1*method-char
method-char        = %x61-7A / DIGIT          ; lowercase ASCII + digits
method-specific-id = 1*idchar                 ; method-defined; see §1.3
fragment           = 1*fragment-char          ; method-defined; non-empty
```

Maximum total length: **256 octets** (`MAX_AGENT_ID_LEN` in
`aex-core::types`). All octets MUST be ASCII (no whitespace, no control
characters, no NUL).

Legacy v1 ids (`spize:org/name:fingerprint`) MAY appear inside wire-v2
payloads during the grace window and MUST be accepted by v2 verifiers.
They do not match the DID URI grammar above; implementations dispatch on
the leading `spize:` token.

Reference parser: `aex-core::types::AgentId::as_did_uri()`.
Reference scheme dispatcher: `aex-core::types::AgentId::scheme()` →
`IdScheme::{SpizeNative, DidSpize, DidEthr, DidWeb, DidKey, Unknown}`.

### §1.2 DID methods supported at v2.0 GA

Per [ADR-0047](decisions/0047-v2-providers-spize-web-ethr-key.md):

| Method | Method-specific-id grammar | Use case |
|---|---|---|
| `did:spize` | `org/name`; fragment is the key fingerprint | Hosted convenience, continuity from v1 `spize:` |
| `did:web`   | DNS authority; fragment is the agent local-id | Domain-anchored enterprise identity |
| `did:ethr`  | `<chain-id>:<0x-address>`; no fragment | EtereCitizen reputation (ADR-0040) |
| `did:key`   | multibase-encoded public key; no fragment | Offline / device-local |

Examples:

```
did:spize:acme/agent-fatture#a4f8b2cd
did:web:studio-rossi.it#agente-clienti
did:ethr:8453:0x14a34b9d2c
did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV
```

Reserved for v2.1+: `did:plc`, `did:ans`, `did:ens`, `did:peer`.
A v2.0 implementation receiving an unrecognised DID method MUST emit
`ResolverError::UnsupportedDidMethod` rather than a generic error.

### §1.3 Method-specific resolution

Each method resolves an `AgentId` to a verifying key:

- `did:spize` — query the registered control plane's `GET /v1/agents/:id`
  or `GET /v2/agents/:id` (same record, dual-served).
- `did:web` — GET `https://<authority>/.well-known/agent-card.json` via
  `aex-net::safe_http` (ADR-0045). The agent card is a JWS (§6); the
  embedded public key is the verifying key.
- `did:ethr` — query the EtereCitizen on-chain registry on Base L2.
  2-of-3 RPC consensus required (ADR-0040).
- `did:key` — decode the multibase string; the bytes are the verifying
  key directly. No network call.

All resolutions are subject to the cache policy in
[ADR-0046](decisions/0046-card-cache-1h-etag-events.md): 1 h TTL,
ETag conditional revalidation, event-driven invalidation on rotate or
revoke.

---

## §2. Capability bits

Capabilities are advertised in two places: the JWS-signed agent card
(§6) and the `GET /v2/capabilities` HTTP response of a control plane
(§5). Each capability has a stable string name; readers ignore unknown
names (forward-compat per ADR-0018).

### §2.1 v2.0 capability registry

Source of truth: `aex-core::Capability` enum. The following bits exist at
v2.0 GA:

| Name | Meaning |
|---|---|
| `wire-v2` | Speaker supports `aex-*:v2` wire prefix (§3). Required for v2 traffic. |
| `jws-agent-card` | Speaker publishes a JWS-signed `/.well-known/agent-card.json` (ADR-0025). |
| `card-etag` | Speaker supports `If-None-Match` conditional GET on the agent card (ADR-0046). |
| `a2a-bridge` | Speaker accepts inbound Google A2A v1.0 task envelopes via the bridge adapter. |
| `etere-citizen-trust` | Speaker's identity is `did:ethr` and observed on-chain via EtereCitizen reputation index. Set by resolver, not advertised by sender. |
| `safe-http` | Speaker fetches well-known endpoints via SSRF-resistant client (ADR-0045). |
| `clock-skew-60s` | Speaker rejects intents with `|now − ts| > 60` seconds (ADR-0044). |
| `streaming-transfer` | Reserved for v2.2. |

Bit positions are immutable; see `aex-core::Capability::as_bit()`.
Renumbering would invalidate every deployed agent card.

### §2.2 Wire serialization

In the JWS payload of the agent card, capabilities are encoded as a JSON
array of strings:

```json
{
  "agent_id": "did:web:acme.com#fatture",
  "capabilities": ["wire-v2", "jws-agent-card", "card-etag", "clock-skew-60s"],
  "...": "..."
}
```

In the `GET /v2/capabilities` response, the same array shape applies (see
§5). Unknown strings MUST be silently dropped on read.

---

## §3. Wire v2 canonical bytes

Every cryptographically signed message in v2 has a canonical byte form
that MUST be reproduced bit-for-bit by any conforming implementation.
The form is line-based: `\n` (LF) terminates every line except the last;
no trailing LF; every field value is single-line ASCII.

Reference: `crates/aex-core/src/wire_v2.rs`. Test vectors:
`wire_v2::tests::*_stable` (Rust) and the cross-language conformance
suite (ADR-0029, extended for v2 per ADR-0048).

### §3.1 `aex-register:v2`

Signed by a registering agent's keypair, proving possession of the
private key.

```
aex-register:v2
pub={public_key_hex}
org={org}
name={name}
nonce={nonce}
ts={issued_at_unix}
```

Field constraints:

| Field | Constraint |
|---|---|
| `public_key_hex` | ASCII single-line; non-empty. Method-specific encoding (Ed25519: 64 hex chars; secp256k1: 66 hex). |
| `org`, `name` | ASCII single-line; non-empty. |
| `nonce` | Lowercase hex, 32–128 chars. New per registration. |
| `issued_at_unix` | Integer Unix seconds. |

Reference function: `wire_v2::registration_challenge_bytes_v2`.

### §3.2 `aex-transfer-intent:v2`

Signed by the **sender** before initiating a transfer.

```
aex-transfer-intent:v2
sender={sender_agent_id}
recipient={recipient_agent_id}
size={size_bytes}
mime={declared_mime_or_empty}
filename={filename_or_empty}
nonce={nonce}
ts={issued_at_unix}
```

`sender_agent_id` and `recipient_agent_id` MUST be either v2 DID URIs
(§1) or legacy `spize:` ids during the grace window.

Test vector (from `wire_v2::tests::v2_transfer_intent_uses_did_uri`):

```
aex-transfer-intent:v2
sender=did:web:acme.com#agent-vendite
recipient=did:web:beta-corp.com#acquisti
size=12345
mime=application/pdf
filename=invoice.pdf
nonce=0123456789abcdef0123456789abcdef
ts=1700000000
```

Reference function: `wire_v2::transfer_intent_bytes_v2`.

### §3.3 `aex-data-ticket:v2`

Signed by the **control plane** when issuing a short-lived capability to
fetch blob bytes directly from a data-plane server.

```
aex-data-ticket:v2
transfer={transfer_id}
recipient={recipient_agent_id}
data_plane={data_plane_url}
expires={expires_unix}
nonce={nonce}
```

`data_plane_url` MUST be an absolute https:// URL. `expires_unix` MUST
be in the future relative to issuance.

Reference function: `wire_v2::data_ticket_bytes_v2`.

### §3.4 `aex-rotate-key:v2`

Signed by the agent's **current** key when requesting rotation to a new
public key (ADR-0024 protocol).

```
aex-rotate-key:v2
agent={agent_id}
old_pub={current_public_key_hex}
new_pub={new_public_key_hex}
nonce={nonce}
ts={issued_at_unix}
```

`old_pub` and `new_pub` MUST differ; verifiers reject otherwise.

Reference function: `wire_v2::rotate_key_challenge_bytes_v2`.

### §3.5 `aex-transfer-receipt:v2`

Signed by the **recipient** when requesting a blob, downloading it, or
acknowledging delivery.

```
aex-transfer-receipt:v2
recipient={recipient_agent_id}
transfer={transfer_id}
action={action}
nonce={nonce}
ts={issued_at_unix}
```

`action` MUST be one of `download`, `ack`, `inbox`, `request_ticket`.
Other values are rejected.

Reference function: `wire_v2::transfer_receipt_bytes_v2`.

### §3.6 Cross-version invariant

For any logical message, the v1 bytes and the v2 bytes are **never**
equal. v1 starts with `spize-`, v2 with `aex-`. A signature verifier
that picks the wrong codec MUST fail signature verification — that is
the intended cross-version sentinel. Reference test:
`wire_v2::tests::v2_prefix_differs_from_v1_for_identical_inputs`.

---

## §4. Clock skew + nonce discipline

Per [ADR-0044](decisions/0044-clock-skew-60s-rfc-7519.md):

### §4.1 Clock skew

Wire-v2 verifiers MUST reject any signed message whose `ts` (or `iat`/`exp`
claim for JWS) differs from `now()` by more than 60 seconds in either
direction. Reference helper:
`aex-core::wire_v2::is_within_clock_skew_v2`.

Verifiers SHOULD emit a `clock_skew.detected` log line at `WARN` level
for any successful verification with `|now − ts| ∈ (30 s, 60 s]`, and at
`ERROR` level for any rejection. Required structured fields:
`peer_id`, `skew_seconds`, `direction ∈ {past, future}`.

### §4.2 Nonce

Every signed message includes a `nonce` field: lowercase hex, length
between `MIN_NONCE_LEN` (32 chars) and `MAX_NONCE_LEN` (128 chars).
A 32-char hex nonce provides 128 bits of entropy. Implementations MUST
draw fresh nonces per message; reusing a nonce within the clock-skew
window allows replay and constitutes a protocol violation.

Verifiers MUST track recently-seen `(sender, nonce)` pairs for at least
`MAX_CLOCK_SKEW_SECS_V2 + 5 s` to detect replay. A replay attempt MUST
emit a `WireError::NonceReuse` audit event at `ERROR` level.

---

## §5. Capability negotiation

Per [ADR-0043](decisions/0043-capability-negotiation-dual-wire.md):

### §5.1 `GET /v2/capabilities`

Every control plane MUST expose `GET /v2/capabilities` returning a JSON
document:

```json
{
  "wire_versions": ["v1", "v2"],
  "capabilities": ["wire-v2", "jws-agent-card", "card-etag", "clock-skew-60s", "safe-http"],
  "max_transfer_bytes": 10737418240,
  "supported_did_methods": ["spize", "web", "ethr", "key"]
}
```

Required fields: `wire_versions`, `capabilities`. Other fields are
informational and MAY be added by implementations; readers MUST ignore
unknown fields. Cache the response for at most 1 minute on the client
side.

### §5.2 Sender adapter

Before sending a transfer intent to a recipient, the sending client:

1. GET `https://<recipient-control-plane>/v2/capabilities`.
2. If `wire_versions` contains `"v2"` and the local sender supports v2 →
   use `aex-transfer-intent:v2`.
3. Else if `wire_versions` contains `"v1"` → use
   `spize-transfer-intent:v1` (fallback).
4. Else → fail loudly. No silent downgrade past v1.

### §5.3 Recipient-side dual parser

During the grace window, control planes MUST verify both prefixes:

- First-line match `spize-` → dispatch to wire-v1 verifier.
- First-line match `aex-` → dispatch to wire-v2 verifier.

Mixing inside one signed payload is a protocol error (`WireError::PrefixMixed`).

### §5.4 Grace window and sunset

6 months from v2 GA. Post-sunset:

- v1-format intents arriving at a control plane receive
  `426 Upgrade Required` with a `Link: </runbook/v1-sunset>; rel="help"`
  header.
- The Prometheus counter `aex_wire_v1_legacy_transfers_total` is reviewed
  weekly; if v1 share exceeds 20 % seven days before sunset, the sunset
  date slips by one calendar week (P2 alert per ADR-0035).

---

## §6. JWS-signed agent card

Per [ADR-0025](decisions/0025-jws-signed-agent-card.md):

### §6.1 Endpoint

`GET https://<authority>/.well-known/agent-card.json`

Served as a static file or by the control plane on behalf of the agent.
Cache headers MUST permit `If-None-Match` (ADR-0046).

### §6.2 Format

The response body is a JWS Compact Serialization (RFC 7515) of three
base64url-encoded segments separated by `.`:

```
<header>.<payload>.<signature>
```

#### §6.2.1 Header

```json
{
  "alg": "EdDSA",
  "typ": "JOSE+JSON",
  "kid": "did:web:acme.com#fatture-2026q3"
}
```

Allowed `alg` values: `"EdDSA"` (Ed25519) or `"ES256K"` (secp256k1).
Verifiers MUST reject `"alg": "none"`, `"alg": "HS256"`, and any other
value. The whitelist is hardcoded; it is not a configuration option.

`kid` MUST match the agent's full DID URI.

#### §6.2.2 Payload

```json
{
  "iss": "did:web:acme.com",
  "sub": "did:web:acme.com#fatture",
  "iat": 1716100000,
  "exp": 1716186400,
  "agent_id": "did:web:acme.com#fatture",
  "public_key": {
    "type": "Ed25519VerificationKey2020",
    "publicKeyMultibase": "z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV"
  },
  "capabilities": ["wire-v2", "jws-agent-card", "card-etag", "clock-skew-60s"],
  "endpoints": {
    "control_plane": "https://acme.com/aex",
    "data_planes": ["https://data.acme.com"]
  }
}
```

Required: `iss`, `sub`, `iat`, `exp`, `agent_id`, `public_key`,
`capabilities`. `exp − iat` MUST be at least 1 hour and at most 90 days.

### §6.3 Verification

Verifiers MUST:

1. Parse the three segments. Reject if not exactly two `.` separators.
2. Parse the header JSON. Reject if `alg` is not in the whitelist
   (§6.2.1).
3. Parse the payload JSON. Reject if any required claim is missing.
4. Check `iat ≤ now ≤ exp` with the 60-s leeway (§4.1).
5. Extract the verifying key from `public_key`. Verify the signature
   over `<base64url(header)>.<base64url(payload)>`.
6. Match `kid` against the `agent_id` claim. Reject on mismatch
   (`JwsKeyMismatch`).

A verification failure on any of these steps MUST be logged at `ERROR`
level with the structured `kid`, `attempted_alg`, `reason` fields.

---

## §7. Conformance

Per [ADR-0048](decisions/0048-conformance-suite-apache-2.md):

### §7.1 Reference suite

The binary `aex-conformance` exercises every normative requirement in
this document against a target control plane URL. Pass condition: every
test in the suite returns `OK`; any test returning `FAIL` invalidates
the compliance claim for that target.

### §7.2 Required tests at v2.0 GA

Each implementation that claims AEX v2 compliance MUST pass:

| Test | Asserts |
|---|---|
| `wire-v2-roundtrip` | Bytes from §3 round-trip through sign+verify against all four DID methods. |
| `jws-algorithm-whitelist` | `alg=none`, `alg=HS256`, missing `alg` → reject. |
| `ssrf-resistance` | safe_http rejects all RFC1918, loopback, link-local, IPv6 ULA targets. |
| `clock-skew-handling` | ±61-s `ts` rejected; ±59-s accepted. |
| `cache-etag` | 304 Not Modified extends TTL without re-verification. |
| `capability-negotiation` | `GET /v2/capabilities` lists `wire-v2`; sender adapter selects correctly. |
| `single-flight` | 100 concurrent resolutions of same handle → 1 outbound fetch. |
| `nonce-replay-rejection` | Same `(sender, nonce)` within window → `WireError::NonceReuse`. |
| `did-uri-parser` | Empty fragment, uppercase method, missing MSI → reject. |
| `cross-version-isolation` | v1 bytes never accepted as v2; v2 bytes never accepted as v1. |

Implementations MAY add tests beyond this list; the suite is forward-
compatible.

### §7.3 Cross-language byte equality

The wire-v2 canonical bytes (§3) MUST be byte-identical across Rust,
Python, and TypeScript SDKs for the same inputs. The golden-vector test
in `tests/golden/wire-v2.json` (ADR-0032) is the arbiter; any divergence
between implementations fails CI in all three languages simultaneously.

---

## §8. Deferred decisions

Per [ADR-0049](decisions/0049-deferred-decisions-neutral-standard.md):

### §8.1 Capability advertisement

A recipient that may answer inbound intents asynchronously MUST
advertise the `deferred-decision` capability bit (bit 8) in its
JWS-signed agent card and in its `GET /v2/capabilities` response.

A sender observing this bit MUST handle an HTTP `202 Accepted`
response to a `POST /v2/intents` and MUST wait for a signed
`aex-decision-response:v2` message before considering the transfer
settled.

### §8.2 `aex-decision-request:v2`

Signed by the **recipient** immediately after receiving an intent
when the policy engine returns a deferred outcome.

```
aex-decision-request:v2
recipient={recipient_agent_id}
transfer={transfer_id}
decision={decision_id}
eta_secs={eta_seconds}
nonce={nonce}
ts={issued_at_unix}
```

| Field | Constraint |
|---|---|
| `recipient` | The recipient's AgentId. |
| `transfer` | The same `transfer_id` issued for the intent. |
| `decision` | Unique identifier within the recipient's namespace. The same string MUST appear in the corresponding response. |
| `eta_secs` | Non-negative integer hint of expected wait in seconds. `0` means "as soon as practical". |
| `nonce` | Lowercase hex, 32–128 chars. |
| `ts` | Integer Unix seconds. |

Reference function: `aex-core::wire_v2::decision_request_bytes_v2`.

### §8.3 `aex-decision-response:v2`

Signed by the **recipient** once the deferred verdict has been
produced.

```
aex-decision-response:v2
recipient={recipient_agent_id}
transfer={transfer_id}
decision={decision_id}
outcome={accepted|rejected}
reason={reason_or_empty}
nonce={nonce}
ts={issued_at_unix}
```

`outcome` MUST be exactly `accepted` or `rejected`. The whitelist is
fixed; future values require a fresh ADR and a wire-version bump.

`reason` is optional (empty allowed) and carries a human-readable
explanation visible to the sender and the audit chain.

Reference function: `aex-core::wire_v2::decision_response_bytes_v2`.

### §8.4 Decider neutrality

The protocol does not specify, recommend, or constrain **who or
what** produces the final outcome. Conforming implementations MAY
source the decision from:

- a human operator via an interactive prompt,
- a secondary AI evaluator (specialist model, second-opinion
  agent),
- a deterministic policy engine (Cedar, OPA, custom DSL),
- a consensus of multiple agents (out of scope for v2.1; see
  ADR-0049 §Consequences for the v2.2 trajectory),
- any combination of the above.

The wire bytes are identical regardless of the decider.

### §8.5 Audit trail

Conforming implementations MUST record both messages in their audit
chain:

- The `aex-decision-request:v2` event lands as
  `DeferredDecisionRequested` in `aex-audit::EventKind`.
- The `aex-decision-response:v2` event lands as
  `SignedDecisionReceipt`. The receipt is non-repudiable: any later
  dispute can verify the original signature against the recipient's
  registered key.

### §8.6 Idempotency and finality

Once a `aex-decision-response:v2` has been emitted for a given
`decision_id`, the decision is final. Re-issuing a response with
the same `decision_id` MUST be rejected by both the sender's
verifier and the recipient's audit chain as a uniqueness violation.

Changing the outcome requires a new transfer.

### §8.7 Conformance

Conforming implementations MUST pass the three deferred-decision
checks in the `aex-conformance` suite:

- `decision-request-bytes-stable`
- `decision-response-bytes-stable`
- `deferred-decision-capability-bit-stable`

## Appendix A — Change log relative to v1

| Item | v1 | v2 |
|---|---|---|
| Wire prefix | `spize-*:v1` | `aex-*:v2` |
| AgentId form | `spize:org/name:fp` | `did:method:msi[#frag]` |
| Clock skew window | 300 s | 60 s |
| Identity providers | Spize-native, did:ethr (stub) | did:spize, did:web, did:ethr (full), did:key |
| Agent card | Optional, unsigned | Required for did:web; JWS-signed |
| Conformance | Per-crate Rust | Open binary, multi-language |
| Trust scoring | None | EtereCitizen surfacing |

## Appendix B — Reference implementations

| Component | Path |
|---|---|
| Wire v2 byte producer | `crates/aex-core/src/wire_v2.rs` |
| AgentId parser | `crates/aex-core/src/types.rs` |
| Capability registry | `crates/aex-core/src/capability.rs` |
| safe_http | `crates/aex-net/src/safe_http.rs` (ADR-0045, chunk 4) |
| JWS verifier | `crates/aex-jws/src/lib.rs` (chunk 2) |
| DID providers | `crates/aex-identity/src/{did_spize, did_web, did_ethr, did_key}.rs` (chunk 3) |
| Resolver chain | `crates/aex-identity/src/resolver_chain.rs` (chunk 5) |
| Conformance suite | `crates/aex-conformance/` (chunk 12) |
