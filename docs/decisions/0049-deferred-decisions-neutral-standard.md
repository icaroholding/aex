# ADR-0049: Deferred decisions — neutral standard for non-immediate responses

## Status

Accepted 2026-05-20.

## Context

AEX v2.0 ships with two synchronous outcomes from the policy engine:
`Allow` and `Deny`. Both must be produced inside the same request
that delivered the transfer intent — the protocol assumes the
recipient can answer the sender immediately.

A growing class of agent-to-agent workflows breaks that assumption:

- High-value transfers (regulated transactions, large file sizes,
  contracts) where the recipient requires a human operator to
  confirm before processing.
- Two-stage AI evaluation where a primary agent receives an intent
  and delegates the accept/reject decision to a secondary, more
  specialized agent (security review, domain expert, second-opinion
  model).
- External policy engines that need seconds to minutes to evaluate
  (KYC checks, on-chain reputation lookups, sanctions screening).
- Multi-agent consensus where N agents must concur before the
  transfer can proceed.

Today implementers add this behavior outside the protocol — usually
by holding the connection open with long-polling, by returning a
synthetic `Deny` with a "please-retry" code, or by tunneling the
deferred state through application-level conventions. The result is
non-interoperable across SDKs and impossible to verify in a
conformance suite.

The pattern shared by all the use cases above is structurally the
same: **the recipient acknowledges receipt but cannot produce the
final outcome immediately, and will return a signed verdict later.**
The protocol takes no position on who or what produces the verdict
— human prompt, secondary AI, policy engine, consensus of agents
are all equivalent at the wire layer.

## Decision

AEX v2.1 introduces a deferred-decision pattern as a first-class
protocol feature, expressed as one new capability bit and two new
canonical signed messages:

1. **Capability bit `deferred-decision`** (bit 8 in
   `aex_core::capability`). Recipients that advertise this bit
   inform senders that their responses to inbound intents may be
   deferred. Senders MUST be prepared to receive an HTTP 202
   Accepted on intent submission and to wait for a signed
   `aex-decision-response:v2` before considering the transfer
   settled.

2. **Canonical message `aex-decision-request:v2`** — signed by the
   recipient and returned to the sender immediately after receiving
   the intent. Carries `decision_id`, `transfer_id`, an `eta_secs`
   hint, a nonce, and a timestamp.

3. **Canonical message `aex-decision-response:v2`** — signed by the
   recipient when the deferred verdict has been produced. Carries
   the same `decision_id` plus the `outcome` field (`accepted` or
   `rejected`), an optional `reason`, a nonce, and a timestamp. The
   outcome whitelist is hardcoded; new values require a future ADR.

4. **`PolicyDecision::Pending` variant** in `aex-policy`. Additive
   to the existing `Allow`/`Deny` enum; legacy code that only
   matches the two original variants continues to compile (the new
   variant is treated as deny-by-default by non-aware code paths).

5. **`DecisionSink` trait** in `aex-policy` with two reference
   implementations:
   - `InProcessDecisionSink` — closure-based, decision produced
     synchronously inside the process (LLM call, local prompt,
     deterministic policy function).
   - `WebhookDecisionSink` — HTTP POST to an operator-configured
     URL. The remote system later POSTs a signed
     `aex-decision-response:v2` back to the control plane.
   The protocol takes no position on the trait surface beyond what
   the standard implementations exercise; downstream operators may
   ship custom sinks.

6. **Audit chain events.** Two new `EventKind` variants:
   `DeferredDecisionRequested` (a request was issued) and
   `SignedDecisionReceipt` (a final response was emitted and
   persisted as a non-repudiable receipt of the decision).

The wire format is silent about who or what decides. Whether the
deferred outcome originates from a human operator, a secondary
AI evaluator, a policy DSL engine, or a multi-party consensus is an
implementation choice with no protocol consequences.

## Consequences

- AEX gains a class of agent-to-agent workflows previously
  unsupported by the standard (high-value transfers requiring
  confirmation, second-opinion AI delegation, asynchronous policy
  enforcement).
- The pattern is **decider-neutral**: it does not bias the protocol
  toward human-in-the-loop nor toward fully autonomous workflows.
  Implementers choose the decider at runtime configuration time.
- Senders MUST handle the 202 Accepted response and the
  deferred-response signal. SDKs ship logic for this; legacy
  senders that do not handle the deferred path see the transfer
  as a transient unavailable state and retry, eventually surfacing
  a timeout to their caller.
- A new outcome whitelist (`accepted`, `rejected`) joins the
  hardcoded algorithm whitelists already enforced by `aex-jws`.
  Any future outcome value requires a fresh ADR and a wire-version
  bump in the corresponding canonical message.
- The non-repudiability of decisions is a first-class protocol
  property: the audit chain records both the request and the
  final signed response, anchoring decision provenance against
  later disputes.
- Multi-party decisions (N-of-M signatures) are explicitly not
  part of v2.1. They are a natural extension of this pattern and
  are tracked in `TODOS.md` for v2.2.
