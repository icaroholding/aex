# ADR-0045: `aex-net::safe_http` — SSRF-resistant HTTP fetcher for resolver chain

## Status

Accepted 2026-05-19.

## Context

The v2 resolver chain (ADR-0047) fetches `/.well-known/agent-card.json` and
`/.well-known/did.json` over HTTPS for any DID URI the local agent has not
yet seen. Both the URL host and (transitively) the URL itself are derived
from inputs supplied by a remote peer — the recipient handle in a transfer
intent, the issuer of a chained delegation, the `kid` in a JWS header.

That puts the fetcher squarely in the OWASP A10:2021 surface (Server-Side
Request Forgery). Without mitigation, an attacker sends a transfer intent
with recipient `did:web:internal-admin.local` and our resolver eagerly
GETs `https://internal-admin.local/.well-known/agent-card.json` — leaking
the existence of internal services, port-scanning the local network, or
exfiltrating session cookies via redirects.

The fetcher executes in two places: inside `aex-control-plane` (server-side,
on every inbound intent) and inside the SDKs (client-side, on every send).
Both must apply the same defenses.

## Decision

A new module `aex-net::safe_http` exposes a single function
`safe_get(url) -> Result<Response, SafeHttpError>` used by every AEX
component that fetches well-known documents from third-party domains. The
function applies, in order:

1. **Scheme allowlist.** HTTPS only. `http://`, `file://`, custom schemes
   → reject.
2. **DNS resolve once.** Use `aex-net::dns::CloudflareDnsResolver` with
   DoH so we know which IP we are about to connect to.
3. **CIDR block list.** Reject any resolved IP that falls inside:
   - IPv4 loopback (`127.0.0.0/8`)
   - IPv4 RFC 1918 private (`10.0.0.0/8`, `172.16.0.0/12`,
     `192.168.0.0/16`)
   - IPv4 link-local (`169.254.0.0/16`)
   - IPv4 multicast (`224.0.0.0/4`)
   - IPv6 loopback (`::1/128`), unique-local (`fc00::/7`), link-local
     (`fe80::/10`), multicast (`ff00::/8`)
4. **Connect by IP, not by host.** Pass the resolved IP literal to
   `reqwest::ClientBuilder::resolve()` so connect-time DNS rebinding is
   impossible; preserve the original `Host:` header for SNI/HTTP routing.
5. **No redirects.** `redirect::Policy::none()`. A 3xx response is treated
   as a hard fail, not silently followed. Redirect-following would let an
   attacker bypass step (3) by serving a 302 to an internal IP.
6. **Timeout 5 s.** Connect + read budget.
7. **Body size cap 64 KiB.** Agent cards are < 8 KiB in practice; 64 KiB
   is the hard ceiling and is enforced at stream level (no
   `.bytes().await` on unbounded body).
8. **No proxy.** Ignore `HTTPS_PROXY` env var to avoid attacker-controlled
   relays in CI/dev environments.

The list above is the policy; the implementation lives in a single
~150-line module so the surface is auditable.

## Consequences

- The SSRF surface for AEX shrinks to one auditable choke-point. The
  conformance suite (ADR-0048) includes a `safe_http_resistance` group
  that runs all 13 bypass attempts against any AEX deployment and asserts
  the rejection.
- Connecting by IP literal forces explicit handling of certificate
  validation (SNI uses original host, cert chain validates against
  original host); a regression there would break the fetcher loudly.
- The fetcher is async (Tokio) and shares the existing reqwest connection
  pool from `aex-net::http`. No new HTTP client.
- Operators running AEX on private networks who need to reach an
  internal `did:web:my-internal-corp.local` must explicitly opt in via
  configuration (`AEX_SAFE_HTTP_ALLOWLIST=internal-corp.local`). The opt-in
  is logged at startup.
- A `aex_ssrf_blocked_total` Prometheus counter and a P2 alert fire on
  any non-zero rate, since SSRF attempts represent intent to abuse the
  network.
