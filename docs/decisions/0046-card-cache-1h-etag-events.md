# ADR-0046: Agent card cache — 1 h TTL + ETag conditional GET + event-driven invalidation

## Status

Accepted 2026-05-19.

## Context

The v2 resolver chain (ADR-0047) fetches `/.well-known/agent-card.json` for
every distinct recipient handle. A naive implementation re-fetches on
every send and re-verifies every JWS, which is wasteful and puts load on
the recipient's well-known endpoint proportional to the sender's send
rate. A naive caching strategy with a very long TTL prolongs the propagation
window for key rotations (ADR-0024 requires 24 h grace from rotate to
sunset) and capability changes.

A working middle ground is needed: short enough to track rotations,
long enough to avoid a thundering herd on every recipient's static-file
server.

## Decision

The resolver chain caches `ResolvedAgent` records with the following
policy:

1. **TTL 1 hour.** Every cached entry expires 1 h after its underlying
   JWS was minted (taken from the `iat` claim, not the local fetch time).
   This makes the cache lifetime a property of the issuer, not the
   resolver.

2. **Conditional revalidation with ETag.** When the TTL expires, the
   resolver issues a GET with `If-None-Match: <stored ETag>`:
   - `304 Not Modified` → extend TTL another 1 h; do not re-verify the
     JWS (the bytes haven't changed, the signature is still valid).
   - `200 OK` with new ETag → verify the new JWS, replace the cached
     entry.

3. **Event-driven invalidation overrides TTL.** The cache is forcibly
   evicted in three cases, regardless of TTL remaining:
   - Key rotation observed (`aex-rotate-key:v2`) for any agent_id in
     the cache.
   - Agent revocation observed (`/v2/agents/:id/revoke` 200 response or
     equivalent audit event).
   - Manual via `aex-cli debug cache-invalidate <handle>`.

4. **Stale-while-revalidate.** When a TTL-expired entry is in revalidation,
   serve the stale entry for up to 1 h post-TTL. After that, fail with
   `ResolverError::CardExpired` rather than serving silent staleness.

5. **Bounded LRU.** 10 000 entries by default, configurable via
   `AEX_RESOLVER_CACHE_SIZE`. Eviction is LRU on `last_used_at`.

6. **Cache key.** `handle + jws_hash`. The `jws_hash` discriminates between
   "same handle, different signed card" (legitimate rotation) and "same
   handle, attacker swapped the well-known" (cache-integrity violation,
   logged and rejected, ADR-0045 audit signal).

## Consequences

- The recipient's `/.well-known/agent-card.json` sees, in steady state,
  one conditional GET per hour per active sender — not one full GET per
  send. With the `If-None-Match` branch returning 304s for unchanged
  cards, the bandwidth cost is essentially zero.
- Key rotations propagate within 1 h worst case; with event-driven
  invalidation, within seconds for any sender that observed the rotation
  event on the audit feed.
- Cache integrity is verified at every fetch: two responses for the same
  handle that disagree on `agent_id` or `pubkey` trigger
  `ResolverError::CacheIntegrityViolation` (P1 alert per ADR-0035).
- The `aex_resolver_cache_hit_ratio` Prometheus metric is expected
  > 0.85 in steady state.
- The `stale-while-revalidate` window is bounded: 1 h hard ceiling on
  serving stale, after which the resolver fails closed.
