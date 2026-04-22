/**
 * Transport-plurality endpoint descriptor + serial-sticky negotiation.
 *
 * Sprint 2 (wire v1.3.0-beta.1): a transfer carries a `reachable_at[]`
 * array of endpoints. The recipient tries them in the sender's declared
 * priority order (ADR-0012: sender-ranked, serial, sticky) and stops at
 * the first that answers. Stickiness is per-transfer: subsequent
 * transfers re-evaluate from the top.
 *
 * Unknown `kind` values are preserved on the wire but SKIPPED during
 * fallback — a forward-compatible peer on a newer wire can advertise a
 * transport this SDK can't speak, and we gracefully fall through
 * instead of exploding.
 */

// Keep these in sync with `aex_core::Endpoint::KIND_*` and the Python
// SDK's `aex_sdk.endpoint` constants.
export const KIND_CLOUDFLARE_QUICK = "cloudflare_quick";
export const KIND_CLOUDFLARE_NAMED = "cloudflare_named";
export const KIND_IROH = "iroh";
export const KIND_TAILSCALE_FUNNEL = "tailscale_funnel";
export const KIND_FRP = "frp";

export const KNOWN_KINDS: ReadonlySet<string> = new Set([
  KIND_CLOUDFLARE_QUICK,
  KIND_CLOUDFLARE_NAMED,
  KIND_IROH,
  KIND_TAILSCALE_FUNNEL,
  KIND_FRP,
]);

/**
 * Endpoint kinds this SDK can dial today. Iroh requires a QUIC client
 * wire-up that lands in a later PR; for now Iroh entries are skipped
 * during fallback with a `skippedReason` instead of dialed.
 */
export const HTTP_KINDS: ReadonlySet<string> = new Set([
  KIND_CLOUDFLARE_QUICK,
  KIND_CLOUDFLARE_NAMED,
  KIND_TAILSCALE_FUNNEL,
  KIND_FRP,
]);

export interface Endpoint {
  kind: string;
  url: string;
  priority: number;
  healthHintUnix?: number;
}

/** JSON shape as stored on the wire (snake_case). */
export interface EndpointJson {
  kind: string;
  url: string;
  priority?: number;
  health_hint_unix?: number | null;
}

export function endpointFromJson(obj: EndpointJson): Endpoint {
  return {
    kind: obj.kind,
    url: obj.url,
    priority: obj.priority ?? 0,
    healthHintUnix:
      obj.health_hint_unix === null || obj.health_hint_unix === undefined
        ? undefined
        : Number(obj.health_hint_unix),
  };
}

export function endpointToJson(ep: Endpoint): EndpointJson {
  const out: EndpointJson = {
    kind: ep.kind,
    url: ep.url,
    priority: ep.priority,
  };
  if (ep.healthHintUnix !== undefined) {
    out.health_hint_unix = ep.healthHintUnix;
  }
  return out;
}

export function isKnownKind(ep: Endpoint): boolean {
  return KNOWN_KINDS.has(ep.kind);
}

export function isHttpDialable(ep: Endpoint): boolean {
  return HTTP_KINDS.has(ep.kind);
}

/** Return a new array sorted by priority (lower first). `Array.sort`
 * is stable so ties keep insertion order. */
export function sortByPriority(endpoints: readonly Endpoint[]): Endpoint[] {
  return [...endpoints].sort((a, b) => a.priority - b.priority);
}

export interface FallbackAttempt {
  endpoint: Endpoint;
  error?: string;
  skippedReason?: string;
  ok: boolean;
}

export interface FallbackResult<T> {
  value?: T;
  chosen?: Endpoint;
  attempts: FallbackAttempt[];
}

export function succeeded<T>(result: FallbackResult<T>): result is FallbackResult<T> & {
  value: T;
  chosen: Endpoint;
} {
  return result.chosen !== undefined;
}

/**
 * Walk `endpoints` in sender-declared priority order and invoke
 * `attempt(endpoint)` on each until one returns without throwing.
 *
 * - Unknown / non-dialable kinds are skipped with a `skippedReason`;
 *   they never count as failures for the at-least-one-succeeded
 *   invariant.
 * - The first rejection from a known-dialable endpoint is recorded
 *   but does NOT abort fallback — we keep walking.
 * - Once one attempt resolves, the loop stops (sticky per-transfer per
 *   ADR-0012).
 */
export async function tryEndpoints<T>(
  endpoints: readonly Endpoint[],
  attempt: (ep: Endpoint) => Promise<T>,
  options?: { onSkip?: (ep: Endpoint, reason: string) => void },
): Promise<FallbackResult<T>> {
  const attempts: FallbackAttempt[] = [];
  const ordered = sortByPriority(endpoints);
  for (const ep of ordered) {
    if (!isKnownKind(ep)) {
      const reason = `unknown kind: '${ep.kind}'`;
      attempts.push({ endpoint: ep, skippedReason: reason, ok: false });
      options?.onSkip?.(ep, reason);
      continue;
    }
    if (!isHttpDialable(ep)) {
      const reason = `${ep.kind} is not HTTP-dialable from this SDK yet`;
      attempts.push({ endpoint: ep, skippedReason: reason, ok: false });
      options?.onSkip?.(ep, reason);
      continue;
    }
    try {
      const value = await attempt(ep);
      attempts.push({ endpoint: ep, ok: true });
      return { value, chosen: ep, attempts };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      attempts.push({ endpoint: ep, error: message, ok: false });
    }
  }
  return { attempts };
}
