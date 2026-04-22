"""Transport-plurality endpoint descriptor + serial-sticky negotiation.

Sprint 2 (wire v1.3.0-beta.1): a transfer carries a ``reachable_at[]``
array of endpoints. The recipient tries them in the sender's declared
priority order (ADR-0012: sender-ranked, serial, sticky) and stops at
the first that answers. Stickiness is per-transfer: subsequent transfers
re-evaluate from the top.

Unknown ``kind`` values are preserved on the wire but SKIPPED during
fallback — a forward-compatible peer on a newer wire can advertise a
transport this SDK can't speak, and we gracefully fall through instead
of exploding.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Optional

# Known transport kinds. Keep in sync with the Rust
# `aex_core::Endpoint::KIND_*` constants.
KIND_CLOUDFLARE_QUICK = "cloudflare_quick"
KIND_CLOUDFLARE_NAMED = "cloudflare_named"
KIND_IROH = "iroh"
KIND_TAILSCALE_FUNNEL = "tailscale_funnel"
KIND_FRP = "frp"

KNOWN_KINDS: frozenset[str] = frozenset(
    {
        KIND_CLOUDFLARE_QUICK,
        KIND_CLOUDFLARE_NAMED,
        KIND_IROH,
        KIND_TAILSCALE_FUNNEL,
        KIND_FRP,
    }
)

# Endpoints this SDK can actually dial today. Iroh requires an iroh
# client wire-up that lands in a later PR; until then Iroh endpoints are
# skipped with a debug log rather than dialed.
HTTP_KINDS: frozenset[str] = frozenset(
    {
        KIND_CLOUDFLARE_QUICK,
        KIND_CLOUDFLARE_NAMED,
        KIND_TAILSCALE_FUNNEL,
        KIND_FRP,
    }
)


@dataclass(frozen=True)
class Endpoint:
    """A single way to reach a sender's data plane."""

    kind: str
    url: str
    priority: int = 0
    health_hint_unix: Optional[int] = None

    @classmethod
    def from_json(cls, obj: dict[str, Any]) -> "Endpoint":
        return cls(
            kind=str(obj["kind"]),
            url=str(obj["url"]),
            priority=int(obj.get("priority", 0)),
            health_hint_unix=(
                int(obj["health_hint_unix"]) if obj.get("health_hint_unix") is not None else None
            ),
        )

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "kind": self.kind,
            "url": self.url,
            "priority": self.priority,
        }
        if self.health_hint_unix is not None:
            out["health_hint_unix"] = self.health_hint_unix
        return out

    @property
    def is_known_kind(self) -> bool:
        return self.kind in KNOWN_KINDS

    @property
    def is_http_dialable(self) -> bool:
        return self.kind in HTTP_KINDS


def sort_by_priority(endpoints: Iterable[Endpoint]) -> list[Endpoint]:
    """Return endpoints ordered by sender priority (lower first), ties
    broken by original position (Python's sort is stable)."""
    return sorted(endpoints, key=lambda e: e.priority)


@dataclass
class FallbackAttempt:
    """One attempt in [`try_endpoints`] — useful for surfacing diagnostics
    to the caller when all transports fail."""

    endpoint: Endpoint
    error: Optional[str] = None
    skipped_reason: Optional[str] = None
    ok: bool = False


@dataclass
class FallbackResult:
    """Outcome of [`try_endpoints`]. On success ``value`` is whatever the
    per-endpoint callable returned for the first working endpoint."""

    value: Any = None
    chosen: Optional[Endpoint] = None
    attempts: list[FallbackAttempt] = field(default_factory=list)

    @property
    def succeeded(self) -> bool:
        return self.chosen is not None


def try_endpoints(
    endpoints: Iterable[Endpoint],
    attempt: Callable[[Endpoint], Any],
    *,
    on_skip: Optional[Callable[[Endpoint, str], None]] = None,
) -> FallbackResult:
    """Walk ``endpoints`` in sender-declared priority order; invoke
    ``attempt(endpoint)`` on each until one returns without raising.

    - Unknown / non-dialable kinds are skipped with a recorded reason;
      they never count as failures for the purposes of the
      at-least-one-succeeded invariant.
    - The first exception from a known-dialable endpoint is recorded but
      does NOT abort fallback — we keep walking.
    - Once one attempt succeeds, the loop stops (sticky per-transfer per
      ADR-0012).

    Returns a [`FallbackResult`] populated with the chosen endpoint, the
    attempt's return value, and per-endpoint diagnostics.
    """
    result = FallbackResult()
    ordered = sort_by_priority(endpoints)
    for ep in ordered:
        if not ep.is_known_kind:
            reason = f"unknown kind: {ep.kind!r}"
            result.attempts.append(FallbackAttempt(endpoint=ep, skipped_reason=reason))
            if on_skip is not None:
                on_skip(ep, reason)
            continue
        if not ep.is_http_dialable:
            reason = f"{ep.kind} is not HTTP-dialable from this SDK yet"
            result.attempts.append(FallbackAttempt(endpoint=ep, skipped_reason=reason))
            if on_skip is not None:
                on_skip(ep, reason)
            continue
        try:
            value = attempt(ep)
        except Exception as exc:  # pragma: no cover - the per-endpoint
            # error path is covered in test_endpoint.py with a mock that
            # raises; the `except Exception` is deliberately broad so a
            # failing endpoint never crashes fallback.
            result.attempts.append(FallbackAttempt(endpoint=ep, error=str(exc)))
            continue
        result.attempts.append(FallbackAttempt(endpoint=ep, ok=True))
        result.value = value
        result.chosen = ep
        return result
    return result
