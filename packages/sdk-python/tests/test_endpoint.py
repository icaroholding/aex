"""Tests for the Sprint 2 transport-plurality endpoint negotiation."""

from __future__ import annotations

import pytest

from aex_sdk.endpoint import (
    KIND_CLOUDFLARE_QUICK,
    KIND_FRP,
    KIND_IROH,
    Endpoint,
    sort_by_priority,
    try_endpoints,
)


def test_endpoint_roundtrip_without_health_hint():
    ep = Endpoint(kind=KIND_CLOUDFLARE_QUICK, url="https://a.trycloudflare.com", priority=0)
    j = ep.to_json()
    assert j == {
        "kind": "cloudflare_quick",
        "url": "https://a.trycloudflare.com",
        "priority": 0,
    }
    assert Endpoint.from_json(j) == ep


def test_endpoint_roundtrip_with_health_hint():
    ep = Endpoint(
        kind=KIND_IROH,
        url="iroh:abc@relay.aex.dev:443",
        priority=1,
        health_hint_unix=1_700_000_000,
    )
    j = ep.to_json()
    assert j["health_hint_unix"] == 1_700_000_000
    assert Endpoint.from_json(j) == ep


def test_known_vs_unknown_kind():
    ok = Endpoint(kind=KIND_FRP, url="https://frp.example")
    alien = Endpoint(kind="future_transport_v9", url="future:alien@mars")
    assert ok.is_known_kind
    assert ok.is_http_dialable
    assert not alien.is_known_kind
    assert not alien.is_http_dialable


def test_iroh_known_but_not_http_dialable():
    ep = Endpoint(kind=KIND_IROH, url="iroh:abc")
    assert ep.is_known_kind
    assert not ep.is_http_dialable


def test_sort_by_priority_stable_on_ties():
    eps = [
        Endpoint(kind=KIND_FRP, url="a", priority=5),
        Endpoint(kind=KIND_FRP, url="b", priority=1),
        Endpoint(kind=KIND_FRP, url="c", priority=1),
    ]
    sorted_eps = sort_by_priority(eps)
    assert [e.url for e in sorted_eps] == ["b", "c", "a"]


def test_try_endpoints_picks_first_success():
    eps = [
        Endpoint(kind=KIND_FRP, url="first", priority=0),
        Endpoint(kind=KIND_FRP, url="second", priority=1),
    ]
    calls = []

    def attempt(ep: Endpoint) -> str:
        calls.append(ep.url)
        return f"fetched:{ep.url}"

    result = try_endpoints(eps, attempt)
    assert result.succeeded
    assert result.value == "fetched:first"
    assert result.chosen and result.chosen.url == "first"
    assert calls == ["first"]  # sticky: stops after first success


def test_try_endpoints_falls_through_on_error():
    eps = [
        Endpoint(kind=KIND_FRP, url="broken", priority=0),
        Endpoint(kind=KIND_FRP, url="working", priority=1),
    ]

    def attempt(ep: Endpoint) -> str:
        if ep.url == "broken":
            raise RuntimeError("kaboom")
        return "ok"

    result = try_endpoints(eps, attempt)
    assert result.succeeded
    assert result.chosen and result.chosen.url == "working"
    assert len(result.attempts) == 2
    assert result.attempts[0].error == "kaboom"
    assert result.attempts[1].ok


def test_try_endpoints_skips_iroh_and_unknown():
    skipped = []
    eps = [
        Endpoint(kind=KIND_IROH, url="iroh:a", priority=0),
        Endpoint(kind="future_transport_v9", url="alien:x", priority=1),
        Endpoint(kind=KIND_FRP, url="https://frp.ok", priority=2),
    ]

    def attempt(ep: Endpoint) -> str:
        return "ok"

    result = try_endpoints(eps, attempt, on_skip=lambda ep, reason: skipped.append((ep.kind, reason)))
    assert result.succeeded
    assert result.chosen and result.chosen.url == "https://frp.ok"
    assert any(k == "iroh" for k, _ in skipped)
    assert any(k == "future_transport_v9" for k, _ in skipped)


def test_try_endpoints_returns_unsucceeded_when_all_fail():
    eps = [
        Endpoint(kind=KIND_FRP, url="first", priority=0),
        Endpoint(kind=KIND_FRP, url="second", priority=1),
    ]

    def attempt(ep: Endpoint) -> str:
        raise ConnectionError(f"failed: {ep.url}")

    result = try_endpoints(eps, attempt)
    assert not result.succeeded
    assert result.chosen is None
    assert len(result.attempts) == 2
    assert all(a.error is not None for a in result.attempts)


def test_try_endpoints_empty_list_returns_unsucceeded():
    result = try_endpoints([], lambda ep: "ok")
    assert not result.succeeded
    assert result.attempts == []


def test_try_endpoints_respects_sender_priority_order():
    eps = [
        Endpoint(kind=KIND_FRP, url="low-priority", priority=5),
        Endpoint(kind=KIND_FRP, url="high-priority", priority=0),
    ]
    hit = []

    def attempt(ep: Endpoint) -> str:
        hit.append(ep.url)
        return "ok"

    result = try_endpoints(eps, attempt)
    assert result.succeeded
    assert hit == ["high-priority"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
