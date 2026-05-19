"""Golden-vector tests for ``aex_sdk.wire_v2``.

Each expected byte sequence in this file is **identical** to the one
pinned in ``crates/aex-core/src/wire_v2.rs`` ``*_stable`` tests. If a
test here fails, either the Python implementation drifted from Rust or
the Rust implementation changed without updating Python — fix both
sides together, then update both test files.
"""

from __future__ import annotations

import pytest

from aex_sdk.wire_v2 import (
    MAX_CLOCK_SKEW_SECS_V2,
    MAX_NONCE_LEN,
    MIN_NONCE_LEN,
    PROTOCOL_VERSION_V2,
    data_ticket_bytes_v2,
    is_within_clock_skew_v2,
    registration_challenge_bytes_v2,
    rotate_key_challenge_bytes_v2,
    transfer_intent_bytes_v2,
    transfer_receipt_bytes_v2,
)

NONCE = "0123456789abcdef0123456789abcdef"


# ── Constants ─────────────────────────────────────────────────────────


def test_protocol_version_is_v2() -> None:
    assert PROTOCOL_VERSION_V2 == "v2"


def test_clock_skew_window_is_60s() -> None:
    assert MAX_CLOCK_SKEW_SECS_V2 == 60


def test_nonce_bounds() -> None:
    assert MIN_NONCE_LEN == 32
    assert MAX_NONCE_LEN == 128


# ── Golden vectors — must match Rust wire_v2::tests ───────────────────


def test_v2_register_canonical_bytes_stable() -> None:
    out = registration_challenge_bytes_v2(
        "aabbcc", "acme", "alice", NONCE, 1_700_000_000
    )
    expected = (
        b"aex-register:v2\n"
        b"pub=aabbcc\n"
        b"org=acme\n"
        b"name=alice\n"
        b"nonce=0123456789abcdef0123456789abcdef\n"
        b"ts=1700000000"
    )
    assert out == expected


def test_v2_transfer_intent_uses_did_uri() -> None:
    out = transfer_intent_bytes_v2(
        "did:web:acme.com#agent-vendite",
        "did:web:beta-corp.com#acquisti",
        12345,
        "application/pdf",
        "invoice.pdf",
        NONCE,
        1_700_000_000,
    )
    expected = (
        b"aex-transfer-intent:v2\n"
        b"sender=did:web:acme.com#agent-vendite\n"
        b"recipient=did:web:beta-corp.com#acquisti\n"
        b"size=12345\n"
        b"mime=application/pdf\n"
        b"filename=invoice.pdf\n"
        b"nonce=0123456789abcdef0123456789abcdef\n"
        b"ts=1700000000"
    )
    assert out == expected


def test_v2_data_ticket_stable() -> None:
    out = data_ticket_bytes_v2(
        "tx_abc123",
        "did:web:acme.com#bob",
        "https://data.acme.com",
        1_700_000_100,
        NONCE,
    )
    expected = (
        b"aex-data-ticket:v2\n"
        b"transfer=tx_abc123\n"
        b"recipient=did:web:acme.com#bob\n"
        b"data_plane=https://data.acme.com\n"
        b"expires=1700000100\n"
        b"nonce=0123456789abcdef0123456789abcdef"
    )
    assert out == expected


def test_v2_rotate_key_stable() -> None:
    old = "1" * 64
    new = "2" * 64
    out = rotate_key_challenge_bytes_v2(
        "did:spize:acme/alice#aabbcc", old, new, NONCE, 1_700_000_000
    )
    s = out.decode("ascii")
    assert s.startswith("aex-rotate-key:v2\n")
    assert "agent=did:spize:acme/alice#aabbcc\n" in s
    assert f"old_pub={old}\n" in s
    assert f"new_pub={new}\n" in s


def test_v2_receipt_stable() -> None:
    out = transfer_receipt_bytes_v2(
        "did:web:beta-corp.com#acquisti",
        "tx_abc123",
        "ack",
        NONCE,
        1_700_000_000,
    )
    expected = (
        b"aex-transfer-receipt:v2\n"
        b"recipient=did:web:beta-corp.com#acquisti\n"
        b"transfer=tx_abc123\n"
        b"action=ack\n"
        b"nonce=0123456789abcdef0123456789abcdef\n"
        b"ts=1700000000"
    )
    assert out == expected


# ── Validation rejects ─────────────────────────────────────────────────


def test_v2_newline_in_field_rejected() -> None:
    with pytest.raises(ValueError):
        registration_challenge_bytes_v2("aa", "ac\nme", "alice", NONCE, 100)


def test_v2_non_ascii_field_rejected() -> None:
    with pytest.raises(ValueError):
        registration_challenge_bytes_v2("aa", "acmè", "alice", NONCE, 100)


def test_v2_short_nonce_rejected() -> None:
    with pytest.raises(ValueError):
        registration_challenge_bytes_v2("aa", "acme", "alice", "deadbeef", 100)


def test_v2_non_hex_nonce_rejected() -> None:
    with pytest.raises(ValueError):
        registration_challenge_bytes_v2("aa", "acme", "alice", "z" * 32, 100)


def test_v2_rotate_key_rejects_same_old_and_new() -> None:
    same = "a" * 64
    with pytest.raises(ValueError):
        rotate_key_challenge_bytes_v2(
            "did:spize:acme/alice#aabbcc", same, same, NONCE, 1_700_000_000
        )


def test_v2_receipt_rejects_bad_action() -> None:
    with pytest.raises(ValueError):
        transfer_receipt_bytes_v2(
            "did:web:beta.com#bob", "tx_abc", "overwrite", NONCE, 1
        )


def test_v2_receipt_accepts_all_whitelisted_actions() -> None:
    for action in ("download", "ack", "inbox", "request_ticket"):
        out = transfer_receipt_bytes_v2(
            "did:web:beta.com#bob", "tx_abc", action, NONCE, 1
        )
        assert f"action={action}\n".encode("ascii") in out


def test_v2_data_ticket_rejects_newline_url() -> None:
    with pytest.raises(ValueError):
        data_ticket_bytes_v2(
            "tx_abc", "did:web:acme.com#bob", "https://x\nspoof", 1, NONCE
        )


# ── Cross-version invariant ────────────────────────────────────────────


def test_v2_prefix_differs_from_v1() -> None:
    """v1 and v2 bytes for the same logical inputs MUST differ.

    Any verifier picking the wrong codec MUST fail signature
    verification — this is the cross-version sentinel.
    """
    from aex_sdk.wire import registration_challenge_bytes as v1_register

    v1 = v1_register("aabbcc", "acme", "alice", NONCE, 1_700_000_000)
    v2 = registration_challenge_bytes_v2(
        "aabbcc", "acme", "alice", NONCE, 1_700_000_000
    )
    assert v1 != v2
    assert v1.startswith(b"spize-")
    assert v2.startswith(b"aex-")


# ── Clock-skew helper ──────────────────────────────────────────────────


def test_v2_skew_within_window_accepted() -> None:
    now = 1_700_000_000
    assert is_within_clock_skew_v2(now, now) is True
    assert is_within_clock_skew_v2(now, now - 60) is True
    assert is_within_clock_skew_v2(now, now + 60) is True


def test_v2_skew_outside_window_rejected() -> None:
    now = 1_700_000_000
    assert is_within_clock_skew_v2(now, now - 61) is False
    assert is_within_clock_skew_v2(now, now + 61) is False


def test_v2_skew_extreme_inputs_safe() -> None:
    """Python ints are arbitrary precision; no overflow concerns,
    but the helper should still return False on extreme deltas."""
    now = 1_700_000_000
    assert is_within_clock_skew_v2(now, -(2**63)) is False
    assert is_within_clock_skew_v2(now, 2**63) is False
