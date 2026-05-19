"""Wire v2 canonical bytes for AEX (ADR-0042).

These functions MUST produce byte-for-byte identical output to the
corresponding Rust functions in ``aex_core::wire_v2``. The cross-
language golden-vector tests in ``tests/test_wire_v2.py`` pin specific
inputs to specific expected bytes; the same vectors are checked by
``aex-core/src/wire_v2.rs`` ``*_stable`` tests. Any drift in either
direction fails CI in both stacks.

Differences from v1 (``aex_sdk.wire``):

- The canonical prefix is ``aex-<msg>:v2`` instead of
  ``spize-<msg>:v1``. Brand neutrality per ADR-0042.
- The clock-skew window is 60 seconds (down from 300) per ADR-0044.
- ``AgentId`` values inside the payload are expected to be W3C DID
  URIs (``did:method:specific-id[#fragment]``). Legacy ``spize:`` ids
  are still accepted at the wire layer during the v1→v2 grace window
  (ADR-0043) — the function does not enforce DID URI shape because the
  recipient's verifier is the authority on identity validity.
"""

from __future__ import annotations

PROTOCOL_VERSION_V2 = "v2"
MAX_CLOCK_SKEW_SECS_V2 = 60
MIN_NONCE_LEN = 32
MAX_NONCE_LEN = 128


def _validate_ascii_line(s: str, field: str, *, allow_empty: bool = False) -> None:
    if not s:
        if allow_empty:
            return
        raise ValueError(f"{field} is empty")
    for i, c in enumerate(s):
        if ord(c) > 127 or c in ("\n", "\r", "\0"):
            raise ValueError(f"{field} has invalid char at {i}: {c!r}")


def _validate_nonce(nonce: str) -> None:
    if not (MIN_NONCE_LEN <= len(nonce) <= MAX_NONCE_LEN):
        raise ValueError(
            f"nonce length {len(nonce)} outside [{MIN_NONCE_LEN}, {MAX_NONCE_LEN}]"
        )
    if not all(c in "0123456789abcdefABCDEF" for c in nonce):
        raise ValueError("nonce must be hex")


def is_within_clock_skew_v2(now_unix: int, issued_at_unix: int) -> bool:
    """True iff ``|now − issued_at| ≤ 60 s``. Overflow-safe."""
    diff = now_unix - issued_at_unix
    if diff < 0:
        diff = -diff
    return diff <= MAX_CLOCK_SKEW_SECS_V2


def registration_challenge_bytes_v2(
    public_key_hex: str,
    org: str,
    name: str,
    nonce: str,
    issued_at_unix: int,
) -> bytes:
    _validate_ascii_line(public_key_hex, "public_key_hex")
    _validate_ascii_line(org, "org")
    _validate_ascii_line(name, "name")
    _validate_nonce(nonce)
    return (
        f"aex-register:{PROTOCOL_VERSION_V2}\n"
        f"pub={public_key_hex}\n"
        f"org={org}\n"
        f"name={name}\n"
        f"nonce={nonce}\n"
        f"ts={issued_at_unix}"
    ).encode("ascii")


def transfer_intent_bytes_v2(
    sender_agent_id: str,
    recipient: str,
    size_bytes: int,
    declared_mime: str,
    filename: str,
    nonce: str,
    issued_at_unix: int,
) -> bytes:
    _validate_ascii_line(sender_agent_id, "sender_agent_id")
    _validate_ascii_line(recipient, "recipient")
    _validate_ascii_line(declared_mime, "declared_mime", allow_empty=True)
    _validate_ascii_line(filename, "filename", allow_empty=True)
    _validate_nonce(nonce)
    return (
        f"aex-transfer-intent:{PROTOCOL_VERSION_V2}\n"
        f"sender={sender_agent_id}\n"
        f"recipient={recipient}\n"
        f"size={size_bytes}\n"
        f"mime={declared_mime}\n"
        f"filename={filename}\n"
        f"nonce={nonce}\n"
        f"ts={issued_at_unix}"
    ).encode("ascii")


def data_ticket_bytes_v2(
    transfer_id: str,
    recipient_agent_id: str,
    data_plane_url: str,
    expires_unix: int,
    nonce: str,
) -> bytes:
    """Canonical data-plane ticket bytes (v2).

    Mirrors ``aex_core::wire_v2::data_ticket_bytes_v2``. The control
    plane is the actual signer; the SDK includes this function for
    completeness (verification on the recipient side, golden-vector
    tests).
    """
    _validate_ascii_line(transfer_id, "transfer_id")
    _validate_ascii_line(recipient_agent_id, "recipient_agent_id")
    _validate_ascii_line(data_plane_url, "data_plane_url")
    _validate_nonce(nonce)
    return (
        f"aex-data-ticket:{PROTOCOL_VERSION_V2}\n"
        f"transfer={transfer_id}\n"
        f"recipient={recipient_agent_id}\n"
        f"data_plane={data_plane_url}\n"
        f"expires={expires_unix}\n"
        f"nonce={nonce}"
    ).encode("ascii")


def rotate_key_challenge_bytes_v2(
    agent_id: str,
    old_public_key_hex: str,
    new_public_key_hex: str,
    nonce: str,
    issued_at_unix: int,
) -> bytes:
    _validate_ascii_line(agent_id, "agent_id")
    _validate_ascii_line(old_public_key_hex, "old_public_key_hex")
    _validate_ascii_line(new_public_key_hex, "new_public_key_hex")
    _validate_nonce(nonce)
    if old_public_key_hex == new_public_key_hex:
        raise ValueError("old_public_key_hex and new_public_key_hex must differ")
    return (
        f"aex-rotate-key:{PROTOCOL_VERSION_V2}\n"
        f"agent={agent_id}\n"
        f"old_pub={old_public_key_hex}\n"
        f"new_pub={new_public_key_hex}\n"
        f"nonce={nonce}\n"
        f"ts={issued_at_unix}"
    ).encode("ascii")


def transfer_receipt_bytes_v2(
    recipient_agent_id: str,
    transfer_id: str,
    action: str,
    nonce: str,
    issued_at_unix: int,
) -> bytes:
    _validate_ascii_line(recipient_agent_id, "recipient_agent_id")
    _validate_ascii_line(transfer_id, "transfer_id")
    _validate_ascii_line(action, "action")
    _validate_nonce(nonce)
    if action not in ("download", "ack", "inbox", "request_ticket"):
        raise ValueError(
            f"action must be 'download', 'ack', 'inbox' or 'request_ticket', got {action}"
        )
    return (
        f"aex-transfer-receipt:{PROTOCOL_VERSION_V2}\n"
        f"recipient={recipient_agent_id}\n"
        f"transfer={transfer_id}\n"
        f"action={action}\n"
        f"nonce={nonce}\n"
        f"ts={issued_at_unix}"
    ).encode("ascii")


def decision_request_bytes_v2(
    recipient_agent_id: str,
    transfer_id: str,
    decision_id: str,
    eta_seconds: int,
    nonce: str,
    issued_at_unix: int,
) -> bytes:
    """Canonical bytes for an ``aex-decision-request:v2`` message (ADR-0049).

    Signed by the recipient and returned to the sender when an
    inbound transfer cannot be answered synchronously.
    """
    _validate_ascii_line(recipient_agent_id, "recipient_agent_id")
    _validate_ascii_line(transfer_id, "transfer_id")
    _validate_ascii_line(decision_id, "decision_id")
    _validate_nonce(nonce)
    if eta_seconds < 0:
        raise ValueError("eta_seconds must be non-negative")
    return (
        f"aex-decision-request:{PROTOCOL_VERSION_V2}\n"
        f"recipient={recipient_agent_id}\n"
        f"transfer={transfer_id}\n"
        f"decision={decision_id}\n"
        f"eta_secs={eta_seconds}\n"
        f"nonce={nonce}\n"
        f"ts={issued_at_unix}"
    ).encode("ascii")


def decision_response_bytes_v2(
    recipient_agent_id: str,
    transfer_id: str,
    decision_id: str,
    outcome: str,
    reason: str,
    nonce: str,
    issued_at_unix: int,
) -> bytes:
    """Canonical bytes for an ``aex-decision-response:v2`` message (ADR-0049).

    Signed by the recipient once the deferred decision has been
    taken. ``outcome`` must be exactly ``accepted`` or ``rejected``.
    """
    _validate_ascii_line(recipient_agent_id, "recipient_agent_id")
    _validate_ascii_line(transfer_id, "transfer_id")
    _validate_ascii_line(decision_id, "decision_id")
    _validate_ascii_line(outcome, "outcome")
    _validate_ascii_line(reason, "reason", allow_empty=True)
    _validate_nonce(nonce)
    if outcome not in ("accepted", "rejected"):
        raise ValueError(
            f"outcome must be 'accepted' or 'rejected', got {outcome}"
        )
    return (
        f"aex-decision-response:{PROTOCOL_VERSION_V2}\n"
        f"recipient={recipient_agent_id}\n"
        f"transfer={transfer_id}\n"
        f"decision={decision_id}\n"
        f"outcome={outcome}\n"
        f"reason={reason}\n"
        f"nonce={nonce}\n"
        f"ts={issued_at_unix}"
    ).encode("ascii")
