"""End-to-end integration test for the Python SDK.

Requires a running control plane (started automatically via a subprocess
fixture if not already up). Marked optional because it spins up services
and runs real HTTP — skip it in CI where Postgres isn't available.
"""

from __future__ import annotations

import os
import socket
import subprocess
import tempfile
import time

import pytest

from aex_sdk import Identity, SpizeClient
from aex_sdk.errors import SpizeHTTPError


def _server_reachable(url: str) -> bool:
    """Quick TCP check against base url host:port."""
    import urllib.parse as up

    parsed = up.urlparse(url)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or 80
    try:
        with socket.create_connection((host, port), timeout=0.25):
            return True
    except OSError:
        return False


BASE_URL = os.environ.get("SPIZE_TEST_BASE_URL", "http://127.0.0.1:8080")


@pytest.mark.skipif(
    not _server_reachable(BASE_URL),
    reason=f"control plane at {BASE_URL} not reachable; run it manually",
)
def test_alice_sends_clean_file_to_bob(tmp_path) -> None:
    alice = Identity.generate(
        org="sdktest",
        name=f"alice{int(time.time())}",
    )
    bob = Identity.generate(
        org="sdktest",
        name=f"bob{int(time.time())}",
    )

    with SpizeClient(BASE_URL, alice) as alice_client, SpizeClient(
        BASE_URL, bob
    ) as bob_client:
        alice_client.register()
        bob_client.register()

        payload = b"e2e-test-" + os.urandom(32)
        tx = alice_client.send(
            recipient=bob.agent_id,
            data=payload,
            declared_mime="text/plain",
            filename="note.txt",
        )
        assert tx.state == "ready_for_pickup", f"unexpected state: {tx.state}"

        received = bob_client.download(tx.transfer_id)
        assert received == payload

        ack = bob_client.ack(tx.transfer_id)
        assert ack["state"] == "delivered"
        assert len(ack["audit_chain_head"]) == 64


@pytest.mark.skipif(
    not _server_reachable(BASE_URL),
    reason="control plane not reachable",
)
def test_eicar_blocked() -> None:
    alice = Identity.generate(
        org="sdktest",
        name=f"eicarsend{int(time.time())}",
    )
    bob = Identity.generate(
        org="sdktest",
        name=f"eicarrecv{int(time.time())}",
    )

    with SpizeClient(BASE_URL, alice) as alice_client, SpizeClient(
        BASE_URL, bob
    ) as bob_client:
        alice_client.register()
        bob_client.register()

        eicar = (
            b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        )
        tx = alice_client.send(
            recipient=bob.agent_id,
            data=eicar,
            declared_mime="text/plain",
            filename="test.txt",
        )
        assert tx.was_rejected, f"EICAR should be rejected; state = {tx.state}"
        assert tx.rejection_code == "scanner_malicious"

        # Bob can't download a rejected transfer.
        with pytest.raises(SpizeHTTPError) as ei:
            bob_client.download(tx.transfer_id)
        assert ei.value.status_code == 404
