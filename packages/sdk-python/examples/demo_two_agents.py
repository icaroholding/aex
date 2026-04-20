"""M1 demo: Alice sends a clean file to Bob, then tries EICAR (blocked).

Run:
    # in a separate terminal:
    docker compose -f deploy/docker-compose.dev.yml up -d
    DATABASE_URL=postgres://spize:spize_dev@localhost:5432/spize \
        cargo run -p spize-control-plane

    # then:
    python packages/sdk-python/examples/demo_two_agents.py
"""

from __future__ import annotations

import os
import time

from aex_sdk import Identity, SpizeClient

BASE_URL = os.environ.get("SPIZE_BASE_URL", "http://127.0.0.1:8080")

EICAR = (
    b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
)


def main() -> None:
    print(f"— Spize M1 demo against {BASE_URL} —\n")

    suffix = int(time.time())
    alice = Identity.generate(org="demo", name=f"alice{suffix}")
    bob = Identity.generate(org="demo", name=f"bob{suffix}")
    print(f"Alice: {alice.agent_id}")
    print(f"Bob:   {bob.agent_id}\n")

    with SpizeClient(BASE_URL, alice) as ac, SpizeClient(BASE_URL, bob) as bc:
        ac.register()
        bc.register()
        print("Both agents registered.\n")

        # --- Scenario 1: clean file ---
        payload = b"Ciao Bob, ecco la fattura Q1. -Alice"
        print(f"[1] Alice sends a clean {len(payload)}-byte text file to Bob …")
        tx = ac.send(recipient=bob.agent_id, data=payload,
                     declared_mime="text/plain", filename="invoice.txt")
        print(f"    transfer_id: {tx.transfer_id}")
        print(f"    state: {tx.state}")
        print(f"    verdict: {tx.scanner_verdict and tx.scanner_verdict.get('overall')}")

        received = bc.download(tx.transfer_id)
        assert received == payload, "payload mismatch!"
        print(f"    Bob downloaded ✓ ({len(received)} bytes match)")

        ack = bc.ack(tx.transfer_id)
        print(f"    Bob acked — chain head: {ack['audit_chain_head'][:16]}…\n")

        # --- Scenario 2: EICAR ---
        print("[2] Alice tries to send EICAR test malware to Bob …")
        tx2 = ac.send(recipient=bob.agent_id, data=EICAR,
                      declared_mime="text/plain", filename="test.txt")
        print(f"    transfer_id: {tx2.transfer_id}")
        print(f"    state: {tx2.state}")
        print(f"    rejection: {tx2.rejection_code} — {tx2.rejection_reason}\n")
        assert tx2.was_rejected, "expected EICAR to be rejected"

        print("Demo complete. M1 flow verified end-to-end.")


if __name__ == "__main__":
    main()
