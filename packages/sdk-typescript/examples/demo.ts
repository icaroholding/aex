/**
 * M1 demo (TypeScript): Alice sends a clean file to Bob, then EICAR.
 *
 * Run:
 *     docker compose -f deploy/docker-compose.dev.yml up -d
 *     DATABASE_URL=postgres://spize:spize_dev@localhost:5432/spize \
 *         cargo run -p spize-control-plane
 *     cd packages/sdk-typescript
 *     npm install
 *     npm run build
 *     node --experimental-strip-types examples/demo.ts
 *     # or: npx tsx examples/demo.ts
 */

import { Identity, SpizeClient } from "../src/index.js";

const BASE_URL = process.env.SPIZE_BASE_URL ?? "http://127.0.0.1:8080";

const EICAR = new TextEncoder().encode(
  "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
);

async function main() {
  console.log(`— Spize M1 demo (TS) against ${BASE_URL} —\n`);

  const suffix = Math.floor(Date.now() / 1000);
  const alice = await Identity.generate({ org: "demots", name: `alice${suffix}` });
  const bob = await Identity.generate({ org: "demots", name: `bob${suffix}` });
  console.log(`Alice: ${alice.agentId}`);
  console.log(`Bob:   ${bob.agentId}\n`);

  const ac = new SpizeClient({ baseUrl: BASE_URL, identity: alice });
  const bc = new SpizeClient({ baseUrl: BASE_URL, identity: bob });

  await ac.register();
  await bc.register();
  console.log("Both agents registered.\n");

  // [1] Clean file.
  const payload = new TextEncoder().encode("Ciao Bob from TypeScript!");
  console.log(`[1] Alice sends ${payload.length}-byte clean text to Bob …`);
  const tx = await ac.send({
    recipient: bob.agentId,
    data: payload,
    declaredMime: "text/plain",
    filename: "hello.txt",
  });
  console.log(`    transfer_id: ${tx.transferId}`);
  console.log(`    state: ${tx.state}`);

  const received = await bc.download(tx.transferId);
  console.log(`    Bob downloaded ${received.length} bytes`);
  if (Buffer.from(received).equals(Buffer.from(payload))) {
    console.log("    payload matches ✓");
  }

  const ack = await bc.ack(tx.transferId);
  console.log(`    chain head: ${ack.audit_chain_head.slice(0, 16)}…\n`);

  // [2] EICAR.
  console.log("[2] Alice tries to send EICAR …");
  const tx2 = await ac.send({
    recipient: bob.agentId,
    data: EICAR,
    declaredMime: "text/plain",
    filename: "eicar.txt",
  });
  console.log(`    state: ${tx2.state}`);
  console.log(`    rejection: ${tx2.rejectionCode} — ${tx2.rejectionReason}\n`);

  console.log("Demo complete (TS).");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
