import { describe, it, expect } from "vitest";

import { Identity, verifySignature } from "../src/identity.js";

describe("Identity", () => {
  it("generate produces a valid agent_id", async () => {
    const ident = await Identity.generate({ org: "acme", name: "alice" });
    expect(ident.agentId).toMatch(/^spize:acme\/alice:[0-9a-f]{6}$/);
    expect(ident.fingerprint).toHaveLength(6);
  });

  it("fromSecret is deterministic", async () => {
    const secret = new Uint8Array(32).fill(7);
    const a = await Identity.fromSecret({ org: "acme", name: "alice", privateKey: secret });
    const b = await Identity.fromSecret({ org: "acme", name: "alice", privateKey: secret });
    expect(a.agentId).toBe(b.agentId);
    expect(a.publicKeyHex).toBe(b.publicKeyHex);
  });

  it("sign and verifySignature roundtrip", async () => {
    const ident = await Identity.generate({ org: "acme", name: "alice" });
    const sig = await ident.sign(new TextEncoder().encode("hello"));
    expect(await verifySignature(ident.publicKey, new TextEncoder().encode("hello"), sig)).toBe(true);
    expect(await verifySignature(ident.publicKey, new TextEncoder().encode("hxllo"), sig)).toBe(false);
  });

  it("toJSON / fromJSON roundtrip", async () => {
    const ident = await Identity.generate({ org: "acme", name: "alice" });
    const json = ident.toJSON();
    const loaded = await Identity.fromJSON(json);
    expect(loaded.agentId).toBe(ident.agentId);
    expect(loaded.publicKeyHex).toBe(ident.publicKeyHex);
    expect(loaded.privateKeyHex).toBe(ident.privateKeyHex);
  });

  it("fromJSON rejects mismatched public key", async () => {
    const ident = await Identity.generate({ org: "acme", name: "alice" });
    const json = ident.toJSON();
    json.publicKeyHex = "00".repeat(32);
    await expect(Identity.fromJSON(json)).rejects.toThrow();
  });

  it("rejects bad org chars", async () => {
    await expect(
      Identity.generate({ org: "acme corp", name: "alice" }),
    ).rejects.toThrow();
  });

  it("rejects bad secret length", async () => {
    await expect(
      Identity.fromSecret({
        org: "acme",
        name: "alice",
        privateKey: new Uint8Array(16),
      }),
    ).rejects.toThrow();
  });
});
