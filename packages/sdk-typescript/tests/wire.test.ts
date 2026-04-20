import { describe, it, expect } from "vitest";

import {
  registrationChallengeBytes,
  transferIntentBytes,
  transferReceiptBytes,
} from "../src/wire.js";

const DEC = new TextDecoder();

describe("wire", () => {
  it("registration_challenge_bytes matches golden vector", () => {
    const bytes = registrationChallengeBytes({
      publicKeyHex: "aabbcc",
      org: "acme",
      name: "alice",
      nonce: "0123456789abcdef0123456789abcdef",
      issuedAtUnix: 1_700_000_000,
    });
    expect(DEC.decode(bytes)).toBe(
      "spize-register:v1\n" +
        "pub=aabbcc\n" +
        "org=acme\n" +
        "name=alice\n" +
        "nonce=0123456789abcdef0123456789abcdef\n" +
        "ts=1700000000",
    );
  });

  it("transfer_intent_bytes matches golden vector", () => {
    const bytes = transferIntentBytes({
      senderAgentId: "spize:acme/alice:aabbcc",
      recipient: "spize:acme/bob:ddeeff",
      sizeBytes: 12345,
      declaredMime: "application/pdf",
      filename: "invoice.pdf",
      nonce: "0123456789abcdef0123456789abcdef",
      issuedAtUnix: 1_700_000_000,
    });
    expect(DEC.decode(bytes)).toBe(
      "spize-transfer-intent:v1\n" +
        "sender=spize:acme/alice:aabbcc\n" +
        "recipient=spize:acme/bob:ddeeff\n" +
        "size=12345\n" +
        "mime=application/pdf\n" +
        "filename=invoice.pdf\n" +
        "nonce=0123456789abcdef0123456789abcdef\n" +
        "ts=1700000000",
    );
  });

  it("transfer_intent_bytes accepts empty optional fields", () => {
    const bytes = transferIntentBytes({
      senderAgentId: "spize:acme/alice:aabbcc",
      recipient: "bob@example.com",
      sizeBytes: 100,
      declaredMime: "",
      filename: "",
      nonce: "0123456789abcdef0123456789abcdef",
      issuedAtUnix: 1_700_000_000,
    });
    const s = DEC.decode(bytes);
    expect(s).toContain("mime=\n");
    expect(s).toContain("filename=\n");
  });

  it("transfer_receipt_bytes matches golden vector", () => {
    const bytes = transferReceiptBytes({
      recipientAgentId: "spize:acme/bob:ddeeff",
      transferId: "tx_abc123",
      action: "ack",
      nonce: "0123456789abcdef0123456789abcdef",
      issuedAtUnix: 1_700_000_000,
    });
    expect(DEC.decode(bytes)).toBe(
      "spize-transfer-receipt:v1\n" +
        "recipient=spize:acme/bob:ddeeff\n" +
        "transfer=tx_abc123\n" +
        "action=ack\n" +
        "nonce=0123456789abcdef0123456789abcdef\n" +
        "ts=1700000000",
    );
  });

  it("rejects short nonce", () => {
    expect(() =>
      registrationChallengeBytes({
        publicKeyHex: "aa",
        org: "acme",
        name: "alice",
        nonce: "deadbeef",
        issuedAtUnix: 100,
      }),
    ).toThrow();
  });

  it("rejects newline in field", () => {
    expect(() =>
      registrationChallengeBytes({
        publicKeyHex: "aa",
        org: "ac\nme",
        name: "alice",
        nonce: "0123456789abcdef0123456789abcdef",
        issuedAtUnix: 100,
      }),
    ).toThrow();
  });
});
