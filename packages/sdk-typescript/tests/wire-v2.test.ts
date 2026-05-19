/**
 * Golden-vector tests for `wire-v2.ts`.
 *
 * Each expected byte sequence here is identical to the one pinned in
 * `crates/aex-core/src/wire_v2.rs` `*_stable` tests and in
 * `packages/sdk-python/tests/test_wire_v2.py`. Any drift fails CI in
 * all three languages — fix together.
 */

import { describe, it, expect } from "vitest";

import {
  MAX_CLOCK_SKEW_SECS_V2,
  MAX_NONCE_LEN,
  MIN_NONCE_LEN,
  PROTOCOL_VERSION_V2,
  dataTicketBytesV2,
  decisionRequestBytesV2,
  decisionResponseBytesV2,
  isWithinClockSkewV2,
  registrationChallengeBytesV2,
  rotateKeyChallengeBytesV2,
  transferIntentBytesV2,
  transferReceiptBytesV2,
} from "../src/wire-v2";
import { registrationChallengeBytes as v1Register } from "../src/wire";

const NONCE = "0123456789abcdef0123456789abcdef";
const ENCODER = new TextEncoder();

function bytes(s: string): Uint8Array {
  return ENCODER.encode(s);
}

describe("wire-v2 constants", () => {
  it("protocol version is v2", () => {
    expect(PROTOCOL_VERSION_V2).toBe("v2");
  });
  it("clock skew window is 60 seconds", () => {
    expect(MAX_CLOCK_SKEW_SECS_V2).toBe(60);
  });
  it("nonce bounds match", () => {
    expect(MIN_NONCE_LEN).toBe(32);
    expect(MAX_NONCE_LEN).toBe(128);
  });
});

describe("wire-v2 golden vectors", () => {
  it("register canonical bytes are stable", () => {
    const out = registrationChallengeBytesV2({
      publicKeyHex: "aabbcc",
      org: "acme",
      name: "alice",
      nonce: NONCE,
      issuedAtUnix: 1_700_000_000,
    });
    const expected = bytes(
      "aex-register:v2\n" +
        "pub=aabbcc\n" +
        "org=acme\n" +
        "name=alice\n" +
        "nonce=0123456789abcdef0123456789abcdef\n" +
        "ts=1700000000",
    );
    expect(out).toEqual(expected);
  });

  it("transfer intent with did:web identifiers", () => {
    const out = transferIntentBytesV2({
      senderAgentId: "did:web:acme.com#agent-vendite",
      recipient: "did:web:beta-corp.com#acquisti",
      sizeBytes: 12345,
      declaredMime: "application/pdf",
      filename: "invoice.pdf",
      nonce: NONCE,
      issuedAtUnix: 1_700_000_000,
    });
    const expected = bytes(
      "aex-transfer-intent:v2\n" +
        "sender=did:web:acme.com#agent-vendite\n" +
        "recipient=did:web:beta-corp.com#acquisti\n" +
        "size=12345\n" +
        "mime=application/pdf\n" +
        "filename=invoice.pdf\n" +
        "nonce=0123456789abcdef0123456789abcdef\n" +
        "ts=1700000000",
    );
    expect(out).toEqual(expected);
  });

  it("data ticket canonical bytes are stable", () => {
    const out = dataTicketBytesV2({
      transferId: "tx_abc123",
      recipientAgentId: "did:web:acme.com#bob",
      dataPlaneUrl: "https://data.acme.com",
      expiresUnix: 1_700_000_100,
      nonce: NONCE,
    });
    const expected = bytes(
      "aex-data-ticket:v2\n" +
        "transfer=tx_abc123\n" +
        "recipient=did:web:acme.com#bob\n" +
        "data_plane=https://data.acme.com\n" +
        "expires=1700000100\n" +
        "nonce=0123456789abcdef0123456789abcdef",
    );
    expect(out).toEqual(expected);
  });

  it("rotate-key bytes are stable", () => {
    const old = "1".repeat(64);
    const newer = "2".repeat(64);
    const out = rotateKeyChallengeBytesV2({
      agentId: "did:spize:acme/alice#aabbcc",
      oldPublicKeyHex: old,
      newPublicKeyHex: newer,
      nonce: NONCE,
      issuedAtUnix: 1_700_000_000,
    });
    const s = new TextDecoder("utf-8").decode(out);
    expect(s.startsWith("aex-rotate-key:v2\n")).toBe(true);
    expect(s.includes(`agent=did:spize:acme/alice#aabbcc\n`)).toBe(true);
    expect(s.includes(`old_pub=${old}\n`)).toBe(true);
    expect(s.includes(`new_pub=${newer}\n`)).toBe(true);
  });

  it("receipt canonical bytes are stable", () => {
    const out = transferReceiptBytesV2({
      recipientAgentId: "did:web:beta-corp.com#acquisti",
      transferId: "tx_abc123",
      action: "ack",
      nonce: NONCE,
      issuedAtUnix: 1_700_000_000,
    });
    const expected = bytes(
      "aex-transfer-receipt:v2\n" +
        "recipient=did:web:beta-corp.com#acquisti\n" +
        "transfer=tx_abc123\n" +
        "action=ack\n" +
        "nonce=0123456789abcdef0123456789abcdef\n" +
        "ts=1700000000",
    );
    expect(out).toEqual(expected);
  });
});

describe("wire-v2 validation rejects", () => {
  it("rejects newline in field", () => {
    expect(() =>
      registrationChallengeBytesV2({
        publicKeyHex: "aa",
        org: "ac\nme",
        name: "alice",
        nonce: NONCE,
        issuedAtUnix: 100,
      }),
    ).toThrow();
  });

  it("rejects non-ASCII field", () => {
    expect(() =>
      registrationChallengeBytesV2({
        publicKeyHex: "aa",
        org: "acmè",
        name: "alice",
        nonce: NONCE,
        issuedAtUnix: 100,
      }),
    ).toThrow();
  });

  it("rejects short nonce", () => {
    expect(() =>
      registrationChallengeBytesV2({
        publicKeyHex: "aa",
        org: "acme",
        name: "alice",
        nonce: "deadbeef",
        issuedAtUnix: 100,
      }),
    ).toThrow();
  });

  it("rejects non-hex nonce", () => {
    expect(() =>
      registrationChallengeBytesV2({
        publicKeyHex: "aa",
        org: "acme",
        name: "alice",
        nonce: "z".repeat(32),
        issuedAtUnix: 100,
      }),
    ).toThrow();
  });

  it("rejects identical old/new keys in rotate", () => {
    const same = "a".repeat(64);
    expect(() =>
      rotateKeyChallengeBytesV2({
        agentId: "did:spize:acme/alice#aabbcc",
        oldPublicKeyHex: same,
        newPublicKeyHex: same,
        nonce: NONCE,
        issuedAtUnix: 1_700_000_000,
      }),
    ).toThrow();
  });

  it("rejects bad receipt action", () => {
    expect(() =>
      transferReceiptBytesV2({
        recipientAgentId: "did:web:beta.com#bob",
        transferId: "tx_abc",
        // @ts-expect-error: intentionally bad action
        action: "overwrite",
        nonce: NONCE,
        issuedAtUnix: 1,
      }),
    ).toThrow();
  });

  it("accepts all whitelisted receipt actions", () => {
    for (const action of ["download", "ack", "inbox", "request_ticket"] as const) {
      const out = transferReceiptBytesV2({
        recipientAgentId: "did:web:beta.com#bob",
        transferId: "tx_abc",
        action,
        nonce: NONCE,
        issuedAtUnix: 1,
      });
      const s = new TextDecoder("utf-8").decode(out);
      expect(s.includes(`action=${action}\n`)).toBe(true);
    }
  });

  it("rejects newline in data ticket URL", () => {
    expect(() =>
      dataTicketBytesV2({
        transferId: "tx_abc",
        recipientAgentId: "did:web:acme.com#bob",
        dataPlaneUrl: "https://x\nspoof",
        expiresUnix: 1,
        nonce: NONCE,
      }),
    ).toThrow();
  });
});

describe("wire-v2 cross-version invariant", () => {
  it("v2 bytes never collide with v1 bytes for identical inputs", () => {
    const v1 = v1Register({
      publicKeyHex: "aabbcc",
      org: "acme",
      name: "alice",
      nonce: NONCE,
      issuedAtUnix: 1_700_000_000,
    });
    const v2 = registrationChallengeBytesV2({
      publicKeyHex: "aabbcc",
      org: "acme",
      name: "alice",
      nonce: NONCE,
      issuedAtUnix: 1_700_000_000,
    });
    expect(v1).not.toEqual(v2);
    const v1Str = new TextDecoder("utf-8").decode(v1);
    const v2Str = new TextDecoder("utf-8").decode(v2);
    expect(v1Str.startsWith("spize-")).toBe(true);
    expect(v2Str.startsWith("aex-")).toBe(true);
  });
});

describe("wire-v2 deferred decision (ADR-0049)", () => {
  it("decision request canonical bytes are stable", () => {
    const out = decisionRequestBytesV2({
      recipientAgentId: "did:web:acme.com#agent-vendite",
      transferId: "tx_abc123",
      decisionId: "dec_0001",
      etaSeconds: 86_400,
      nonce: NONCE,
      issuedAtUnix: 1_700_000_000,
    });
    const expected = bytes(
      "aex-decision-request:v2\n" +
        "recipient=did:web:acme.com#agent-vendite\n" +
        "transfer=tx_abc123\n" +
        "decision=dec_0001\n" +
        "eta_secs=86400\n" +
        "nonce=0123456789abcdef0123456789abcdef\n" +
        "ts=1700000000",
    );
    expect(out).toEqual(expected);
  });

  it("decision response accepted canonical bytes are stable", () => {
    const out = decisionResponseBytesV2({
      recipientAgentId: "did:web:acme.com#agent-vendite",
      transferId: "tx_abc123",
      decisionId: "dec_0001",
      outcome: "accepted",
      reason: "",
      nonce: NONCE,
      issuedAtUnix: 1_700_000_000,
    });
    const expected = bytes(
      "aex-decision-response:v2\n" +
        "recipient=did:web:acme.com#agent-vendite\n" +
        "transfer=tx_abc123\n" +
        "decision=dec_0001\n" +
        "outcome=accepted\n" +
        "reason=\n" +
        "nonce=0123456789abcdef0123456789abcdef\n" +
        "ts=1700000000",
    );
    expect(out).toEqual(expected);
  });

  it("decision response rejected with reason carries through", () => {
    const out = decisionResponseBytesV2({
      recipientAgentId: "did:web:acme.com#agent-vendite",
      transferId: "tx_abc123",
      decisionId: "dec_0001",
      outcome: "rejected",
      reason: "operator declined: budget exceeded",
      nonce: NONCE,
      issuedAtUnix: 1_700_000_000,
    });
    const s = new TextDecoder("utf-8").decode(out);
    expect(s.startsWith("aex-decision-response:v2\n")).toBe(true);
    expect(s.includes("outcome=rejected\n")).toBe(true);
    expect(s.includes("reason=operator declined: budget exceeded\n")).toBe(true);
  });

  it("rejects bad outcome", () => {
    expect(() =>
      decisionResponseBytesV2({
        recipientAgentId: "did:web:acme.com#agent-vendite",
        transferId: "tx_abc123",
        decisionId: "dec_0001",
        // @ts-expect-error: intentionally bad
        outcome: "maybe",
        reason: "",
        nonce: NONCE,
        issuedAtUnix: 1_700_000_000,
      }),
    ).toThrow();
  });

  it("rejects negative eta", () => {
    expect(() =>
      decisionRequestBytesV2({
        recipientAgentId: "did:web:acme.com#agent-vendite",
        transferId: "tx_abc123",
        decisionId: "dec_0001",
        etaSeconds: -1,
        nonce: NONCE,
        issuedAtUnix: 1_700_000_000,
      }),
    ).toThrow();
  });

  it("rejects newline in decision id", () => {
    expect(() =>
      decisionRequestBytesV2({
        recipientAgentId: "did:web:acme.com#agent-vendite",
        transferId: "tx_abc123",
        decisionId: "dec\n0001",
        etaSeconds: 60,
        nonce: NONCE,
        issuedAtUnix: 1_700_000_000,
      }),
    ).toThrow();
  });

  it("request and response with same fields produce different bytes", () => {
    const req = decisionRequestBytesV2({
      recipientAgentId: "did:web:acme.com#x",
      transferId: "tx_1",
      decisionId: "dec_1",
      etaSeconds: 60,
      nonce: NONCE,
      issuedAtUnix: 1_700_000_000,
    });
    const resp = decisionResponseBytesV2({
      recipientAgentId: "did:web:acme.com#x",
      transferId: "tx_1",
      decisionId: "dec_1",
      outcome: "accepted",
      reason: "",
      nonce: NONCE,
      issuedAtUnix: 1_700_000_000,
    });
    expect(req).not.toEqual(resp);
  });
});

describe("wire-v2 clock-skew helper", () => {
  it("accepts inside the 60-second window", () => {
    const now = 1_700_000_000;
    expect(isWithinClockSkewV2(now, now)).toBe(true);
    expect(isWithinClockSkewV2(now, now - 60)).toBe(true);
    expect(isWithinClockSkewV2(now, now + 60)).toBe(true);
  });

  it("rejects outside the 60-second window", () => {
    const now = 1_700_000_000;
    expect(isWithinClockSkewV2(now, now - 61)).toBe(false);
    expect(isWithinClockSkewV2(now, now + 61)).toBe(false);
  });

  it("symmetric", () => {
    expect(isWithinClockSkewV2(1_000_000, 1_000_030)).toBe(
      isWithinClockSkewV2(1_000_030, 1_000_000),
    );
  });
});
