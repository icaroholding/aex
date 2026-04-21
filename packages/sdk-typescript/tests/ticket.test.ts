import { describe, expect, it } from "vitest";

import { ticketAsHeader, type DataPlaneTicket } from "../src/client.js";

describe("ticketAsHeader", () => {
  it("encodes a ticket in the canonical key order", () => {
    const ticket: DataPlaneTicket = {
      transfer_id: "tx_abc123",
      recipient: "spize:acme/bob:ddeeff",
      data_plane_url: "https://alice.trycloudflare.com",
      expires: 1_700_000_100,
      nonce: "0123456789abcdef0123456789abcdef",
      signature: "aa".repeat(64),
    };
    const header = ticketAsHeader(ticket);
    expect(header).toBe(
      '{"transfer_id":"tx_abc123","recipient":"spize:acme/bob:ddeeff",' +
        '"data_plane_url":"https://alice.trycloudflare.com",' +
        '"expires":1700000100,' +
        '"nonce":"0123456789abcdef0123456789abcdef",' +
        `"signature":"${"aa".repeat(64)}"}`,
    );
  });

  it("round-trips through JSON.parse", () => {
    const ticket: DataPlaneTicket = {
      transfer_id: "tx_rt",
      recipient: "spize:acme/bob:ddeeff",
      data_plane_url: "https://x.trycloudflare.com",
      expires: 42,
      nonce: "a".repeat(32),
      signature: "b".repeat(128),
    };
    const parsed = JSON.parse(ticketAsHeader(ticket));
    expect(parsed).toEqual(ticket);
  });
});
