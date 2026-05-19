/**
 * Wire v2 canonical bytes for AEX (ADR-0042).
 *
 * MUST produce byte-for-byte identical output to:
 *   - Rust: `aex_core::wire_v2::*`
 *   - Python: `aex_sdk.wire_v2.*`
 *
 * Golden vectors are pinned by `tests/wire-v2.test.ts` against the same
 * inputs used by the Rust `wire_v2::tests::*_stable` and the Python
 * `test_wire_v2.py` cases. Drift in any one implementation fails CI in
 * all three.
 *
 * Differences from v1 (see `wire.ts`):
 *   - Prefix is `aex-<msg>:v2` (brand-neutral) instead of
 *     `spize-<msg>:v1`. ADR-0042.
 *   - Clock-skew window is 60 s instead of 300. ADR-0044.
 *   - `agentId` values inside payloads are W3C DID URIs
 *     (`did:method:specific-id[#fragment]`). Legacy `spize:` ids are
 *     still accepted at the wire layer during the v1→v2 grace window
 *     (ADR-0043).
 */

export const PROTOCOL_VERSION_V2 = "v2";
export const MAX_CLOCK_SKEW_SECS_V2 = 60;
export const MIN_NONCE_LEN = 32;
export const MAX_NONCE_LEN = 128;

const ENCODER = new TextEncoder();

function validateAsciiLine(
  s: string,
  field: string,
  { allowEmpty = false }: { allowEmpty?: boolean } = {},
): void {
  if (s.length === 0) {
    if (allowEmpty) return;
    throw new Error(`${field} is empty`);
  }
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i);
    if (code > 0x7f || code === 0x0a || code === 0x0d || code === 0x00) {
      throw new Error(`${field} has invalid char at ${i}: ${s[i]}`);
    }
  }
}

function validateNonce(nonce: string): void {
  if (nonce.length < MIN_NONCE_LEN || nonce.length > MAX_NONCE_LEN) {
    throw new Error(
      `nonce length ${nonce.length} outside [${MIN_NONCE_LEN}, ${MAX_NONCE_LEN}]`,
    );
  }
  if (!/^[0-9a-fA-F]+$/.test(nonce)) {
    throw new Error("nonce must be hex");
  }
}

/** True iff `|now − issuedAt| ≤ 60`. Overflow-safe under JS number range. */
export function isWithinClockSkewV2(
  nowUnix: number,
  issuedAtUnix: number,
): boolean {
  // JS numbers handle the full int64 range adequately at second
  // precision; no special saturation needed for realistic Unix
  // timestamps.
  return Math.abs(nowUnix - issuedAtUnix) <= MAX_CLOCK_SKEW_SECS_V2;
}

export function registrationChallengeBytesV2(args: {
  publicKeyHex: string;
  org: string;
  name: string;
  nonce: string;
  issuedAtUnix: number;
}): Uint8Array {
  validateAsciiLine(args.publicKeyHex, "public_key_hex");
  validateAsciiLine(args.org, "org");
  validateAsciiLine(args.name, "name");
  validateNonce(args.nonce);
  return ENCODER.encode(
    `aex-register:${PROTOCOL_VERSION_V2}\n` +
      `pub=${args.publicKeyHex}\n` +
      `org=${args.org}\n` +
      `name=${args.name}\n` +
      `nonce=${args.nonce}\n` +
      `ts=${args.issuedAtUnix}`,
  );
}

export function transferIntentBytesV2(args: {
  senderAgentId: string;
  recipient: string;
  sizeBytes: number | bigint;
  declaredMime: string;
  filename: string;
  nonce: string;
  issuedAtUnix: number;
}): Uint8Array {
  validateAsciiLine(args.senderAgentId, "sender_agent_id");
  validateAsciiLine(args.recipient, "recipient");
  validateAsciiLine(args.declaredMime, "declared_mime", { allowEmpty: true });
  validateAsciiLine(args.filename, "filename", { allowEmpty: true });
  validateNonce(args.nonce);
  return ENCODER.encode(
    `aex-transfer-intent:${PROTOCOL_VERSION_V2}\n` +
      `sender=${args.senderAgentId}\n` +
      `recipient=${args.recipient}\n` +
      `size=${args.sizeBytes}\n` +
      `mime=${args.declaredMime}\n` +
      `filename=${args.filename}\n` +
      `nonce=${args.nonce}\n` +
      `ts=${args.issuedAtUnix}`,
  );
}

export function dataTicketBytesV2(args: {
  transferId: string;
  recipientAgentId: string;
  dataPlaneUrl: string;
  expiresUnix: number;
  nonce: string;
}): Uint8Array {
  validateAsciiLine(args.transferId, "transfer_id");
  validateAsciiLine(args.recipientAgentId, "recipient_agent_id");
  validateAsciiLine(args.dataPlaneUrl, "data_plane_url");
  validateNonce(args.nonce);
  return ENCODER.encode(
    `aex-data-ticket:${PROTOCOL_VERSION_V2}\n` +
      `transfer=${args.transferId}\n` +
      `recipient=${args.recipientAgentId}\n` +
      `data_plane=${args.dataPlaneUrl}\n` +
      `expires=${args.expiresUnix}\n` +
      `nonce=${args.nonce}`,
  );
}

export function rotateKeyChallengeBytesV2(args: {
  agentId: string;
  oldPublicKeyHex: string;
  newPublicKeyHex: string;
  nonce: string;
  issuedAtUnix: number;
}): Uint8Array {
  validateAsciiLine(args.agentId, "agent_id");
  validateAsciiLine(args.oldPublicKeyHex, "old_public_key_hex");
  validateAsciiLine(args.newPublicKeyHex, "new_public_key_hex");
  validateNonce(args.nonce);
  if (args.oldPublicKeyHex === args.newPublicKeyHex) {
    throw new Error("old_public_key_hex and new_public_key_hex must differ");
  }
  return ENCODER.encode(
    `aex-rotate-key:${PROTOCOL_VERSION_V2}\n` +
      `agent=${args.agentId}\n` +
      `old_pub=${args.oldPublicKeyHex}\n` +
      `new_pub=${args.newPublicKeyHex}\n` +
      `nonce=${args.nonce}\n` +
      `ts=${args.issuedAtUnix}`,
  );
}

export type ReceiptActionV2 = "download" | "ack" | "inbox" | "request_ticket";

const RECEIPT_ACTIONS_V2: readonly ReceiptActionV2[] = [
  "download",
  "ack",
  "inbox",
  "request_ticket",
];

export function transferReceiptBytesV2(args: {
  recipientAgentId: string;
  transferId: string;
  action: ReceiptActionV2;
  nonce: string;
  issuedAtUnix: number;
}): Uint8Array {
  validateAsciiLine(args.recipientAgentId, "recipient_agent_id");
  validateAsciiLine(args.transferId, "transfer_id");
  validateAsciiLine(args.action, "action");
  validateNonce(args.nonce);
  if (!RECEIPT_ACTIONS_V2.includes(args.action)) {
    throw new Error(
      `action must be one of ${RECEIPT_ACTIONS_V2.join(", ")}, got ${args.action}`,
    );
  }
  return ENCODER.encode(
    `aex-transfer-receipt:${PROTOCOL_VERSION_V2}\n` +
      `recipient=${args.recipientAgentId}\n` +
      `transfer=${args.transferId}\n` +
      `action=${args.action}\n` +
      `nonce=${args.nonce}\n` +
      `ts=${args.issuedAtUnix}`,
  );
}
