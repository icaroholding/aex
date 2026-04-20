import * as ed from "@noble/ed25519";
import { sha256 } from "@noble/hashes/sha2";
import { randomBytes } from "node:crypto";

import { IdentityError } from "./errors.js";

const LABEL_RE = /^[a-zA-Z0-9_-]{1,64}$/;

function validateLabel(s: string, field: string): void {
  if (!LABEL_RE.test(s)) {
    throw new IdentityError(`${field} must match [a-zA-Z0-9_-]{1,64}: got "${s}"`);
  }
}

function toHex(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) {
    s += b.toString(16).padStart(2, "0");
  }
  return s;
}

function fromHex(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new Error(`odd-length hex: ${hex.length}`);
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) {
      throw new Error(`bad hex at ${i * 2}`);
    }
    out[i] = byte;
  }
  return out;
}

/** First 3 bytes of SHA-256 over the public key, hex-encoded. */
function computeFingerprint(publicKey: Uint8Array): string {
  const digest = sha256(publicKey);
  return toHex(digest.slice(0, 3));
}

export interface IdentityInit {
  org: string;
  name: string;
  privateKey: Uint8Array; // 32 bytes
  publicKey: Uint8Array; // 32 bytes
}

export class Identity {
  readonly org: string;
  readonly name: string;
  readonly privateKey: Uint8Array;
  readonly publicKey: Uint8Array;

  private constructor(init: IdentityInit) {
    this.org = init.org;
    this.name = init.name;
    this.privateKey = init.privateKey;
    this.publicKey = init.publicKey;
    Object.freeze(this);
  }

  /** Generate a fresh keypair. */
  static async generate(args: { org: string; name: string }): Promise<Identity> {
    validateLabel(args.org, "org");
    validateLabel(args.name, "name");
    const privateKey = ed.utils.randomPrivateKey();
    const publicKey = await ed.getPublicKeyAsync(privateKey);
    return new Identity({
      org: args.org,
      name: args.name,
      privateKey,
      publicKey,
    });
  }

  /** Load from an existing 32-byte secret. */
  static async fromSecret(args: {
    org: string;
    name: string;
    privateKey: Uint8Array;
  }): Promise<Identity> {
    validateLabel(args.org, "org");
    validateLabel(args.name, "name");
    if (args.privateKey.length !== 32) {
      throw new IdentityError(
        `Ed25519 secret must be 32 bytes, got ${args.privateKey.length}`,
      );
    }
    const publicKey = await ed.getPublicKeyAsync(args.privateKey);
    return new Identity({
      org: args.org,
      name: args.name,
      privateKey: args.privateKey,
      publicKey,
    });
  }

  get fingerprint(): string {
    return computeFingerprint(this.publicKey);
  }

  get agentId(): string {
    return `spize:${this.org}/${this.name}:${this.fingerprint}`;
  }

  get publicKeyHex(): string {
    return toHex(this.publicKey);
  }

  get privateKeyHex(): string {
    return toHex(this.privateKey);
  }

  async sign(message: Uint8Array): Promise<Uint8Array> {
    return ed.signAsync(message, this.privateKey);
  }

  /** Serialise to a JSON-safe plain object. */
  toJSON(): {
    version: 1;
    org: string;
    name: string;
    privateKeyHex: string;
    publicKeyHex: string;
    agentId: string;
  } {
    return {
      version: 1,
      org: this.org,
      name: this.name,
      privateKeyHex: this.privateKeyHex,
      publicKeyHex: this.publicKeyHex,
      agentId: this.agentId,
    };
  }

  /** Parse an object previously returned by `toJSON`. */
  static async fromJSON(obj: {
    version: number;
    org: string;
    name: string;
    privateKeyHex: string;
    publicKeyHex?: string;
    agentId?: string;
  }): Promise<Identity> {
    if (obj.version !== 1) {
      throw new IdentityError(`unsupported identity version: ${obj.version}`);
    }
    const identity = await Identity.fromSecret({
      org: obj.org,
      name: obj.name,
      privateKey: fromHex(obj.privateKeyHex),
    });
    if (obj.publicKeyHex && obj.publicKeyHex !== identity.publicKeyHex) {
      throw new IdentityError(
        "stored publicKeyHex does not match derived public key",
      );
    }
    if (obj.agentId && obj.agentId !== identity.agentId) {
      throw new IdentityError(
        "stored agentId does not match derived agent_id",
      );
    }
    return identity;
  }
}

export function randomNonce(byteLength = 16): string {
  return toHex(randomBytes(byteLength));
}

export async function verifySignature(
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): Promise<boolean> {
  try {
    return await ed.verifyAsync(signature, message, publicKey);
  } catch {
    return false;
  }
}

export const hex = { encode: toHex, decode: fromHex };
