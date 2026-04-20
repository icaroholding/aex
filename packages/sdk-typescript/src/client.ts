import { hex, Identity, randomNonce } from "./identity.js";
import { SpizeError, SpizeHttpError } from "./errors.js";
import {
  registrationChallengeBytes,
  transferIntentBytes,
  transferReceiptBytes,
} from "./wire.js";

export interface SpizeClientOptions {
  baseUrl: string;
  identity: Identity;
  fetch?: typeof globalThis.fetch;
  timeoutMs?: number;
}

export interface AgentResponse {
  agent_id: string;
  public_key_hex: string;
  fingerprint: string;
  org: string;
  name: string;
  created_at: string;
}

export interface TransferResponse {
  transferId: string;
  state:
    | "awaiting_scan"
    | "ready_for_pickup"
    | "accepted"
    | "delivered"
    | "rejected"
    | string;
  senderAgentId: string;
  recipient: string;
  sizeBytes: number;
  declaredMime: string | null;
  filename: string | null;
  scannerVerdict: Record<string, unknown> | null;
  policyDecision: Record<string, unknown> | null;
  rejectionCode: string | null;
  rejectionReason: string | null;
  createdAt: string;

  wasRejected: boolean;
  wasDelivered: boolean;
}

export interface AckResponse {
  transfer_id: string;
  state: string;
  audit_chain_head: string;
}

export interface InboxEntry {
  transfer_id: string;
  sender_agent_id: string;
  state: string;
  size_bytes: number;
  declared_mime: string | null;
  filename: string | null;
  created_at: string;
}

export interface InboxResponse {
  agent_id: string;
  count: number;
  entries: InboxEntry[];
}

function fromTransferJson(body: {
  transfer_id: string;
  state: string;
  sender_agent_id: string;
  recipient: string;
  size_bytes: number;
  declared_mime: string | null;
  filename: string | null;
  scanner_verdict: Record<string, unknown> | null;
  policy_decision: Record<string, unknown> | null;
  rejection_code: string | null;
  rejection_reason: string | null;
  created_at: string;
}): TransferResponse {
  return {
    transferId: body.transfer_id,
    state: body.state,
    senderAgentId: body.sender_agent_id,
    recipient: body.recipient,
    sizeBytes: Number(body.size_bytes),
    declaredMime: body.declared_mime,
    filename: body.filename,
    scannerVerdict: body.scanner_verdict,
    policyDecision: body.policy_decision,
    rejectionCode: body.rejection_code,
    rejectionReason: body.rejection_reason,
    createdAt: body.created_at,
    wasRejected: body.state === "rejected",
    wasDelivered: body.state === "delivered",
  };
}

export class SpizeClient {
  readonly baseUrl: string;
  readonly identity: Identity;
  private readonly _fetch: typeof globalThis.fetch;
  private readonly timeoutMs: number;

  constructor(opts: SpizeClientOptions) {
    this.baseUrl = opts.baseUrl.replace(/\/+$/, "");
    this.identity = opts.identity;
    this._fetch = opts.fetch ?? globalThis.fetch.bind(globalThis);
    this.timeoutMs = opts.timeoutMs ?? 30_000;
  }

  // ---------- health ----------

  async health(): Promise<Record<string, unknown>> {
    return this.getJson("/healthz");
  }

  // ---------- registration ----------

  async register(): Promise<AgentResponse> {
    const issuedAt = Math.floor(Date.now() / 1000);
    const nonce = randomNonce();
    const challenge = registrationChallengeBytes({
      publicKeyHex: this.identity.publicKeyHex,
      org: this.identity.org,
      name: this.identity.name,
      nonce,
      issuedAtUnix: issuedAt,
    });
    const sig = await this.identity.sign(challenge);
    return this.postJson("/v1/agents/register", {
      public_key_hex: this.identity.publicKeyHex,
      org: this.identity.org,
      name: this.identity.name,
      nonce,
      issued_at: issuedAt,
      signature_hex: hex.encode(sig),
    });
  }

  async getAgent(agentId: string): Promise<AgentResponse> {
    return this.getJson(`/v1/agents/${agentId}`);
  }

  // ---------- transfers ----------

  async send(args: {
    recipient: string;
    data: Uint8Array;
    declaredMime?: string;
    filename?: string;
  }): Promise<TransferResponse> {
    const declaredMime = args.declaredMime ?? "";
    const filename = args.filename ?? "";
    const issuedAt = Math.floor(Date.now() / 1000);
    const nonce = randomNonce();
    const canonical = transferIntentBytes({
      senderAgentId: this.identity.agentId,
      recipient: args.recipient,
      sizeBytes: args.data.length,
      declaredMime,
      filename,
      nonce,
      issuedAtUnix: issuedAt,
    });
    const sig = await this.identity.sign(canonical);
    const body = await this.postJson<any>("/v1/transfers", {
      sender_agent_id: this.identity.agentId,
      recipient: args.recipient,
      declared_mime: declaredMime,
      filename,
      nonce,
      issued_at: issuedAt,
      intent_signature_hex: hex.encode(sig),
      blob_hex: hex.encode(args.data),
    });
    return fromTransferJson(body);
  }

  async getTransfer(transferId: string): Promise<TransferResponse> {
    const body = await this.getJson<any>(`/v1/transfers/${transferId}`);
    return fromTransferJson(body);
  }

  async download(transferId: string): Promise<Uint8Array> {
    const body = await this.postJson<{ blob_hex: string }>(
      `/v1/transfers/${transferId}/download`,
      await this.buildReceipt(transferId, "download"),
    );
    return hex.decode(body.blob_hex);
  }

  async ack(transferId: string): Promise<AckResponse> {
    return this.postJson(
      `/v1/transfers/${transferId}/ack`,
      await this.buildReceipt(transferId, "ack"),
    );
  }

  /** List transfers waiting for this identity (state: ready_for_pickup or accepted). */
  async inbox(): Promise<InboxResponse> {
    return this.postJson("/v1/inbox", await this.buildReceipt("inbox", "inbox"));
  }

  private async buildReceipt(
    transferId: string,
    action: "download" | "ack" | "inbox",
  ): Promise<Record<string, unknown>> {
    const issuedAt = Math.floor(Date.now() / 1000);
    const nonce = randomNonce();
    const canonical = transferReceiptBytes({
      recipientAgentId: this.identity.agentId,
      transferId,
      action,
      nonce,
      issuedAtUnix: issuedAt,
    });
    const sig = await this.identity.sign(canonical);
    return {
      recipient_agent_id: this.identity.agentId,
      nonce,
      issued_at: issuedAt,
      signature_hex: hex.encode(sig),
    };
  }

  // ---------- HTTP helpers ----------

  private async getJson<T>(path: string): Promise<T> {
    return this.request<T>(path, { method: "GET" });
  }

  private async postJson<T>(path: string, body: unknown): Promise<T> {
    return this.request<T>(path, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
  }

  private async request<T>(path: string, init: RequestInit): Promise<T> {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), this.timeoutMs);
    try {
      const resp = await this._fetch(`${this.baseUrl}${path}`, {
        ...init,
        signal: ctrl.signal,
      });
      if (!resp.ok) {
        let body: { code?: string; message?: string } = {};
        try {
          body = (await resp.json()) as typeof body;
        } catch {
          /* empty */
        }
        throw new SpizeHttpError(
          resp.status,
          body.code ?? null,
          body.message ?? resp.statusText,
        );
      }
      return (await resp.json()) as T;
    } catch (err) {
      if (err instanceof SpizeError) throw err;
      if (err instanceof Error && err.name === "AbortError") {
        throw new SpizeError(`request timed out after ${this.timeoutMs}ms`);
      }
      throw err;
    } finally {
      clearTimeout(timer);
    }
  }
}
