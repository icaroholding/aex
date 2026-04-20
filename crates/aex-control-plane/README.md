# aex-control-plane

HTTP server for the Agent Exchange Protocol (AEX). Coordinates identity, routing, policy, scanner verdicts, and audit. File bytes never touch this server — that is the data plane's job.

## Run locally

```sh
# 1. Start Postgres
docker compose -f ../../deploy/docker-compose.dev.yml up -d

# 2. Export env (or copy ../../.env.example to ../../.env)
export DATABASE_URL=postgres://spize:spize_dev@localhost:5432/spize
export BIND_ADDR=127.0.0.1:8080

# 3. Run
cargo run -p aex-control-plane
```

## Endpoints

### `GET /healthz`

Liveness + version.

### `POST /v1/agents/register`

Register a new agent. The client must hold the private key and prove it by signing a canonical challenge.

**Request body:**

```json
{
  "public_key_hex": "<64 hex chars, Ed25519 pubkey>",
  "org":            "acme",
  "name":           "alice",
  "nonce":          "<32-128 hex chars>",
  "issued_at":      1700000000,
  "signature_hex":  "<128 hex chars, Ed25519 sig over canonical challenge>"
}
```

The canonical challenge bytes are defined in
[`spize_core::wire::registration_challenge_bytes`](../aex-core/src/wire.rs)
and must be computed identically on both client and server.

**Responses:**

| Status | Meaning |
|--------|---------|
| 201    | Registered. Body contains `agent_id`, derived `fingerprint`, and `created_at`. |
| 400    | Malformed field (bad hex, out-of-range nonce, org/name contains disallowed chars, stale timestamp). |
| 401    | Signature does not verify against the supplied `public_key_hex` + canonical challenge. |
| 409    | Nonce replay, or the public key / agent_id is already registered. |

### `GET /v1/agents/*agent_id`

Resolve an agent_id (e.g. `spize:acme/alice:a4f8b2`) to its public key record. Wildcard route because agent_ids contain `/`.

## Integration tests

Run `cargo test -p aex-control-plane`. Requires `DATABASE_URL` pointing at a running Postgres; `sqlx::test` creates a fresh DB per test and runs migrations automatically.
