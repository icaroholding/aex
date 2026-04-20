-- Agent Exchange Protocol (AEX) — agents table.
--
-- Stores public key registrations. Private keys NEVER touch this database —
-- clients generate keypairs locally and publish only the public half here.
-- The agent_id is derived server-side from the public key to prevent
-- client-side forgery of canonical identifiers.

CREATE TABLE agents (
    -- Internal surrogate key. Not exposed on the API.
    id              UUID            PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Canonical agent identifier, e.g. `spize:acme/alice:a4f8b2`.
    -- Derived from (org, name, public_key) by the server.
    agent_id        TEXT            NOT NULL UNIQUE,

    -- Raw Ed25519 public key, 32 bytes. Indexed UNIQUE to guarantee
    -- one-key-one-agent: the same public key cannot register under two
    -- different (org, name) tuples.
    public_key      BYTEA           NOT NULL UNIQUE,

    -- First 3 bytes of SHA-256(public_key), hex-encoded. Denormalized for
    -- fast lookup-by-fingerprint.
    fingerprint     TEXT            NOT NULL,

    -- Org and human-facing agent name, parsed back out of agent_id. Stored
    -- separately for filtering without string parsing.
    org             TEXT            NOT NULL,
    name            TEXT            NOT NULL,

    created_at      TIMESTAMPTZ     NOT NULL DEFAULT now(),

    -- Future revocation support. NULL = active.
    revoked_at      TIMESTAMPTZ
);

CREATE INDEX idx_agents_org      ON agents (org);
CREATE INDEX idx_agents_fingerprint ON agents (fingerprint);

-- Registration nonces — one-shot replay protection.
--
-- Any nonce the server has seen before is rejected, even if the timestamp
-- is fresh. Rows are pruned periodically by a maintenance job (not yet
-- implemented); for now we rely on UNIQUE to reject replays indefinitely.
CREATE TABLE registration_nonces (
    nonce           TEXT            PRIMARY KEY,
    public_key      BYTEA           NOT NULL,
    consumed_at     TIMESTAMPTZ     NOT NULL DEFAULT now()
);
