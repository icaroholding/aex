-- Transfer orchestration tables.
--
-- state machine:
--     awaiting_scan → ready_for_pickup → accepted → delivered
--                 \→ rejected
--
-- For M1 we collapse the scan into the create-transfer request, so
-- `awaiting_scan` exists only briefly during the request's own lifetime
-- and is never observed via the API. Phase D (data plane) splits upload
-- and scan into separate HTTP round-trips and that state becomes visible.

CREATE TABLE transfers (
    id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    transfer_id         TEXT        NOT NULL UNIQUE,

    sender_agent_id     TEXT        NOT NULL,
    -- Opaque recipient address as submitted. Format depends on recipient_kind.
    recipient           TEXT        NOT NULL,
    recipient_kind      TEXT        NOT NULL,  -- spize_native|did|human_bridge|unknown

    -- Lifecycle.
    state               TEXT        NOT NULL,  -- state enum above
    size_bytes          BIGINT      NOT NULL,
    declared_mime       TEXT,
    filename            TEXT,

    -- Blob metadata (data plane handles the bytes themselves).
    blob_sha256         TEXT,
    blob_path           TEXT,

    -- Verdicts + decisions captured for audit trail replay.
    scanner_verdict     JSONB,
    policy_decision     JSONB,

    -- Timestamps per state transition.
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    scanned_at          TIMESTAMPTZ,
    accepted_at         TIMESTAMPTZ,
    delivered_at        TIMESTAMPTZ,
    rejected_at         TIMESTAMPTZ,
    rejection_code      TEXT,
    rejection_reason    TEXT
);

CREATE INDEX idx_transfers_sender    ON transfers (sender_agent_id);
CREATE INDEX idx_transfers_recipient ON transfers (recipient);
CREATE INDEX idx_transfers_state     ON transfers (state);
CREATE INDEX idx_transfers_created   ON transfers (created_at DESC);

-- Per-agent intent nonce replay protection (mirrors registration nonces).
CREATE TABLE transfer_intent_nonces (
    nonce       TEXT        PRIMARY KEY,
    agent_id    TEXT        NOT NULL,
    consumed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
