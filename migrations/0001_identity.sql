-- 0001 — Identity.
--
-- Rows here are SYNTHETIC (we create the agents); the key material and every signature
-- verification over it is REAL. See docs/strategy/07_DATABASE/DATA_MODEL.md.
--
-- No CREATE EXTENSION pgcrypto: gen_random_uuid() has been core since PostgreSQL 13 and
-- the target is 16. The strategy package's schema.sql still declares it; this repo's
-- schema does not. Recorded in FAILURES.md F-006.

CREATE TABLE agents (
    agent_id            TEXT PRIMARY KEY,
    display_name        TEXT        NOT NULL,
    public_key          BYTEA       NOT NULL,
    registered_by       TEXT        NOT NULL,              -- merchant_id
    status              TEXT        NOT NULL DEFAULT 'active'
                        CHECK (status IN ('active','suspended','revoked')),
    key_rotated_at      TIMESTAMPTZ,
    previous_public_key BYTEA,                             -- rotation overlap window
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Ed25519 public keys are exactly 32 bytes. A wrong-length key is a bug we would
    -- rather catch on insert than on the first signature verification.
    CONSTRAINT agents_public_key_len CHECK (octet_length(public_key) = 32),
    CONSTRAINT agents_prev_key_len
        CHECK (previous_public_key IS NULL OR octet_length(previous_public_key) = 32)
);

CREATE INDEX idx_agents_merchant ON agents(registered_by);

CREATE TABLE principals (
    principal_id  TEXT PRIMARY KEY,
    merchant_id   TEXT        NOT NULL,
    public_key    BYTEA       NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT principals_public_key_len CHECK (octet_length(public_key) = 32)
);

CREATE INDEX idx_principals_merchant ON principals(merchant_id);
