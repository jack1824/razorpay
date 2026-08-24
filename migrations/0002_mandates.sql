-- 0002 — Mandates. The mandate IS the intent receipt.
--
-- Signed by the principal BEFORE any purchase. That temporal ordering is the entire
-- cryptographic contribution: a mandate cannot be retrofitted to an outcome.
--
-- canonical_json is the RFC 8785 (JCS) serialisation that was actually signed. It is
-- stored verbatim rather than re-derived, because re-deriving it means re-implementing
-- JCS at verification time and any divergence silently invalidates every signature.
--
-- Per ADR 0001 item 9: the signed object always carries all ten mandate keys with
-- defaults materialised ([], [], 'none'). Under JCS an absent key and an empty array
-- hash differently, so "omit if default" would have given one mandate two valid hashes.

CREATE TABLE mandates (
    mandate_id             TEXT PRIMARY KEY,
    principal_id           TEXT        NOT NULL REFERENCES principals(principal_id),
    agent_id               TEXT        NOT NULL REFERENCES agents(agent_id),
    max_total_paise        BIGINT      NOT NULL CHECK (max_total_paise   > 0),
    max_per_txn_paise      BIGINT      NOT NULL CHECK (max_per_txn_paise > 0),
    allow_categories       TEXT[]      NOT NULL DEFAULT '{}',
    deny_categories        TEXT[]      NOT NULL DEFAULT '{}',
    substitution_tolerance TEXT        NOT NULL DEFAULT 'none'
                           CHECK (substitution_tolerance IN ('none','same_price','similar')),
    expires_at             TIMESTAMPTZ NOT NULL,
    nonce                  TEXT        NOT NULL UNIQUE,    -- replay defence, per mandate
    canonical_json         TEXT        NOT NULL,           -- RFC 8785 JCS, exactly as signed
    signature              BYTEA       NOT NULL,           -- principal's Ed25519 signature
    mandate_hash           BYTEA       NOT NULL,           -- [DERIVED] sha256(canonical_json)
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at             TIMESTAMPTZ,

    CHECK (max_per_txn_paise <= max_total_paise),
    CONSTRAINT mandates_signature_len    CHECK (octet_length(signature) = 64),
    CONSTRAINT mandates_hash_len         CHECK (octet_length(mandate_hash) = 32)
);

CREATE INDEX idx_mandates_agent_active ON mandates(agent_id, expires_at)
    WHERE revoked_at IS NULL;

CREATE INDEX idx_mandates_principal ON mandates(principal_id);

-- mandate_hash is the join key from decision_records back to the authority that was
-- exercised. The verifier uses it, so it needs to be findable.
CREATE INDEX idx_mandates_hash ON mandates(mandate_hash);
