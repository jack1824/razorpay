-- 0007 — Decision records. Append-only, hash-chained, signed. The emitted intent receipt.
--
-- ── Why seq is BIGINT and not BIGSERIAL (ADR 0001, Q4) ──────────────────────────────
--
-- The strategy package specifies `seq BIGSERIAL NOT NULL UNIQUE`. That breaks the chain
-- by construction, and it would have broken it on day 6 rather than in a way anyone
-- noticed on day 2:
--
--   * BIGSERIAL allocates OUTSIDE transaction control. With `uvicorn --workers 4`,
--     two concurrent inserts take seq=N and seq=N+1 and may commit in either order.
--     Whichever computed prev_hash first computed it against a predecessor that is not
--     yet visible, or against one that a rollback erased.
--   * A rolled-back transaction consumes its sequence value permanently. prev_hash must
--     equal the payload_hash of seq-1; a gap makes that record unverifiable forever.
--
-- seq is therefore allocated explicitly as max(seq)+1 INSIDE
-- pg_advisory_xact_lock(hashtext(merchant_id)), held for the whole transaction. See
-- dwaar/db/repositories/decision_records.py.
--
-- ── Why the chain is per-merchant ───────────────────────────────────────────────────
--
-- A single global chain means one advisory lock for every decision in the system. Keying
-- the lock on merchant_id shards the chain at no extra cost: the verifier iterates chains
-- instead of walking one. With a single merchant in the demo the two are indistinguishable,
-- and the honest answer to "does this scale" becomes "it is already sharded by merchant"
-- rather than a promise to shard later.
--
-- merchant_id is not in the strategy package's schema. Without it there is no key to shard
-- on and no way for the verifier to enumerate chains.

CREATE TABLE decision_records (
    record_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    merchant_id     TEXT        NOT NULL,
    seq             BIGINT      NOT NULL,     -- explicit; NEVER a sequence. See above.
    prev_hash       BYTEA       NOT NULL,     -- genesis = 32 zero bytes
    payload_hash    BYTEA       NOT NULL,     -- [DERIVED]
    signature       BYTEA       NOT NULL,     -- Dwaar's Ed25519 signature
    signing_key_id  TEXT        NOT NULL REFERENCES signing_keys(key_id),
    agent_id        TEXT        NOT NULL,
    principal_id    TEXT        NOT NULL,
    mandate_hash    BYTEA       NOT NULL,
    request_digest  BYTEA       NOT NULL,
    decision        TEXT        NOT NULL
                    CHECK (decision IN ('allow','bound','throttle','step_up','deny')),
    rule_fired      TEXT,

    -- NULLABLE ON PURPOSE, and the nullability is a feature.
    -- When a budget breach is denied, the model is never consulted and this stays NULL.
    -- That NULL is the audit-trail proof the limit was enforced by arithmetic rather than
    -- inferred by a score. Point at it in Q&A.
    risk_score      NUMERIC(5,4) CHECK (risk_score IS NULL OR (risk_score >= 0 AND risk_score <= 1)),

    injection_flag  BOOLEAN     NOT NULL DEFAULT false,
    amount_paise    BIGINT,
    budget_before   BIGINT,
    budget_after    BIGINT,
    features        JSONB       NOT NULL,     -- feature VALUES used, for exact replay
    policy_version  INT         NOT NULL,
    latency_us      INT         NOT NULL CHECK (latency_us >= 0),
    degraded_mode   TEXT,                     -- e.g. 'risk_model_unavailable'
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- The chain's identity: one seq per merchant. Also the index the tail lookup uses.
    CONSTRAINT decision_records_chain_unique UNIQUE (merchant_id, seq),
    CONSTRAINT decision_records_seq_positive CHECK (seq >= 1),

    CONSTRAINT decision_records_prev_hash_len   CHECK (octet_length(prev_hash)      = 32),
    CONSTRAINT decision_records_payload_len     CHECK (octet_length(payload_hash)   = 32),
    CONSTRAINT decision_records_mandate_len     CHECK (octet_length(mandate_hash)   = 32),
    CONSTRAINT decision_records_digest_len      CHECK (octet_length(request_digest) = 32),
    CONSTRAINT decision_records_signature_len   CHECK (octet_length(signature)      = 64)
);

CREATE INDEX idx_decisions_agent_time ON decision_records(agent_id, created_at DESC);
CREATE INDEX idx_decisions_decision   ON decision_records(decision);

COMMENT ON COLUMN decision_records.risk_score IS
    'NULL when the decision was deterministic and the model was never consulted. That '
    'NULL is the audit-trail proof the limit was enforced by arithmetic, not inferred.';

COMMENT ON COLUMN decision_records.seq IS
    'Allocated as max(seq)+1 under pg_advisory_xact_lock(hashtext(merchant_id)). NEVER a '
    'sequence: BIGSERIAL allocates outside transaction control and would gap the chain on '
    'any rollback and reorder it under concurrent workers. See ADR 0001 Q4.';

-- APPEND-ONLY IS ENFORCED IN 0009 BY ROLE GRANT, NOT HERE AND NOT BY A TRIGGER.
--
-- The strategy package writes `REVOKE UPDATE, DELETE ON decision_records FROM PUBLIC`.
-- That is a no-op: PUBLIC holds no table-level UPDATE/DELETE to begin with, and REVOKE
-- never strips the table OWNER, who keeps every privilege unconditionally. If the API
-- connects as the owner the table is fully mutable and the control is fiction.
--
-- A BEFORE UPDATE trigger is also deliberately absent. It would block a superuser too,
-- and a superuser MUST be able to tamper: the control being demonstrated is detection by
-- cryptography, not prevention by DBMS. An append-only log that only stops its own
-- application from editing it proves nothing about an attacker who owns the database.
-- Preventing the tamper would destroy the only evidence that the detection works.
