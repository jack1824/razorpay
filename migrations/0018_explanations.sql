-- 0018 — The async explainer's table, and the role that proves it cannot decide anything.
--
-- WHY THE ROLE IS THE INTERESTING PART
--
-- "The explainer is off the decision path" is a claim, and a claim about an LLM near money
-- is the claim a judge should press hardest on. It is currently supported by three things —
-- the import-closure test, the runtime no-LLM test, and the fact that it consumes a queue —
-- and all three are properties of the CODE. Code changes.
--
-- A third database role does not. `dwaar_explainer` gets SELECT on `decision_records` and
-- INSERT on `explanations`, and nothing else. It cannot INSERT a decision record, cannot
-- UPDATE one, cannot touch `budget_ledger` or `mandates`, and — like `dwaar_app` — owns
-- nothing, so a REVOKE against it actually means something.
--
-- The explainer reads a record that has already been written, signed and chained. There is
-- no ordering in which it could alter a decision, because the decision was durable before
-- the explainer could see it. The role is what makes that a property rather than a promise.
--
-- Demo beat 5 is `docker kill dwaar-llm-explainer` and decisions continuing unchanged. This
-- is the reason that beat is boring, and it should be boring.

CREATE TABLE explanations (
    explanation_id  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    record_id       UUID        NOT NULL REFERENCES decision_records(record_id),
    merchant_id     TEXT        NOT NULL,
    seq             BIGINT      NOT NULL,

    -- The cache key. Two denials for the same rule, decision and risk band get the same
    -- text, so a burst of 30 card-testing denials is ONE model call. Stored on the row so a
    -- reader can see which explanation was reused rather than inferring it.
    cache_key       TEXT        NOT NULL,
    body            TEXT        NOT NULL,
    model           TEXT,
    -- NULL means the model was never called: the text came from the cache or from the
    -- deterministic fallback. Same tristate discipline as `injection_flag` — "generated"
    -- and "reused" are different facts and a reader should not have to infer which.

    cached          BOOLEAN     NOT NULL DEFAULT false,
    generated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- One explanation per record. A retried stream message must not produce a second.
    CONSTRAINT explanations_record_unique UNIQUE (record_id)
);

CREATE INDEX idx_explanations_chain ON explanations(merchant_id, seq DESC);
CREATE INDEX idx_explanations_cache ON explanations(cache_key);

COMMENT ON TABLE explanations IS
    'Merchant-readable text for a decision that was ALREADY written, signed and chained. '
    'Written by dwaar_explainer, which holds SELECT on decision_records and INSERT here and '
    'nothing else. Killing the process that writes this table changes no decision — see '
    'migration 0018 and FAIL_MATRIX.md.';

-- The app role reads them for the console. It does not write them: the explainer does.
GRANT SELECT ON explanations TO dwaar_app;

-- ── dwaar_explainer ─────────────────────────────────────────────────────────────────
--
-- Created by the init scripts (CREATE ROLE is cluster-level and migrations run as the
-- owner). Guarded so a database bootstrapped before this migration still applies it — the
-- grants below are then skipped rather than failing the whole migration, and
-- `tests/db/test_explainer_isolation.py` reports the role as absent rather than passing
-- vacuously.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dwaar_explainer') THEN
        EXECUTE 'GRANT USAGE ON SCHEMA public TO dwaar_explainer';
        EXECUTE 'GRANT SELECT ON decision_records TO dwaar_explainer';
        EXECUTE 'GRANT SELECT, INSERT ON explanations TO dwaar_explainer';

        -- Stated as revocations so the absence is a decision rather than an omission.
        -- Nothing here was granted; these run anyway, for the reason migration 0009 gives.
        EXECUTE 'REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON decision_records FROM dwaar_explainer';
        EXECUTE 'REVOKE ALL ON budget_ledger  FROM dwaar_explainer';
        EXECUTE 'REVOKE ALL ON mandates       FROM dwaar_explainer';
        EXECUTE 'REVOKE ALL ON policies       FROM dwaar_explainer';
        EXECUTE 'REVOKE ALL ON agents         FROM dwaar_explainer';
        EXECUTE 'REVOKE ALL ON principals     FROM dwaar_explainer';
        EXECUTE 'REVOKE ALL ON signing_keys   FROM dwaar_explainer';
        EXECUTE 'REVOKE UPDATE, DELETE ON explanations FROM dwaar_explainer';
        EXECUTE 'REVOKE CREATE ON SCHEMA public FROM dwaar_explainer';
    ELSE
        RAISE NOTICE 'dwaar_explainer role absent; grants skipped. Run scripts/init-db/local-bootstrap.sh.';
    END IF;
END
$$;
