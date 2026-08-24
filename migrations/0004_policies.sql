-- 0004 — Policies. Compiled offline by an LLM, tested, human-approved, signed.
--
-- approved_by NULL means NOT LIVE. That is the human gate: an LLM compiles the rules,
-- generated property tests must pass, and a person puts their name on it before it can
-- decide anything about money. Compilation is a build-time activity — nothing in this
-- table is written by a request path.

CREATE TABLE policies (
    policy_id       TEXT PRIMARY KEY,
    merchant_id     TEXT        NOT NULL,
    version         INT         NOT NULL,
    source_nl       TEXT        NOT NULL,     -- the merchant's English
    compiled_rules  JSONB       NOT NULL,     -- rule DSL
    generated_tests JSONB       NOT NULL,     -- LLM-written property tests
    tests_passed    BOOLEAN     NOT NULL DEFAULT false,
    approved_by     TEXT,                     -- human gate; NULL = not live
    signature       BYTEA,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),

    UNIQUE (merchant_id, version),

    -- A policy cannot be approved without its generated tests having passed. This is the
    -- gate that stops "approve it, we'll fix the tests after the demo".
    CONSTRAINT policies_approved_implies_tested
        CHECK (approved_by IS NULL OR tests_passed IS TRUE),
    CONSTRAINT policies_signature_len
        CHECK (signature IS NULL OR octet_length(signature) = 64)
);

CREATE INDEX idx_policies_live ON policies(merchant_id, version DESC)
    WHERE approved_by IS NOT NULL;
