-- 0006 — Periodic Merkle anchors over the decision chain.
--
-- Bounds the damage window: a tamper is detectable by the chain alone, but an attacker
-- who rewrites a suffix AND re-signs it needs the signing key. Anchors bound how far back
-- such a rewrite could reach without contradicting a published root.
--
-- This is the correct primitive. A blockchain here would be reaching for Byzantine
-- consensus in a system with one writer, which signals not knowing the difference.
--
-- On the cut list (docs/strategy/BUILD_PLAN.md "Cut order if behind", item 3) — the table
-- exists now so that cutting it is a decision not to populate it, not a migration.

CREATE TABLE chain_anchors (
    anchor_id   BIGSERIAL PRIMARY KEY,
    merchant_id TEXT        NOT NULL,
    merkle_root BYTEA       NOT NULL,
    from_seq    BIGINT      NOT NULL,
    to_seq      BIGINT      NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT chain_anchors_range     CHECK (to_seq >= from_seq),
    CONSTRAINT chain_anchors_root_len  CHECK (octet_length(merkle_root) = 32)
);

CREATE INDEX idx_anchors_merchant ON chain_anchors(merchant_id, to_seq DESC);
