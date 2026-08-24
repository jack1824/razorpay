-- 0003 — Budget ledger. Enforcement is arithmetic, never a model score.
--
-- ── Why prev_entry_id exists (ADR 0001, Q2) ─────────────────────────────────────────
--
-- CHECK (balance_after >= 0) alone does NOT prevent overspend. Two concurrent
-- transactions can each read the same tail entry, each compute a balance from it, and
-- each insert a new row that individually satisfies the CHECK. The budget is gone and
-- no constraint fired.
--
-- SELECT ... FOR UPDATE on the tail ledger row does not fix it either: FOR UPDATE locks
-- rows that exist, and the race is two transactions *inserting* new tails. This is a
-- phantom, not a row conflict. docs/strategy/04_SYSTEM_ARCHITECTURE/TECH_STACK.md advises
-- "lock the ledger row, not the mandate" — that advice is wrong against this schema.
--
-- The mechanism is therefore a mandate-row lock (see dwaar/db/repositories/budget_ledger.py).
-- prev_entry_id + UNIQUE (mandate_id, prev_entry_id) is a TRIPWIRE, not the mechanism:
-- under correct locking it can never fire, and if it ever fires the locking is wrong and
-- the database caught it instead of the money silently leaving.
--
-- Caveat worth knowing when reading a failure: PostgreSQL treats NULLs as distinct in a
-- unique index, so the constraint does not constrain genesis rows (prev_entry_id IS NULL).
-- Single-genesis-per-mandate is guaranteed by idempotency_key = 'genesis:'||mandate_id
-- instead. Same guarantee, different constraint.

CREATE TABLE budget_ledger (
    entry_id        BIGSERIAL PRIMARY KEY,
    mandate_id      TEXT   NOT NULL REFERENCES mandates(mandate_id),
    prev_entry_id   BIGINT REFERENCES budget_ledger(entry_id),   -- NULL only for genesis
    delta_paise     BIGINT NOT NULL,                             -- negative = reserve
    balance_after   BIGINT NOT NULL CHECK (balance_after >= 0),  -- HARD INVARIANT
    idempotency_key TEXT   NOT NULL UNIQUE,                      -- duplicate webhook safety
    reason          TEXT   NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- The tripwire.
    CONSTRAINT budget_ledger_chain_unique UNIQUE (mandate_id, prev_entry_id),

    -- A ledger entry must not reference itself as its predecessor.
    CONSTRAINT budget_ledger_no_self_ref CHECK (prev_entry_id IS NULL OR prev_entry_id <> entry_id)
);

CREATE INDEX idx_ledger_mandate ON budget_ledger(mandate_id, entry_id DESC);

COMMENT ON COLUMN budget_ledger.prev_entry_id IS
    'Tripwire for the mandate-row lock (ADR 0001 Q2). Under correct locking the '
    'UNIQUE (mandate_id, prev_entry_id) constraint can never fire. If it does, the '
    'locking is wrong and the database caught an overspend the CHECK would have missed.';
