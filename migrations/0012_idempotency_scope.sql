-- 0012 — Scope idempotency to the mandate, and give decision_records its own key.
--
-- Three defects, one migration.
--
-- ── (a) Global uniqueness was a cross-tenant denial of service ──────────────────────
--
-- `idempotency_key TEXT NOT NULL UNIQUE` is global. The key is supplied by the agent, and
-- the agent is untrusted. So agent A could burn a key belonging to agent B on a completely
-- different mandate: B's request fails as a duplicate and receives A's outcome. It is also
-- an oracle — A learns whether B is using a given key.
--
-- The ledger is per-mandate and a mandate binds one agent to one principal, so the mandate
-- is the correct scope. Two mandates held by the same agent are separate budgets and
-- separate authorities; the same client key on both legitimately produces two entries.
--
-- ── (b) decision_records could mint phantom records ─────────────────────────────────
--
-- A replayed authorize deduped at the LEDGER and still wrote a second chained record. Two
-- records for one logical decision breaks any one-decision-one-record claim and pollutes
-- the evidence chain with entries that describe nothing that happened twice.
--
-- ── (c) Client keys could forge a server namespace ──────────────────────────────────
--
-- Enforced in `dwaar/idempotency.py`, not here, because it is a derivation rule rather
-- than a constraint: every client key is stored prefixed `rsv:`, so an agent submitting
-- `release:1234` cannot collide with the real release of entry 1234 — which would have
-- silently no-opped that release and leaked the reservation permanently.

-- ── budget_ledger: mandate-scoped uniqueness ────────────────────────────────────────
ALTER TABLE budget_ledger DROP CONSTRAINT IF EXISTS budget_ledger_idempotency_key_key;

-- Existing keys predate namespacing. There is no production data, but a migration that
-- silently leaves un-namespaced rows behind would make the namespace invariant untestable.
UPDATE budget_ledger
   SET idempotency_key = 'rsv:' || idempotency_key
 WHERE split_part(idempotency_key, ':', 1) NOT IN ('genesis', 'rsv', 'release', 'settle');

ALTER TABLE budget_ledger
    ADD CONSTRAINT budget_ledger_mandate_idempotency_unique
    UNIQUE (mandate_id, idempotency_key);

COMMENT ON COLUMN budget_ledger.idempotency_key IS
    'Namespaced: genesis:<mandate_id> | rsv:<client_key> | release:<entry_id> | '
    'settle:<entry_id>. Client keys are ALWAYS prefixed server-side so an agent cannot '
    'forge a server namespace and silently no-op a real release. Unique per mandate, not '
    'globally: global uniqueness let one agent burn another agent''s key.';

-- ── decision_records: one record per logical decision ───────────────────────────────
ALTER TABLE decision_records
    ADD COLUMN request_idempotency_key TEXT;

-- Scoped on `mandate_hash`, not `mandate_id`.
--
-- decision_records carries no mandate_id — it identifies the authority by hash, which is
-- 1:1 with the mandate since migration 0010 made mandate_hash UNIQUE. Using the hash
-- avoids adding a redundant column to a table whose every column is inside a signature,
-- and it keeps the dedup scope pinned to the exact signed authority rather than to a
-- string that could in principle be repointed.
--
-- Nullable, because a decision can legitimately have no request key: a revoked-mandate
-- deny is chained and never reaches the ledger. The index is partial so those rows are
-- unconstrained rather than colliding on NULL.
CREATE UNIQUE INDEX idx_decisions_request_idempotency
    ON decision_records(mandate_hash, request_idempotency_key)
    WHERE request_idempotency_key IS NOT NULL;

COMMENT ON COLUMN decision_records.request_idempotency_key IS
    'The client key for the request this decision answered, prefixed as stored in '
    'budget_ledger. Inside the signed payload: it identifies WHICH request a record is a '
    'decision about, and a record that could be repointed at a different request would be '
    'evidence of nothing.';
