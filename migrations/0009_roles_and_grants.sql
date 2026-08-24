-- 0009 — Role grants. THIS IS THE APPEND-ONLY CONTROL.
--
-- Runs as dwaar_owner, which owns every table above. dwaar_app is created by the Postgres
-- init script (scripts/init-db/01-roles.sh, superuser context) because CREATE ROLE is a
-- cluster-level privilege the owner does not have.
--
-- The critical property: dwaar_app is NOT the owner of any table. A REVOKE never strips an
-- owner, so an app connecting as the owner can always UPDATE and DELETE regardless of what
-- was revoked. Non-ownership is the only thing that makes the grant below meaningful.
--
-- tests/db/test_append_only_grant.py asserts UPDATE and DELETE on decision_records raise
-- InsufficientPrivilege as dwaar_app, and that the same statements succeed as superuser —
-- because the tamper demo depends on the superuser path working.

-- ── Connect and schema access ───────────────────────────────────────────────────────
GRANT USAGE ON SCHEMA public TO dwaar_app;

-- ── Read/write tables ───────────────────────────────────────────────────────────────
-- Mutable state. UPDATE is granted only where the domain genuinely mutates a row:
--   agents   — status transitions (auto-suspend on repeated signature failure, threat 1)
--              and key rotation (previous_public_key, threat 3)
--   mandates — revoked_at
--   policies — tests_passed, approved_by
GRANT SELECT, INSERT, UPDATE ON agents        TO dwaar_app;
GRANT SELECT, INSERT         ON principals    TO dwaar_app;
GRANT SELECT, INSERT, UPDATE ON mandates      TO dwaar_app;
GRANT SELECT, INSERT, UPDATE ON policies      TO dwaar_app;
GRANT SELECT, INSERT, UPDATE ON signing_keys  TO dwaar_app;
GRANT SELECT, INSERT         ON chain_anchors TO dwaar_app;
GRANT SELECT, INSERT         ON eval_runs     TO dwaar_app;

-- ── Append-only tables ──────────────────────────────────────────────────────────────
--
-- decision_records: the audit trail. SELECT + INSERT, nothing else, forever.
GRANT SELECT, INSERT ON decision_records TO dwaar_app;

-- budget_ledger: also append-only, and for the same reason rather than a weaker one.
-- A released reservation is a COMPENSATING ENTRY, never an edit to the reserving row.
-- If the ledger could be updated, `balance == sum(deltas)` would stop being an invariant
-- and the property test asserting it would be asserting nothing.
GRANT SELECT, INSERT ON budget_ledger TO dwaar_app;

-- ── Sequences ───────────────────────────────────────────────────────────────────────
-- Only for the two tables that still use BIGSERIAL. decision_records deliberately does
-- not: seq is allocated explicitly under an advisory lock (see 0007).
GRANT USAGE, SELECT ON SEQUENCE budget_ledger_entry_id_seq TO dwaar_app;
GRANT USAGE, SELECT ON SEQUENCE chain_anchors_anchor_id_seq TO dwaar_app;

-- ── Migration bookkeeping ───────────────────────────────────────────────────────────
-- Readable so /health and the verifier can report schema version. Never writable by the app.
GRANT SELECT ON schema_migrations TO dwaar_app;

-- ── Explicitly NOT granted, recorded so the absence is a decision ───────────────────
--   UPDATE  ON decision_records  -- the audit trail
--   DELETE  ON decision_records  -- the audit trail
--   UPDATE  ON budget_ledger     -- compensating entries only
--   DELETE  ON budget_ledger     -- compensating entries only
--   DELETE  ON anything          -- nothing in this system deletes
--   TRUNCATE ON anything
--   CREATE  ON SCHEMA public     -- the app cannot create tables
--
-- Belt and braces against a future migration that grants too much: strip anything that
-- may have been inherited from PUBLIC on the two append-only tables.
REVOKE UPDATE, DELETE, TRUNCATE ON decision_records FROM PUBLIC;
REVOKE UPDATE, DELETE, TRUNCATE ON budget_ledger    FROM PUBLIC;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
