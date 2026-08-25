-- Remove the demo merchant's fixtures and its chain. Run as the OWNER, by `make demo-reset`.
--
-- ── This deletes from an append-only table, which needs saying out loud ─────────────
--
-- `decision_records` is append-only to the APPLICATION: `dwaar_app` holds SELECT and INSERT,
-- owns nothing, and a REVOKE cannot strip an owner — which is why non-ownership is the actual
-- control (migration 0009). The owner can always delete, and that is not a hole. An audit log
-- its own administrator cannot administer is not an audit log, it is a disk that fills up.
--
-- What the design claims is narrower and survives this: a change cannot happen UNDETECTED.
-- `make verify` passes after this runs, because the chain simply starts again from seq 1 for
-- this merchant. It would NOT pass if a single row had been removed from the middle, which is
-- the case the hash chain exists for and the reason the deletes below are whole-chain.
--
-- ── Why it is ever needed ───────────────────────────────────────────────────────────
--
-- Identities in `data/seed/` come from an RNG stream keyed on the seed rather than from the
-- fixture's content, so editing a signed term — adding `scopes`, for instance — produces the
-- same `mandate_id` carrying different bytes. The seeder refuses to seed over that rather
-- than patching a column to match, because patching a signed column to match a fixture is
-- precisely the tamper the integrity check exists to find (FAILURES.md F-042).
--
-- Scoped to `mch_demo0001` and its agents. Touches no zoo traffic, no evaluation run, and
-- nothing `eval/RESULTS.md` reports.

BEGIN;

DELETE FROM decision_records WHERE merchant_id = 'mch_demo0001';

-- Before the mandates: budget_ledger references them.
DELETE FROM budget_ledger WHERE mandate_id IN (
    SELECT m.mandate_id
    FROM mandates m
    JOIN principals p ON p.principal_id = m.principal_id
    WHERE p.merchant_id = 'mch_demo0001'
);

DELETE FROM mandates WHERE principal_id IN (
    SELECT principal_id FROM principals WHERE merchant_id = 'mch_demo0001'
);

DELETE FROM agents     WHERE registered_by = 'mch_demo0001';
DELETE FROM principals WHERE merchant_id   = 'mch_demo0001';

COMMIT;
