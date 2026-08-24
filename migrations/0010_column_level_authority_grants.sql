-- 0010 — Narrow the app role's UPDATE grants to specific columns.
--
-- 0009 granted table-wide UPDATE on mandates, agents, policies and signing_keys because
-- the app legitimately mutates one or two columns on each. Table-wide UPDATE also let the
-- app mutate every OTHER column, and on `mandates` those columns are the authority itself.
--
-- Demonstrated against the running database before this migration existed:
--
--     $ psql "postgresql://dwaar_app:...@localhost/dwaar"
--     UPDATE mandates SET expires_at = now() + interval '100 years' WHERE ...;
--     UPDATE 1
--
-- An application that can extend its own mandate's expiry — or raise max_per_txn_paise —
-- has escalated past the authority the principal granted, and nothing detects it: the
-- principal's signature covers `canonical_json`, which is untouched, so the mandate still
-- verifies. The hot path reads the denormalised columns, not the signed blob. The
-- signature stays valid while the authority it attests to has been rewritten underneath it.
--
-- That is precisely the failure `decision_records`' two-role grant exists to prevent, left
-- open one table over.
--
-- PostgreSQL supports column-level privileges, so the fix states the intent exactly:
-- revocation is an UPDATE the app must make; the caps and the expiry are not.
--
-- A column-level GRANT does not override a table-level one, so each REVOKE must come first.

-- ── mandates: the app may only revoke ───────────────────────────────────────────────
REVOKE UPDATE ON mandates FROM dwaar_app;
GRANT  UPDATE (revoked_at) ON mandates TO dwaar_app;

-- ── agents: status transitions and key rotation, nothing else ───────────────────────
-- Not registered_by: an agent must not be able to move itself to another merchant.
REVOKE UPDATE ON agents FROM dwaar_app;
GRANT  UPDATE (status, public_key, previous_public_key, key_rotated_at)
       ON agents TO dwaar_app;

-- ── policies: the human gate and its result ─────────────────────────────────────────
-- Not compiled_rules or source_nl: an approved policy's rules are frozen. Changing them
-- would be a new version, which is an INSERT.
REVOKE UPDATE ON policies FROM dwaar_app;
GRANT  UPDATE (tests_passed, approved_by, signature) ON policies TO dwaar_app;

-- ── signing_keys: retire only ───────────────────────────────────────────────────────
-- Not public_key: rewriting the public key of a key that has already signed records would
-- invalidate every one of them, and invalidation is indistinguishable from forgery.
REVOKE UPDATE ON signing_keys FROM dwaar_app;
GRANT  UPDATE (retired_at) ON signing_keys TO dwaar_app;

-- ── mandate_hash is an identity, so make it one ─────────────────────────────────────
-- decision_records.mandate_hash is how the verifier resolves a record back to the
-- authority that was exercised. A plain index makes that join fast; UNIQUE makes it
-- correct — two rows sharing a hash would make the join ambiguous, and the verifier would
-- have no way to choose. It cannot collide in practice (the canonical form contains both a
-- unique mandate_id and a unique nonce), which is exactly why asserting it costs nothing.
DROP INDEX IF EXISTS idx_mandates_hash;
CREATE UNIQUE INDEX idx_mandates_hash ON mandates(mandate_hash);
