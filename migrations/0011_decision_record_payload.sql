-- 0011 — Freeze the signed decision-record payload.
--
-- Stage 8 signs for real from Phase 3 onward, so every column below becomes permanent the
-- moment the first record is written: `decision_records` is append-only, so a column added
-- later cannot be backfilled, and re-canonicalising to include it forks the chain. This is
-- the last migration that can change what a signature covers without invalidating history.
--
-- Six changes, each forced by something that would otherwise be unfixable.

-- ── degraded_mode: TEXT → TEXT[] ────────────────────────────────────────────────────
--
-- Three in-path components degrade independently and Phase 3 has four simultaneous
-- degradations, so a single TEXT holds a set only by inventing a delimiter. An array is
-- queryable without parsing, which the eval harness will want ("every record where the risk
-- model was down"), and has no escaping or ordering bugs.
--
-- It is inside the signed payload, because whether a decision was degraded is material to
-- how the decision should be read. That makes array ORDER part of the hash, so the
-- application always sorts it and the golden vector pins that.
ALTER TABLE decision_records
    ALTER COLUMN degraded_mode DROP DEFAULT,
    ALTER COLUMN degraded_mode TYPE TEXT[]
        USING (CASE WHEN degraded_mode IS NULL THEN '{}'::TEXT[] ELSE ARRAY[degraded_mode] END),
    ALTER COLUMN degraded_mode SET DEFAULT '{}',
    ALTER COLUMN degraded_mode SET NOT NULL;

COMMENT ON COLUMN decision_records.degraded_mode IS
    'Sorted set of degradation tokens, e.g. {policy_stubbed,risk_model_stubbed}. Empty '
    'means fully operational. Inside the signed payload, so the sort is load-bearing.';

-- ── stages_executed: which stages actually ran ──────────────────────────────────────
--
-- The arithmetic authority gate short-circuits stages 3-6 for a mandate breach. Without
-- this column such a record stores `features = {}`, which is indistinguishable from a
-- feature set that was computed and came back empty. That is a stub lying by omission.
ALTER TABLE decision_records
    ADD COLUMN stages_executed TEXT[] NOT NULL DEFAULT '{}';

COMMENT ON COLUMN decision_records.stages_executed IS
    'Stage names that actually ran, in order. A short-circuited record says so instead of '
    'storing an empty feature set that looks computed.';

-- ── features / policy_version: absent is not the same as empty ──────────────────────
--
-- Both are unknowable on a short-circuited record. features defaults to {} and is read
-- alongside stages_executed; policy_version becomes nullable, which lets NULL mean "the
-- policy engine was never consulted" while 0 keeps meaning "consulted, no compiled policy
-- exists". Those are different facts and the audit trail should not conflate them.
ALTER TABLE decision_records
    ALTER COLUMN features SET DEFAULT '{}'::jsonb,
    ALTER COLUMN policy_version DROP NOT NULL;

-- ── reason_code: required by the API, absent from the record ────────────────────────
--
-- `openapi.yaml` makes reason_code required in every Decision response and the console
-- renders it, but the table carried only nullable `rule_fired`. That made the coarse-
-- outbound/fine-inbound split of threat 10 unauditable: we could not check after the fact
-- what an agent was actually told.
ALTER TABLE decision_records
    ADD COLUMN reason_code TEXT NOT NULL DEFAULT 'unspecified';
ALTER TABLE decision_records
    ALTER COLUMN reason_code DROP DEFAULT;

COMMENT ON COLUMN decision_records.reason_code IS
    'The COARSE code returned to the agent. rule_fired is the fine-grained internal reason. '
    'Storing both is what makes threat 10''s outbound/inbound split auditable.';

-- ── model_version: a scored decision must be replayable, not merely verifiable ──────
--
-- A record carrying risk_score = 0.87 with no model version is verifiable but not
-- reproducible, which is weaker than "a record that can be verified by someone who does not
-- trust you". The CHECK ties the two together so a scored decision can never lose its
-- provenance, and an unscored one can never acquire a fake one.
ALTER TABLE decision_records
    ADD COLUMN model_version TEXT;

ALTER TABLE decision_records
    ADD CONSTRAINT decision_records_model_version_iff_scored
    CHECK ((risk_score IS NULL) = (model_version IS NULL));

-- ── canonical_json: the verifier must not have to reconstruct the payload ───────────
--
-- `mandates` stores the exact bytes that were signed, for the reason that reconstructing
-- them means reimplementing JCS at verification time and any divergence invalidates every
-- signature. decision_records had no equivalent, so the verifier could not re-derive
-- payload_hash from stored data at all.
--
-- Storing it also makes the payload definition self-documenting in the data: a future
-- reader can see exactly what was covered without reading the code that produced it.
ALTER TABLE decision_records
    ADD COLUMN canonical_json TEXT NOT NULL DEFAULT '';
ALTER TABLE decision_records
    ALTER COLUMN canonical_json DROP DEFAULT;

-- ── grants for the new columns ──────────────────────────────────────────────────────
-- decision_records is INSERT+SELECT for dwaar_app and remains so; table-level grants cover
-- new columns automatically. Stated here only so the absence of a GRANT is deliberate.
