-- 0014 — injection_flag becomes a TRISTATE: NULL, false, true.
--
-- WHY
--
-- `injection_flag BOOLEAN NOT NULL DEFAULT false` can express two things and there are
-- three. Until the detector landed, every record carried `false` — which reads as
-- "we looked and found nothing" and meant "nothing looked". A signed, hash-chained,
-- unpurgeable row was making a claim the system had never checked.
--
-- The distinguisher was `stages_executed`: no `detect_injection` entry meant no detection.
-- That is exactly the defect class of F-016 in a different costume — a fact a reader has to
-- INFER by correlating two columns, rather than one the record states. F-016 was a signed
-- blob that could disagree with the columns beside it; this is a column whose meaning
-- depends on another column. Both make the audit trail something you interpret instead of
-- something you read.
--
--     NULL   not checked. No detector ran on this request.
--     false  checked, nothing found.
--     true   checked, instruction-shaped content found.
--
-- HISTORY IS NOT REWRITTEN
--
-- Existing rows keep `false`, and that `false` still means "nothing looked". They are not
-- backfilled to NULL and could not be: `injection_flag` is inside the signed canonical
-- payload, so changing the column would break every signature it appears in. The chain is
-- append-only in the same sense this file is. What those rows say about themselves is
-- recorded in FAILURES.md, not corrected in place.
--
-- The constraint below is therefore ADDED NOT VALID: it governs every row written from now
-- on and makes no claim about rows written before the detector existed. That is the honest
-- shape. A constraint that silently exempted history by being written loosely would claim
-- more than it enforces.

ALTER TABLE decision_records ALTER COLUMN injection_flag DROP DEFAULT;
ALTER TABLE decision_records ALTER COLUMN injection_flag DROP NOT NULL;

-- Both directions, because each one alone permits a lie:
--
--   ran and NULL      -> a detector that produced no verdict, recorded as "not checked"
--   did not run, NOT NULL -> the original defect, a verdict nobody reached
ALTER TABLE decision_records
    ADD CONSTRAINT decision_records_injection_flag_matches_stages
    CHECK (
        ('detect_injection' = ANY(stages_executed)) = (injection_flag IS NOT NULL)
    ) NOT VALID;

COMMENT ON COLUMN decision_records.injection_flag IS
    'TRISTATE. NULL = no detector ran on this request; false = checked, clean; '
    'true = checked, instruction-shaped content found. Constrained to agree with '
    'stages_executed. Rows written before 2026-08-28 carry false meaning "nothing looked" '
    'and are exempt (constraint is NOT VALID); see migration 0014 and FAILURES.md.';
