-- 0013 — Give `policies` a canonical form, so its signature attests to something defined.
--
-- `policies.signature` existed with no statement of WHAT it signs. A signature over an
-- unspecified serialisation is not a control: two implementations would disagree about
-- what to verify, and the column could only ever be decorative.
--
-- This is the third instance of the same pattern — a signed artifact alongside
-- denormalised columns that the application actually reads:
--
--     decision_records   canonical_json  vs  every signed column   (F-016)
--     mandates           canonical_json  vs  the ten terms         (F-013 residual)
--     policies           canonical_json  vs  version/approval      (this migration)
--
-- Three instances is a bug class. `dwaar/crypto/integrity.py` holds one helper and a
-- registry; the verifier iterates the registry, so registering a table is what makes it
-- checked. ADR 0001 records the standing requirement.
--
-- ── What the policy signature covers, and why not just compiled_rules ───────────────
--
-- policy_id, merchant_id, version, compiled_rules, approved_by.
--
-- Signing the ruleset alone would leave the rest free: an approved v3 ruleset could be
-- repointed at another merchant, or an unapproved version could inherit an approval, and
-- the signature would still verify. What is being attested is "this merchant approved
-- THIS ruleset as THIS version", not "these rules exist somewhere".

ALTER TABLE policies
    ADD COLUMN canonical_json TEXT;

-- Both or neither. A signature with no canonical form is unverifiable; a canonical form
-- with no signature is unattested. Either alone reads as a control and is not one.
ALTER TABLE policies
    ADD CONSTRAINT policies_signature_iff_canonical
    CHECK ((signature IS NULL) = (canonical_json IS NULL));

COMMENT ON COLUMN policies.canonical_json IS
    'RFC 8785 canonical form of {policy_id, merchant_id, version, compiled_rules, '
    'approved_by} — exactly what `signature` covers. Verified against the columns by '
    'dwaar/crypto/integrity.py, because the application reads the columns and the '
    'signature attests to the blob.';

GRANT UPDATE (tests_passed, approved_by, signature, canonical_json) ON policies TO dwaar_app;
