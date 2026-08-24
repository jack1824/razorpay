-- 0005 — Dwaar's own signing keys.
--
-- Not in the strategy package's schema.sql. Added per ADR 0001 Q5, because
-- decision_records.signature is Dwaar's signature and there was nowhere to record WHICH
-- key made it. The standalone verifier is a headline artifact; on the first key rotation
-- it would have started reporting every historical record as invalid, with no way to tell
-- a rotation from a forgery.
--
-- Retired keys are never deleted. Verification of an old record needs the key that signed
-- it, forever.
--
-- There is deliberately NO "at most one active key" constraint. An earlier draft of this
-- migration had one and it was wrong: rotation uses an OVERLAP WINDOW everywhere else in
-- this system — agents.previous_public_key exists for exactly that reason (threat 3) — and
-- a single-active constraint would have made the signing key the one identity in the
-- design that cannot rotate without a gap. Records in flight during a rotation would be
-- signed with a key the constraint had just forbidden.
--
-- "Which key is current" is a policy question answered by created_at/retired_at, not an
-- invariant the schema should enforce. The verifier resolves each record's key by its
-- signing_key_id regardless, so several active keys are a non-event for verification.

CREATE TABLE signing_keys (
    key_id      TEXT PRIMARY KEY,
    public_key  BYTEA       NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    retired_at  TIMESTAMPTZ,

    CONSTRAINT signing_keys_public_key_len CHECK (octet_length(public_key) = 32),
    CONSTRAINT signing_keys_retired_after_created
        CHECK (retired_at IS NULL OR retired_at >= created_at)
);

CREATE INDEX idx_signing_keys_active ON signing_keys(created_at DESC)
    WHERE retired_at IS NULL;
