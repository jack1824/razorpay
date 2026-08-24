"""The columns-vs-canonical helper, and its positive control.

"A check whose job is to never fail cannot be validated by never failing." This file was
written in the same commit as the helper, not after, for exactly that reason: the helper's
value is entirely in what it *rejects*, and asserting only that clean data passes would
leave a broken helper indistinguishable from a working one.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from dwaar.crypto import integrity
from dwaar.crypto import mandate as mandatemod
from dwaar.crypto import record as recordmod
from dwaar.crypto.integrity import (
    REGISTRY,
    IntegrityCheck,
    IntegrityError,
    assert_columns_match_canonical,
)

EXPIRES = datetime(2026, 10, 5, 10, 0, 0, tzinfo=UTC)


def _mandate_row(**overrides):
    row = {
        "mandate_id": "mnd_000000000001",
        "principal_id": "prn_000000000001",
        "agent_id": "agt_000000000001",
        "max_total_paise": 5_000_000,
        "max_per_txn_paise": 500_000,
        "allow_categories": ["groceries", "apparel"],
        "deny_categories": ["gift_cards"],
        "substitution_tolerance": "same_price",
        "expires_at": EXPIRES,
        "nonce": "0123456789abcdef01234567",
    }
    row["canonical_json"] = mandatemod.canonical_json(mandatemod.build_payload(**row))
    row.update(overrides)
    return row


# ── the happy path ──────────────────────────────────────────────────────────────────

def test_untouched_columns_verify():
    assert_columns_match_canonical(_mandate_row(), integrity.MANDATES)


# ── POSITIVE CONTROLS: every field, one at a time ───────────────────────────────────

@pytest.mark.parametrize(
    ("column", "tampered"),
    [
        ("max_total_paise", 999_999_999),
        ("max_per_txn_paise", 999_999),
        ("expires_at", EXPIRES + timedelta(days=3650)),
        ("allow_categories", ["gift_cards"]),
        ("deny_categories", []),
        ("substitution_tolerance", "similar"),
        ("nonce", "rewritten"),
        ("agent_id", "agt_someoneelse"),
        ("principal_id", "prn_someoneelse"),
        ("mandate_id", "mnd_someoneelse"),
    ],
)
def test_every_signed_mandate_field_is_actually_checked(column, tampered):
    """If any of these passed, that field would be silently unprotected — the signature
    would keep verifying while the term it attests to had been rewritten."""
    row = _mandate_row(**{column: tampered})
    with pytest.raises(IntegrityError, match="do not match the signed"):
        assert_columns_match_canonical(row, integrity.MANDATES)


def test_a_missing_canonical_form_is_an_error_not_a_pass():
    """An attested row whose blob has vanished must fail, not be skipped. Skipping it
    would let an attacker disable the check by deleting the evidence."""
    row = _mandate_row(canonical_json=None)
    with pytest.raises(IntegrityError, match="nothing to verify against"):
        assert_columns_match_canonical(row, integrity.MANDATES)


def test_a_row_that_cannot_be_canonicalised_fails_closed():
    """A malformed row must not be reported as intact."""
    row = _mandate_row(max_total_paise=None)
    with pytest.raises(IntegrityError):
        assert_columns_match_canonical(row, integrity.MANDATES)


def test_an_unsigned_row_is_skipped_only_when_a_signature_column_is_declared():
    """`policies` may legitimately be unsigned. `mandates` may not — every mandate is
    signed by construction, so it has no signature_column and nothing is skipped."""
    assert integrity.POLICIES.signature_column == "signature"
    assert integrity.MANDATES.signature_column is None
    assert integrity.DECISION_RECORDS.signature_column is None

    unsigned = {
        "policy_id": "pol_1", "merchant_id": "mch_1", "version": 1,
        "compiled_rules": {}, "approved_by": None,
        "signature": None, "canonical_json": None,
    }
    assert_columns_match_canonical(unsigned, integrity.POLICIES)  # no raise


def test_a_signed_policy_with_rewritten_rules_fails():
    row = {
        "policy_id": "pol_1", "merchant_id": "mch_1", "version": 3,
        "compiled_rules": {"deny": ["gift_cards"]}, "approved_by": "arpit",
        "signature": b"\x00" * 64,
    }
    row["canonical_json"] = integrity.POLICIES.rebuild(row)
    assert_columns_match_canonical(row, integrity.POLICIES)

    with pytest.raises(IntegrityError):
        assert_columns_match_canonical({**row, "compiled_rules": {"deny": []}}, integrity.POLICIES)


@pytest.mark.parametrize("column", ["merchant_id", "version", "approved_by"])
def test_a_policy_signature_covers_more_than_the_rules(column):
    """Signing compiled_rules alone would let an approved v3 ruleset be repointed at
    another merchant, or an unapproved version inherit an approval."""
    row = {
        "policy_id": "pol_1", "merchant_id": "mch_1", "version": 3,
        "compiled_rules": {"deny": ["gift_cards"]}, "approved_by": "arpit",
        "signature": b"\x00" * 64,
    }
    row["canonical_json"] = integrity.POLICIES.rebuild(row)
    tampered = {**row, column: "elsewhere" if column != "version" else 99}
    with pytest.raises(IntegrityError):
        assert_columns_match_canonical(tampered, integrity.POLICIES)


# ── the registry is the control surface ─────────────────────────────────────────────

def test_the_registry_covers_every_table_with_a_canonical_form():
    """The rule from ADR 0001: any table carrying both a signed serialisation and
    extracted columns must be registered here.

    Registration is what makes a table checked, so forgetting one is silent — which is why
    this asserts the registry rather than trusting a convention.
    """
    registered = {check.table for check in REGISTRY}
    assert registered == {"decision_records", "mandates", "policies"}


def test_every_registered_check_has_a_working_rebuild():
    for check in REGISTRY:
        assert callable(check.rebuild)
        assert check.canonical_column
        assert check.identity_column


def test_the_helper_raises_rather_than_returning_a_boolean():
    """A caller that ignores a boolean has silently disabled the control, and this is the
    control that catches an attacker with database access."""
    import inspect

    signature = inspect.signature(assert_columns_match_canonical)
    assert signature.return_annotation in (None, "None")


def test_a_check_with_a_broken_rebuild_is_detected():
    """Positive control for the helper itself: a rebuild that returns nonsense must be
    reported, not swallowed."""
    broken = IntegrityCheck(
        table="fake", canonical_column="canonical_json", identity_column="id",
        rebuild=lambda row: "not the canonical form",
    )
    with pytest.raises(IntegrityError):
        assert_columns_match_canonical({"id": 1, "canonical_json": "{}"}, broken)


def test_decision_record_rebuild_matches_the_signer():
    """The verifier and the signer must build the same bytes, or every record reads as
    tampered."""
    fields = {
        "seq": 1, "merchant_id": "mch_1", "prev_hash": b"\x00" * 32,
        "signing_key_id": "key_1", "agent_id": "agt_1", "principal_id": "prn_1",
        "mandate_hash": b"\x01" * 32, "request_digest": b"\x02" * 32,
        "request_idempotency_key": "rsv:k", "decision": "allow", "reason_code": "allowed",
        "rule_fired": None, "risk_score": None, "model_version": None,
        "injection_flag": False, "features": {}, "policy_version": None,
        "amount_paise": 1000, "budget_before": 5000, "budget_after": 4000,
        "degraded_mode": [], "stages_executed": ["render_decision"], "latency_us": 100,
        "created_at": EXPIRES,
    }
    signed = recordmod.canonical_json(recordmod.build_payload(**fields))
    rebuilt = integrity.DECISION_RECORDS.rebuild({**fields, "canonical_json": signed})
    assert rebuilt == signed
