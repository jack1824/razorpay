"""Golden vector for the signed decision-record payload.

Same discipline as the mandate vector, and it matters more here: `decision_records` is
append-only AND hash-chained, so a change to the canonical form cannot be migrated. It
would invalidate every existing signature and there is no UPDATE grant to fix them with.

If this test fails, do not update the expected value. Either the canonicaliser has a bug,
or someone changed what a signature covers — which forks the chain and needs a plan, not a
diff.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timezone

import pytest

from dwaar.crypto import record as recordmod

VECTOR_FIELDS = {
    "seq": 42,
    "merchant_id": "mch_demo0001",
    "prev_hash": bytes.fromhex("aa" * 32),
    "signing_key_id": "key_0123456789ab",
    "agent_id": "agt_000000000001",
    "principal_id": "prn_000000000001",
    "mandate_hash": bytes.fromhex("bb" * 32),
    "request_digest": bytes.fromhex("cc" * 32),
    "decision": "deny",
    "reason_code": "denied",
    "rule_fired": "mandate.max_per_txn",
    "risk_score": None,
    "model_version": None,
    "injection_flag": False,
    "features": {},
    "policy_version": None,
    "amount_paise": 1_200_000,
    "budget_before": None,
    "budget_after": None,
    # Deliberately unsorted on the way in. The payload builder sorts it, because array
    # order is inside the hash.
    "degraded_mode": ["risk_model_stubbed", "features_stubbed", "policy_stubbed"],
    "stages_executed": ["verify_signature", "resolve_mandate", "check_authority"],
    "latency_us": 3421,
    "created_at": datetime(2026, 9, 5, 10, 0, 0, tzinfo=UTC),
}


# The exact bytes that get signed. Generated, never typed — a hash nobody
# computed is a metric nobody measured (F-011).
EXPECTED_CANONICAL = (
    '{'
    '"agent_id":"agt_000000000001",'
    '"amount_paise":1200000,'
    '"budget_after":null,'
    '"budget_before":null,'
    '"created_at":"2026-09-05T10:00:00+00:00",'
    '"decision":"deny",'
    '"degraded_mode":["features_stubbed",'
    '"policy_stubbed",'
    '"risk_model_stubbed"],'
    '"features":{},'
    '"injection_flag":false,'
    '"latency_us":3421,'
    '"mandate_hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",'
    '"merchant_id":"mch_demo0001",'
    '"model_version":null,'
    '"policy_version":null,'
    '"prev_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",'
    '"principal_id":"prn_000000000001",'
    '"reason_code":"denied",'
    '"request_digest":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",'
    '"risk_score":null,'
    '"rule_fired":"mandate.max_per_txn",'
    '"seq":42,'
    '"signing_key_id":"key_0123456789ab",'
    '"stages_executed":["verify_signature",'
    '"resolve_mandate",'
    '"check_authority"]'
    '}'
)


def test_every_signed_field_is_present():
    payload = recordmod.build_payload(**VECTOR_FIELDS)
    assert set(payload) == set(recordmod.SIGNED_FIELDS)


def test_degraded_mode_is_sorted_in_the_payload():
    """Load-bearing. Array order changes the hash, so an unsorted list would give one
    record several valid signatures depending on which stage degraded first."""
    payload = recordmod.build_payload(**VECTOR_FIELDS)
    assert payload["degraded_mode"] == [
        "features_stubbed", "policy_stubbed", "risk_model_stubbed"
    ]


def test_stages_executed_keeps_its_order():
    """Unlike degraded_mode, this IS ordered data — it records the sequence stages ran in."""
    payload = recordmod.build_payload(**VECTOR_FIELDS)
    assert payload["stages_executed"] == [
        "verify_signature", "resolve_mandate", "check_authority"
    ]


def test_nulls_are_explicit_not_omitted():
    """Under JCS an absent key and an explicit null are different bytes. Omitting nulls
    would give one record two valid hashes."""
    payload = recordmod.build_payload(**VECTOR_FIELDS)
    for nullable in ("risk_score", "model_version", "policy_version", "budget_before"):
        assert nullable in payload
        assert payload[nullable] is None


def test_bytes_become_lowercase_hex():
    payload = recordmod.build_payload(**VECTOR_FIELDS)
    assert payload["prev_hash"] == "aa" * 32
    assert payload["mandate_hash"] == "bb" * 32
    assert payload["request_digest"] == "cc" * 32


def test_created_at_is_normalised_to_utc():
    """PostgreSQL returns TIMESTAMPTZ in the session timezone. Without normalisation a
    verifier with a different TimeZone setting would rebuild different bytes and report a
    valid record as forged."""
    from datetime import timedelta

    ist = timezone(timedelta(hours=5, minutes=30))
    same_instant = dict(VECTOR_FIELDS)
    same_instant["created_at"] = VECTOR_FIELDS["created_at"].astimezone(ist)

    assert (
        recordmod.canonical_json(recordmod.build_payload(**same_instant))
        == recordmod.canonical_json(recordmod.build_payload(**VECTOR_FIELDS))
    )


def test_risk_score_is_carried_as_an_exact_decimal_string():
    """JCS forbids floats, and NUMERIC(5,4) round-trips as Decimal. Carrying it as a
    4-decimal string keeps signer and verifier bit-identical."""
    scored = dict(VECTOR_FIELDS, risk_score=0.87, model_version="lgbm-0.4.2")
    payload = recordmod.build_payload(**scored)
    assert payload["risk_score"] == "0.8700"
    assert isinstance(payload["risk_score"], str)


def test_canonical_form_is_pinned():
    payload = recordmod.build_payload(**VECTOR_FIELDS)
    canonical = recordmod.canonical_json(payload)
    assert canonical == EXPECTED_CANONICAL


def test_hash_matches_the_canonical_form():
    payload = recordmod.build_payload(**VECTOR_FIELDS)
    assert recordmod.payload_hash(payload) == hashlib.sha256(EXPECTED_CANONICAL.encode()).digest()


def test_a_field_outside_the_signed_set_is_rejected():
    """Adding one changes what every signature covers and cannot be backfilled."""
    with pytest.raises(ValueError, match="outside the signed set"):
        recordmod.build_payload(**VECTOR_FIELDS, agent_reasoning_summary="because I felt like it")


def test_a_missing_non_nullable_field_is_rejected():
    fields = dict(VECTOR_FIELDS)
    del fields["seq"]
    with pytest.raises(ValueError, match="missing required field 'seq'"):
        recordmod.build_payload(**fields)


def test_payload_from_row_round_trips():
    """The verifier rebuilds the payload from columns. If that ever diverged from what the
    signer built, every record would read as tampered."""
    payload = recordmod.build_payload(**VECTOR_FIELDS)
    row = dict(VECTOR_FIELDS)
    rebuilt = recordmod.canonical_json(recordmod.payload_from_row(row))
    assert rebuilt == recordmod.canonical_json(payload)
