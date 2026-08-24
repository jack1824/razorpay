"""Golden vector for the signed mandate payload.

ADR 0001 item 9 asked for this on day 2 and it was missed — Phase 2 implemented "defaults
are materialised" as a database assertion but never pinned the *bytes*. Recorded as F-011.

Why the bytes need pinning and the database assertion does not cover it: the signature is
over a serialisation. Any change to key ordering, escaping, number formatting, or which
fields are included silently invalidates every signature ever produced — and the failure
appears as "signature invalid", indistinguishable from a forgery. A golden vector turns
that into a diff.

If this test fails, do not update the expected value to make it pass. Either the change to
the canonicaliser is a bug, or it is a deliberate format change that invalidates every
existing mandate and needs a migration plan.
"""

from __future__ import annotations

import hashlib

import pytest

from dwaar.crypto import mandate as mandatemod
from dwaar.crypto.jcs import canonicalize

# A fixed mandate. Values chosen to exercise the things that break canonicalisers:
# unsorted input keys, an empty array, a materialised default, and a large integer.
VECTOR_FIELDS = {
    "mandate_id": "mnd_000000000001",
    "principal_id": "prn_000000000001",
    "agent_id": "agt_000000000001",
    "max_total_paise": 5_000_000,
    "max_per_txn_paise": 500_000,
    "allow_categories": ["groceries", "apparel"],
    "expires_at": "2026-10-05T10:00:00+00:00",
    "nonce": "0123456789abcdef01234567",
}

EXPECTED_CANONICAL = (
    '{"agent_id":"agt_000000000001",'
    '"allow_categories":["groceries","apparel"],'
    '"deny_categories":[],'
    '"expires_at":"2026-10-05T10:00:00+00:00",'
    '"mandate_id":"mnd_000000000001",'
    '"max_per_txn_paise":500000,'
    '"max_total_paise":5000000,'
    '"nonce":"0123456789abcdef01234567",'
    '"principal_id":"prn_000000000001",'
    '"substitution_tolerance":"none"}'
)

# Computed from EXPECTED_CANONICAL, not asserted from memory. The test below
# checks it against a fresh sha256 of that string as well, so the two pins
# cannot drift apart silently.
EXPECTED_HASH = "4ed119aaa4071f6972237923226682af5d1aec674604e88df0b454a5134d0493"


def test_payload_materialises_every_default():
    payload = mandatemod.build_payload(**VECTOR_FIELDS)
    assert set(payload) == set(mandatemod.SIGNED_FIELDS)
    assert payload["deny_categories"] == []
    assert payload["substitution_tolerance"] == "none"


def test_canonical_form_is_pinned():
    """The exact bytes that get signed. Changing this invalidates every mandate."""
    payload = mandatemod.build_payload(**VECTOR_FIELDS)
    assert mandatemod.canonical_json(payload) == EXPECTED_CANONICAL


def test_hash_matches_the_canonical_form():
    payload = mandatemod.build_payload(**VECTOR_FIELDS)
    digest = mandatemod.mandate_hash(payload)
    assert digest == hashlib.sha256(EXPECTED_CANONICAL.encode()).digest()
    assert digest.hex() == EXPECTED_HASH


def test_absent_and_empty_hash_differently():
    """The footgun ADR item 9 exists to prevent, asserted directly.

    Under JCS an omitted key and an empty array are different bytes. If defaults were
    "omit if empty", one mandate would have two valid hashes and a verifier reconstructing
    it the other way would report a forgery.
    """
    with_empty = canonicalize({"a": 1, "deny_categories": []})
    without = canonicalize({"a": 1})
    assert with_empty != without


def test_field_order_in_the_call_does_not_change_the_bytes():
    """JCS sorts. Callers must not have to care about ordering."""
    forward = mandatemod.build_payload(**VECTOR_FIELDS)
    reversed_fields = dict(reversed(list(VECTOR_FIELDS.items())))
    backward = mandatemod.build_payload(**reversed_fields)
    assert mandatemod.canonical_json(forward) == mandatemod.canonical_json(backward)


def test_unknown_field_is_rejected():
    """A field outside SIGNED_FIELDS would change what every signature covers."""
    with pytest.raises(ValueError, match="outside the signed set"):
        mandatemod.build_payload(**VECTOR_FIELDS, agent_reasoning_summary="I decided to buy")


def test_missing_required_field_is_rejected():
    fields = dict(VECTOR_FIELDS)
    del fields["nonce"]
    with pytest.raises(ValueError, match="missing required field 'nonce'"):
        mandatemod.build_payload(**fields)


def test_agent_reasoning_summary_can_never_be_signed():
    """Removed for cause, and the removal is enforced rather than documented.

    An LLM's stated reasoning is post-hoc narrative from the party whose conduct is in
    dispute. Signing it and calling it evidence would discredit the whole receipt.
    """
    assert "agent_reasoning_summary" not in mandatemod.SIGNED_FIELDS
