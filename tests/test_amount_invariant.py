"""The money invariant, exhaustively, without a database.

`dwaar/invariants.py` is pure and small on purpose: it is the one rule that decides whether
a decision and the money it moved agree, and it is called from three places — the write path,
the fixture that builds records, and the verifier. Testing it here means the cross-product is
covered once rather than three times partially.

The database half — that the trigger refuses the same rows, and that the pipeline never
produces one — is in `tests/db/test_amount_invariant_db.py`. Neither subsumes the other: this
proves the rule is right, that one proves the rule is reached.
"""

from __future__ import annotations

import pytest

from dwaar.invariants import (
    MONEY_MOVING_DECISIONS,
    AmountFacts,
    check_amount_conserved,
    moved_paise,
)

ALL_DECISIONS = ("allow", "bound", "throttle", "step_up", "deny")


def facts(**kw) -> AmountFacts:
    base = {
        "decision": "allow",
        "requested_paise": 100_000,
        "stated_paise": None,
        "budget_before": 5_000_000,
        "budget_after": 4_900_000,
    }
    base.update(kw)
    return AmountFacts(**base)


# ── the shapes that must hold ───────────────────────────────────────────────────────


def test_an_exact_allow_conserves():
    assert check_amount_conserved(facts()) is None


def test_a_bound_conserves_when_it_reserved_the_bounded_amount():
    assert (
        check_amount_conserved(
            facts(
                decision="bound",
                requested_paise=180_000,
                stated_paise=50_000,
                budget_before=500_000,
                budget_after=450_000,
            )
        )
        is None
    )


@pytest.mark.parametrize("decision", ["deny", "throttle", "step_up"])
def test_a_refusal_that_reserved_nothing_conserves(decision):
    """Both shapes of refusal. `budget_before == budget_after` is the exhausted-budget deny,
    which reports the balance it read so the record shows what the limit was; both NULL is
    every other refusal, where the ledger was never reached."""
    reported = facts(decision=decision, budget_before=1000, budget_after=1000)
    unreached = facts(decision=decision, budget_before=None, budget_after=None)
    assert check_amount_conserved(reported) is None
    assert check_amount_conserved(unreached) is None


def test_a_read_only_tool_conserves_with_no_ledger_at_all():
    """Zero amount, no reservation, permitted. `LedgerResult.not_required` — the third state
    that was missing until a delegated `fetch_payment` was denied for insufficient funds."""
    assert (
        check_amount_conserved(
            facts(decision="allow", requested_paise=0, budget_before=None, budget_after=None)
        )
        is None
    )


# ── F-038 ───────────────────────────────────────────────────────────────────────────


def test_F038_a_bound_that_reserved_the_full_request_is_caught():
    """The defect exactly as it was: told the agent ₹500, debited ₹1,800."""
    violation = check_amount_conserved(
        facts(
            decision="bound",
            requested_paise=180_000,
            stated_paise=50_000,
            budget_before=500_000,
            budget_after=320_000,
        )
    )
    assert violation is not None
    assert violation.code == "moved_amount_mismatch"
    assert "180000" in violation.detail and "50000" in violation.detail


def test_a_bound_that_records_no_bounded_amount_is_caught():
    """Without it the authorised figure exists only in the ledger, and an invariant with one
    side missing is not an invariant. This is what the record was missing for four phases."""
    violation = check_amount_conserved(
        facts(decision="bound", requested_paise=180_000, stated_paise=None,
              budget_before=500_000, budget_after=320_000)
    )
    assert violation is not None and violation.code == "bound_without_stated_amount"


def test_a_bound_may_only_ever_reduce():
    violation = check_amount_conserved(
        facts(decision="bound", requested_paise=50_000, stated_paise=180_000,
              budget_before=500_000, budget_after=320_000)
    )
    assert violation is not None and violation.code == "stated_exceeds_requested"


# ── F-043 ───────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("decision", ["throttle", "step_up", "deny"])
def test_F043_a_refusal_that_moved_money_is_caught(decision):
    """1,070 throttled and 23 stepped-up records in the local database had done this. The
    agent was told to come back later and its budget was debited; the retry — a different
    idempotency key — was debited again."""
    violation = check_amount_conserved(
        facts(decision=decision, requested_paise=5_694, budget_before=5_000, budget_after=4_500)
    )
    assert violation is not None
    assert violation.code == "moved_without_permission"
    assert "F-043" in violation.detail


def test_the_permitting_set_is_a_whitelist():
    """F-041's lesson, asserted rather than assumed. A verdict added later must land on the
    strict side, not reach the ledger by falling off the end of a chain of checks."""
    assert frozenset({"allow", "bound"}) == MONEY_MOVING_DECISIONS
    for decision in ALL_DECISIONS:
        if decision in MONEY_MOVING_DECISIONS:
            continue
        assert check_amount_conserved(facts(decision=decision)) is not None


# ── the arithmetic itself ───────────────────────────────────────────────────────────


def test_half_a_reservation_is_caught():
    assert check_amount_conserved(facts(budget_after=None)).code == "budget_half_recorded"
    assert check_amount_conserved(facts(budget_before=None)).code == "budget_half_recorded"


def test_a_balance_that_rose_inside_one_record_is_caught():
    """A release is a compensating ENTRY with its own row, never an edit — so this cannot
    happen, which is exactly why asserting it costs nothing."""
    violation = check_amount_conserved(facts(budget_before=1_000, budget_after=5_000))
    assert violation is not None and violation.code == "budget_increased"


def test_a_permit_that_never_reached_the_ledger_is_caught():
    """An authorisation against no budget. Distinct from the read-only tool above, which
    authorises zero."""
    violation = check_amount_conserved(
        facts(decision="allow", requested_paise=4_000, budget_before=None, budget_after=None)
    )
    assert violation is not None and violation.code == "permitted_without_reserving"


def test_a_permit_that_reserved_zero_is_caught():
    violation = check_amount_conserved(
        facts(decision="allow", requested_paise=4_000, budget_before=1_000, budget_after=1_000)
    )
    assert violation is not None and violation.code == "permitted_without_reserving"


def test_moved_paise_distinguishes_zero_from_not_consulted():
    """0 and None are different answers and the type says so. Conflating them is how
    `risk_score = 0.0` would have destroyed the audit-trail claim."""
    assert moved_paise(facts(budget_before=1_000, budget_after=1_000)) == 0
    assert moved_paise(facts(budget_before=None, budget_after=None)) is None
