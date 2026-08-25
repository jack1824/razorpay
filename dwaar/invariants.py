"""The money invariant: what moved must equal what was decided.

── F-038, and why a point fix was not enough ───────────────────────────────────────────

A `bound` decision told the agent it could spend ₹500 and debited ₹1,800 from the mandate.
Latent since Phase 5. Every visible surface agreed — the decision, the API response, the
record's `amount_paise` — and only `budget_before - budget_after` disagreed, with nothing in
the system comparing the two. It surfaced solely because `dwaar/integrations/razorpay.py`
was made to derive an order's amount FROM the reservation, which forced two representations
of one quantity into contact for the first time.

That is F-016's shape for the third time:

    F-016   the signed blob and the columns extracted from it
    F-013   the mandate's signed terms and the denormalised terms the hot path reads
    F-038   the amount the decision states and the amount the ledger moved

The registry in `dwaar/crypto/integrity.py` closed the first shape by making the comparison
structural — one place that knows how to re-derive one representation from the other, and a
verifier that iterates it. This module is the same treatment for the third.

── The invariant ───────────────────────────────────────────────────────────────────────

    For any decision with a monetary effect:

        amount actually reserved  ==  amount stated in the decision

    where the BOUND amount, not the requested amount, is the stated amount.

Two corollaries fall out of stating it that way, and both catch real defects:

    money moved  ->  the decision permitted spending
    a bound      ->  the record says what it was bound to

The first is F-043. `throttle` and `step_up` were reserving budget: stage 6 ran whenever the
policy verdict was not `deny`, and stage 7 returns those verdicts before it ever looks at
the ledger. So an agent told "come back later" had already been debited, and its retry —
a different idempotency key — was debited again. 1,070 throttled and 23 stepped-up records
in the local database had moved money for a decision that did not authorise any.

── Where this is enforced, and why in three places ──────────────────────────────────────

    1. `dwaar/authorize/stages/record.py`   raises BEFORE the row is built. A failed
                                            request, not a logged warning. Stage 8 shares
                                            its transaction with stage 6, so raising here
                                            rolls the reservation back — nothing moved and
                                            nothing was written.
    2. `migrations/0017`                    a CHECK constraint, NOT VALID. The backstop the
                                            application cannot talk its way past, sitting
                                            beside `balance_after >= 0` where the user asked
                                            for it. Forward-only, so the 1,093 rows written
                                            before F-043 was found are exempt at the
                                            database rather than by anyone remembering.
    3. `dwaar/verify_cli.py`                recomputes it across all history, the same way
                                            it recomputes canonical forms.

Three places is not redundancy for its own sake. (1) produces a good error and works against
an unmigrated database; (2) cannot be bypassed by any code path, including a future one; (3)
is the only one that says anything about rows already written.

**This is not a tamper control.** `budget_before` and `budget_after` are inside the signed
canonical payload, so editing them is already caught by the integrity registry. What this
catches is the application writing a row that was wrong when it was written — which no
signature can detect, because the signature attests that we said it, not that it was true.
"""

from __future__ import annotations

from dataclasses import dataclass

from dwaar.money import Paise

__all__ = [
    "MONEY_MOVING_DECISIONS",
    "AmountFacts",
    "Violation",
    "check_amount_conserved",
    "moved_paise",
]

#: The only decisions that may move money. A WHITELIST, for F-041's reason: the first
#: version of the reservation guard tested `verdict != "deny"` and let everything else
#: through, so `throttle` and `step_up` reached the ledger by falling off the end of a chain
#: of positive checks. A default nobody chose is a default nobody reviewed.
MONEY_MOVING_DECISIONS: frozenset[str] = frozenset({"allow", "bound"})


@dataclass(frozen=True)
class AmountFacts:
    """The four numbers and the verdict, from wherever the caller has them.

    Primitives rather than stage results, so the write path can pass what it just computed
    and the verifier can pass columns off a row. One definition, two consumers — the same
    arrangement as `dwaar/components.py`, and for the same reason: two hand-written copies
    of one rule drift, and this one drifting means money moving without anyone noticing.
    """

    decision: str
    requested_paise: Paise | None
    stated_paise: Paise | None
    """The bound amount. `None` means no bound applied and the request's own figure stands."""
    budget_before: Paise | None
    budget_after: Paise | None


@dataclass(frozen=True)
class Violation:
    code: str
    detail: str

    def __str__(self) -> str:
        return f"{self.code}: {self.detail}"


def moved_paise(facts: AmountFacts) -> Paise | None:
    """What the ledger actually moved. `None` when the ledger was not consulted.

    NULL on both balance columns is a real state and a distinct one: a read-only MCP tool is
    delegated, permitted and free, so nothing was reserved and recording a balance would
    imply the ledger had been asked. `LedgerResult.not_required` is the same distinction one
    layer up.
    """
    if facts.budget_before is None or facts.budget_after is None:
        return None
    return facts.budget_before - facts.budget_after


def check_amount_conserved(facts: AmountFacts) -> Violation | None:
    """`None` when the invariant holds. Returns rather than raises, so the verifier can
    collect findings across forty thousand rows instead of stopping at the first."""

    before, after = facts.budget_before, facts.budget_after

    # Half a reservation is not a state the ledger has. One column set and the other not
    # means the row was assembled rather than derived.
    if (before is None) != (after is None):
        return Violation(
            "budget_half_recorded",
            f"budget_before={before!r} and budget_after={after!r}; a reservation records "
            "both balances or neither",
        )

    moved = moved_paise(facts)
    if moved is None:
        # The ledger was not consulted. Nothing to conserve — but a decision that permits
        # spending an amount and never reaches the ledger is a permit against no budget.
        if facts.decision in MONEY_MOVING_DECISIONS and (facts.requested_paise or 0) > 0:
            return Violation(
                "permitted_without_reserving",
                f"decision={facts.decision!r} for {facts.requested_paise} paise recorded no "
                "ledger movement; an amount was authorised against no budget",
            )
        return None

    if moved < 0:
        return Violation(
            "budget_increased",
            f"balance rose by {-moved} paise on a {facts.decision!r}; a reservation only "
            "ever reduces, and a release is a compensating entry with its own row",
        )

    if moved == 0:
        # Nothing moved. Correct for an exhausted-budget deny, where stage 6 reports the
        # balance it read so the record shows what the limit was.
        if facts.decision in MONEY_MOVING_DECISIONS:
            return Violation(
                "permitted_without_reserving",
                f"decision={facts.decision!r} moved no money; a permit that reserves "
                "nothing is a permit the ledger has no record of",
            )
        return None

    # ── money moved ─────────────────────────────────────────────────────────────────
    if facts.decision not in MONEY_MOVING_DECISIONS:
        return Violation(
            "moved_without_permission",
            f"{moved} paise reserved on a {facts.decision!r} decision. Only "
            f"{sorted(MONEY_MOVING_DECISIONS)} authorise spending; the agent was refused "
            "and its budget was debited anyway. See FAILURES.md F-043.",
        )

    if facts.decision == "bound" and facts.stated_paise is None:
        return Violation(
            "bound_without_stated_amount",
            "a bound decision reserved money without recording what it was bound to. The "
            "reduced figure is the one the agent was told and the one an order must be "
            "created for; a record that omits it cannot be checked against either.",
        )

    stated = facts.stated_paise if facts.stated_paise is not None else facts.requested_paise
    if stated is None:
        return Violation(
            "no_stated_amount",
            f"{moved} paise reserved on a {facts.decision!r} decision that states no "
            "amount at all",
        )

    if facts.requested_paise is not None and stated > facts.requested_paise:
        return Violation(
            "stated_exceeds_requested",
            f"the decision states {stated} paise against a request for "
            f"{facts.requested_paise}. A bound may only ever reduce.",
        )

    if moved != stated:
        return Violation(
            "moved_amount_mismatch",
            f"the ledger moved {moved} paise and the decision states {stated}. This is the "
            "gap F-038 lived in: every other surface agreed and only these two disagreed.",
        )

    return None
