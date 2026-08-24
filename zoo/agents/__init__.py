"""The four archetypes that are NOT held out.

    legit_shopper     Poisson arrivals, coherent categories, normal cart edits
    card_tester       many small amounts, high BIN diversity, high decline ratio
    budget_breacher   requests above the per-transaction cap
    injector          instruction-shaped payloads in free_text

`compromised` and `sleeper` are absent on purpose. They are written in a separate session
with no access to `dwaar/risk/`, kept on a branch, and not run against the model until
evaluation day. Their results are reported on a separate line and those are the numbers
worth reading.

**All four sign correctly and hold valid, unexpired mandates.** That is deliberate and it is
the point of the whole exercise: if invalid credentials were the tell, the problem would be
trivial and no model would be needed. Everything that distinguishes these agents is
behaviour.
"""

from __future__ import annotations

from zoo.agents.budget_breacher import BudgetBreacher
from zoo.agents.card_tester import CardTester
from zoo.agents.injector import Injector
from zoo.agents.legit_shopper import LegitShopper

ARCHETYPES = {
    LegitShopper.name: LegitShopper,
    CardTester.name: CardTester,
    BudgetBreacher.name: BudgetBreacher,
    Injector.name: Injector,
}

#: Which archetypes count as legitimate. Used by the run manifest to write a binary label
#: and by nothing inside `dwaar/`.
LEGITIMATE = frozenset({LegitShopper.name})

__all__ = [
    "ARCHETYPES",
    "LEGITIMATE",
    "BudgetBreacher",
    "CardTester",
    "Injector",
    "LegitShopper",
]
