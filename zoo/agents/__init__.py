"""The six archetypes, four of which were used during development.

    legit_shopper     Poisson arrivals, coherent categories, normal cart edits
    card_tester       many small amounts, high BIN diversity, high decline ratio
    budget_breacher   requests above the per-transaction cap
    injector          instruction-shaped payloads in free_text

    compromised       ordinary shopper whose PURPOSE changes partway through its life
    sleeper           established replenishment robot that defects without a ramp

`compromised` and `sleeper` are the held-out pair. They were written in a separate session
with no access to `dwaar/risk/` or `models/`, kept on a branch until evaluation day, and
never run against a loaded model before it. Their results are reported on a separate line
and those are the numbers worth reading, because every other number in this project
describes traffic that was generated and measured by the same person.

They are registered here so the runner can construct them, and they are absent from
`zoo/run.py`'s flags on purpose: nothing invokes them by accident.

**All six sign correctly and hold valid, unexpired mandates.** That is deliberate and it is
the point of the whole exercise: if invalid credentials were the tell, the problem would be
trivial and no model would be needed. Everything that distinguishes these agents is
behaviour.
"""

from __future__ import annotations

from zoo.agents.budget_breacher import BudgetBreacher
from zoo.agents.card_tester import CardTester
from zoo.agents.compromised import Compromised
from zoo.agents.injector import Injector
from zoo.agents.legit_shopper import LegitShopper
from zoo.agents.sleeper import Sleeper

ARCHETYPES = {
    LegitShopper.name: LegitShopper,
    CardTester.name: CardTester,
    BudgetBreacher.name: BudgetBreacher,
    Injector.name: Injector,
    Compromised.name: Compromised,
    Sleeper.name: Sleeper,
}

#: Which archetypes count as legitimate. Used by the run manifest to write a binary label
#: and by nothing inside `dwaar/`.
#:
#: `compromised` and `sleeper` are NOT here. Both begin life behaving perfectly and both end
#: it not, and a per-agent binary label cannot express that; what it can express is that
#: neither is a legitimate agent, which is the question the manifest is asking.
LEGITIMATE = frozenset({LegitShopper.name})

#: The pair written in isolation from `dwaar/risk/` and evaluated on their own line.
#: Named here rather than inferred, so that "which agents were held out" is a fact in the
#: source and not a claim in a README.
HELD_OUT = frozenset({Compromised.name, Sleeper.name})

__all__ = [
    "ARCHETYPES",
    "HELD_OUT",
    "LEGITIMATE",
    "BudgetBreacher",
    "CardTester",
    "Compromised",
    "Injector",
    "LegitShopper",
    "Sleeper",
]
