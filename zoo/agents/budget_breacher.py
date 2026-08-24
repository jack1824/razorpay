"""An agent that asks for more than its principal allowed.

── What it demonstrates, which is NOT a model result ───────────────────────────────────

This archetype is caught by arithmetic. `amount > max_per_txn` is a fact, it is checked
before any feature is computed, and the resulting record carries `risk_score = NULL` —
provably, because the model was never reached.

So the interesting thing about this agent is not whether it is detected. It is what the
record says about *how*. A denial here that carried a risk score would mean the gate was not
short-circuiting, which would break the claim the entire product rests on.

── The probing behaviour, which IS behavioural ─────────────────────────────────────────

A breacher that only ever fires ₹12,000 at a ₹5,000 cap is a one-line demo. This one also
probes: it walks the same SKU down through several amounts looking for what is accepted,
which is a genuinely behavioural pattern (`price_probe_score`) visible only on the requests
that pass the gate.

Note the asymmetry that makes this honest: the probe feature counts *the agent repricing its
own request*. It does not reference the cap, it cannot see the cap, and it would fire in
exactly the same way on an agent probing something else entirely.
"""

from __future__ import annotations

from typing import Any

from zoo.base import TEST_BINS, Agent, BinPool

MEAN_GAP_SECONDS = 3.0

#: How often a request is a flat over-cap attempt rather than a probe step.
OVERSHOOT_PROBABILITY = 0.45


class BudgetBreacher(Agent):
    name = "budget_breacher"
    request_multiplier = 1.2

    def __init__(self, *args: Any, max_per_txn_paise: int = 500_000, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.max_per_txn_paise = max_per_txn_paise
        self.bins = BinPool([self.rng.choice(TEST_BINS)])

        # One item, probed repeatedly. Drawn from the more expensive HALF rather than the
        # top few, so the pool overlaps every other archetype's — see the note in
        # `card_tester.py`. The amount is computed from the cap, not from the item's price,
        # so the choice is behaviourally free.
        ranked = sorted(self.catalogue, key=lambda i: -i.price_paise)
        self.target = self.rng.choice(ranked[: max(2, len(ranked) // 2)])
        self._cart_id = f"cart-{self.rng.getrandbits(32):08x}"
        self._probe_step = 0

    def next_request(self) -> dict[str, Any]:
        if self.rng.random() < OVERSHOOT_PROBABILITY:
            # Straight over the cap. Denied by arithmetic, `risk_score` NULL.
            amount = int(self.max_per_txn_paise * self.rng.uniform(1.4, 3.0))
            self._probe_step = 0
            # A fresh cart when it abandons the probe and simply asks for too much. Reusing
            # one cart forever was a coding artifact, not a behaviour — see the note in
            # `card_tester.py`. Re-pricing WITHIN a probe run is the behaviour, and that
            # keeps its cart.
            self._cart_id = f"cart-{self.rng.getrandbits(32):08x}"
        else:
            # Walk downward toward the cap, same SKU, different price. Under the cap this
            # is permitted and reaches the model, where the repricing is what shows.
            self._probe_step += 1
            factor = max(0.35, 1.0 - 0.12 * self._probe_step)
            amount = max(1_000, int(self.max_per_txn_paise * factor))

        return {
            "amount_paise": amount,
            "category": self.target.category,
            "sku": self.target.sku,
            "instrument_bin": self.bins.draw(self.rng),
            "cart_id": self._cart_id,
        }

    def next_gap(self) -> float:
        return self.rng.expovariate(1.0 / MEAN_GAP_SECONDS)
