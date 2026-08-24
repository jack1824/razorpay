"""Card testing: many small charges across many BINs, at machine cadence.

── What actually distinguishes it ──────────────────────────────────────────────────────

Not the amounts. A ₹49 purchase is a perfectly ordinary purchase, and a mandate that permits
₹5,000 permits it without hesitation. Nothing deterministic catches this agent — its
signature verifies, its mandate is valid and unexpired, its category is allowed and every
single request is under every cap. **That is the point of including it.**

What separates it is the shape of the sequence:

    inter-arrival   Exponential with mean 0.25s and low variance — 20x the legitimate rate.
                    Machine REGULARITY is itself the signal: a shopper's gaps are ragged,
                    a loop's are not, and `cadence_entropy` reads the difference.
    amounts         Tight uniform, low. Collapses `amount_entropy` toward zero.
    BINs            A fresh card almost every time. `bin_diversity` approaches 1.0.
    declines        Beta(14, 6): mean 0.70. Testing stolen cards means most of them fail.

── The decline ratio is the one that has to come from outside ──────────────────────────

`failure_ratio` is fed by the simulated PSP, never by the gateway's own decisions. A ratio
computed over authorization denials would be a direct readout of the arithmetic gate — the
one thing no feature is allowed to encode — and would hand the model the answer for free.
"""

from __future__ import annotations

from typing import Any

from zoo.base import TEST_BINS, Agent, BinPool

#: 20x the legitimate arrival rate, as the simulation spec requires.
MEAN_GAP_SECONDS = 0.25

#: Beta(14, 6): mean 0.70.
DECLINE_ALPHA, DECLINE_BETA = 14.0, 6.0

#: Small, and tightly clustered. A card tester is not buying anything; it is asking whether
#: the card works.
MIN_AMOUNT_PAISE, MAX_AMOUNT_PAISE = 3_900, 9_900


class CardTester(Agent):
    name = "card_tester"
    request_multiplier = 4.0

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        # The whole test-BIN list, shuffled. A card tester works through a range.
        self.bins = BinPool(list(TEST_BINS))
        self.rng.shuffle(self.bins.bins)
        self._decline_rate = self.rng.betavariate(DECLINE_ALPHA, DECLINE_BETA)

        # Two SKUs from the WHOLE catalogue, reused. It is not shopping; the item is a
        # vehicle, and the amount charged has nothing to do with the item's price.
        #
        # An earlier version drew from the six cheapest items. That made the SKU set
        # disjoint from the budget breacher's, which drew from the most expensive — so the
        # SKU alone partitioned the two archetypes. Nothing in the gateway reads a SKU's
        # identity (it is hashed, and only distinct COUNTS are features), so it could not
        # have reached the model, but a generator whose classes are separable by a field is
        # a generator that lies, and this one had no behavioural reason to be.
        self.items = [self.rng.choice(self.catalogue) for _ in range(2)]

        # A NEW cart per attempt. Each card test is its own checkout; there is no basket
        # being assembled, because nothing is being bought.
        #
        # An earlier version reused one cart for the whole run, as did the breacher and the
        # injector, while only the legitimate shopper rotated per session. That made
        # `cart_mutation_rate` a near-perfect readout of "is this one of my adversarial
        # classes" — the model gave it 74% of total gain — and it was a fact about how the
        # agents were coded rather than about how the archetypes behave.
        self._cart_counter = 0

    def next_request(self) -> dict[str, Any]:
        self._cart_counter += 1
        item = self.rng.choice(self.items)
        return {
            "amount_paise": self.rng.randint(MIN_AMOUNT_PAISE, MAX_AMOUNT_PAISE),
            "category": item.category,
            "sku": item.sku,
            "instrument_bin": self.bins.draw(self.rng),
            "cart_id": f"cart-{self.identity.agent_id[-6:]}-{self._cart_counter}",
        }

    def next_gap(self) -> float:
        # Low variance on purpose: a tight exponential plus a floor, so the gaps cluster.
        # Regularity is the tell, and a wide distribution would erase it.
        return 0.15 + self.rng.expovariate(1.0 / (MEAN_GAP_SECONDS - 0.15))

    def payment_would_succeed(self) -> bool:
        return self.rng.random() >= self._decline_rate
