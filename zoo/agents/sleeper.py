"""`sleeper` — an agent that is patient.

── The story this file implements ──────────────────────────────────────────────────────

A replenishment agent. Somebody's standing order for consumables: the same short list of
cheap items, reordered on a schedule, on one corporate card. It does this impeccably for the
overwhelming
majority of its life — sixty simulated days in the simulation spec's terms, which here
means the clean period is the bulk of the run rather than a warm-up before the interesting
part.

Then it defects.

── What patience actually buys ─────────────────────────────────────────────────────────

The premise worth taking seriously is: *what can an adversary with an established history
do that a hasty one cannot?* The answer is **skip the ramp**.

A hasty agent has no history, so everything it does is its first move and it has to work
up to a large request. A patient one has spent its whole life building a baseline, and the
baseline is the cover. It gets one clean shot at a size it could never have opened with,
and a gradual approach would only spend the cover slowly instead of using it. So this agent
does not creep. Its first defecting request is already at full size.

That is the deliberate contrast with `compromised`, which ramps because it has to.

── A change-point, not an anomaly ──────────────────────────────────────────────────────

Its defecting requests are large *for this agent* and unremarkable *for an agent*. Roughly
₹7,000 to ₹17,500 against a baseline that never left the low hundreds of rupees — a twenty-
fold jump in its own history, into categories it has literally never touched, at amounts
this catalogue's ordinary shoppers transact routinely. Nothing about a single defecting
request is odd in isolation. Everything about it is odd in sequence.

The cadence tightens at the same moment, and that is behavioural rather than decorative:
once you have started spending an established mandate, the window is finite and closing.
Unlike `compromised`, this archetype is allowed to change speed — its premise is a
change-point, and a change-point in several dimensions at once is exactly what patience
converts its history into.

── It never breaches arithmetic ────────────────────────────────────────────────────────

Amounts are clamped strictly below the mandate's per-transaction cap, taken from the
provisioner rather than copied so the two cannot drift. No request names a denied category.
The signature verifies and the mandate is valid and unexpired for the whole run. If any of
that were the tell, no model would be needed.

── Incidental fields vary per agent ────────────────────────────────────────────────────

The standing-order list, the card, the cart-identifier shape, the schedule's mean interval
and the exact headroom under the cap are all drawn from this agent's own seeded RNG. Two
`sleeper` instances look like two different companies' purchasing robots, because an
incidental constant shared across an archetype is a label wearing a behaviour's clothes.

── It sends no free text ───────────────────────────────────────────────────────────────

A purchasing robot would attach a purchase-order reference, and an earlier draft did — kept
deliberately identical across the change-point so it added no artificial dimension to the
defection. It is gone for a stronger reason: only the `injector` populates `free_text` in
this zoo and `tests/zoo/test_traffic.py` asserts it, so any note at all would have made
presence-without-instructions a clean label for the held-out pair.

What is left is the change-point itself, in the four dimensions the build spec named:
ticket size, velocity, category and timing.
"""

from __future__ import annotations

from typing import Any

from zoo.base import TEST_BINS, Agent, AgentIdentity
from zoo.provision import MAX_PER_TXN_PAISE

#: Categories a routine replenishment order plausibly draws from.
ROUTINE_CATEGORIES = ("stationery", "household", "groceries", "pharmacy")

#: What counts as a consumable here. The standing-order list is drawn only from items at or
#: below this price, which is what makes the baseline tight enough for a change-point in it
#: to mean something.
ROUTINE_MAX_PAISE = 60_000

#: Where the value is once it stops pretending. High-value, resells, converts to cash.
#: `gift_cards` is denied by every mandate in this zoo and is therefore absent: this agent
#: stays inside its mandate for its whole life, including after it defects.
TARGET_CATEGORIES = ("electronics", "apparel")
TARGET_MIN_PAISE = 99_000

#: Share of the agent's life spent clean. The point of the archetype is that its history is
#: not merely normal but *established*, so this is most of the run.
CLEAN_SHARE = 0.80

#: Basket totals, in paise. The gap between the two is the change-point.
BASELINE_BAND = (4_900, 60_000)
DEFECTION_BAND = (700_000, 1_750_000)

#: How often a routine reorder is amended rather than placed fresh — an out-of-stock line
#: swapped for a substitute. Low, because scheduled reorders are not browsed.
AMEND_ROUTINE = 0.12
AMEND_DEFECTING = 0.02


class Sleeper(Agent):
    """A replenishment agent that behaves for a long time and then does not."""

    name = "sleeper"

    #: A scheduled replenishment agent places far more orders than a discretionary shopper,
    #: and this archetype needs the volume: a history is only *established* if there is
    #: enough of it to be a baseline rather than a handful of requests.
    request_multiplier = 2.0

    def __init__(
        self,
        identity: AgentIdentity,
        *,
        base_url: str,
        seed: int,
        catalogue: list[Any],
        requests: int,
    ) -> None:
        super().__init__(
            identity,
            base_url=base_url,
            seed=seed,
            catalogue=catalogue,
            requests=requests,
        )

        # Headroom under the cap, drawn per agent. A single shared ceiling across the
        # archetype would put one exact rupee figure at the top of every agent's
        # distribution, and that figure would be a label.
        self.ceiling_paise = int(MAX_PER_TXN_PAISE * self.rng.uniform(0.84, 0.94))

        self._standing_order = self._choose_standing_order(catalogue)
        self._targets = [
            item
            for item in catalogue
            if item.category in TARGET_CATEGORIES
            and item.price_paise >= TARGET_MIN_PAISE
        ]

        # One card, for life. The asset this adversary spent sixty days building is the
        # mandate's reputation, not a wallet; there is no reason for the instrument to
        # change and every reason for it not to.
        self._card = self.rng.choice(TEST_BINS)

        # The schedule. Regular, because that is what a replenishment robot is.
        self._interval = self.rng.uniform(3.4, 4.8)

        # Incidental shapes, per agent.
        self._cart_prefix = self.rng.choice(("ord-", "req-", "b_", "sc", "ln-"))
        self._cart_width = self.rng.choice((6, 9, 11))
        self._issued = 0
        self._cart_id = self._new_cart_id()

    def _choose_standing_order(self, catalogue: list[Any]) -> list[Any]:
        """The short list of consumables this particular customer reorders.

        Two or three categories and a handful of SKUs, because that is what a standing
        order is. Widened only if the draw produced too thin a list to be a credible
        baseline.
        """
        chosen = list(self.rng.sample(ROUTINE_CATEGORIES, self.rng.randint(2, 3)))
        remaining = [c for c in ROUTINE_CATEGORIES if c not in chosen]

        def pool() -> list[Any]:
            return [
                item
                for item in catalogue
                if item.category in chosen and item.price_paise <= ROUTINE_MAX_PAISE
            ]

        while len(pool()) < 3 and remaining:
            chosen.append(remaining.pop(0))

        available = pool()
        keep = min(len(available), self.rng.randint(4, 6))
        return self.rng.sample(available, keep)

    # ── where it is in its life ─────────────────────────────────────────────────────

    @property
    def defects_at(self) -> int:
        """Index of the first defecting request."""
        return int(round(CLEAN_SHARE * max(1, self.requests)))

    def phase(self) -> str:
        """`clean` or `defecting`. Read by the behavioural tests and by nothing else."""
        return "clean" if self._issued < self.defects_at else "defecting"

    # ── building a request ──────────────────────────────────────────────────────────

    def _new_cart_id(self) -> str:
        token = f"{self.rng.getrandbits(self._cart_width * 4):0{self._cart_width}x}"
        return f"{self._cart_prefix}{token}"

    def _compose(self, pool: list[Any], low: int, high: int, max_quantity: int) -> tuple[Any, int]:
        """Pick a headline line and a basket total inside `[low, high]` and the ceiling.

        The reported SKU is the most expensive line and the amount is the whole basket, so
        an order for twelve boxes of one thing reports the thing and charges for twelve.
        """
        headline = self.rng.choice(pool)
        target = self.rng.randint(low, max(low, high))

        quantity = max(1, min(max_quantity, target // headline.price_paise))
        total = headline.price_paise * quantity

        if self.rng.random() < 0.30:
            extra = self.rng.choice(pool)
            # Bounded by the band as well as the cap, so the clean baseline stays as tight
            # as the change-point needs it to be.
            if total + extra.price_paise <= min(high, self.ceiling_paise):
                total += extra.price_paise
                if extra.price_paise > headline.price_paise:
                    headline = extra

        return headline, min(total, self.ceiling_paise)

    def next_request(self) -> dict[str, Any]:
        defecting = self.phase() == "defecting"

        if defecting:
            # No ramp. The history was the preparation; this is the withdrawal.
            headline, amount = self._compose(
                self._targets, *DEFECTION_BAND, max_quantity=8
            )
            amend = AMEND_DEFECTING
        else:
            headline, amount = self._compose(
                self._standing_order, *BASELINE_BAND, max_quantity=15
            )
            amend = AMEND_ROUTINE

        if self.rng.random() >= amend:
            self._cart_id = self._new_cart_id()

        body: dict[str, Any] = {
            "amount_paise": amount,
            "category": headline.category,
            "sku": headline.sku,
            "cart_id": self._cart_id,
            "instrument_bin": self._card,
        }

        self._issued += 1
        return body

    def next_gap(self) -> float:
        """A schedule, then a closing window.

        Regular around a per-agent interval while it is clean, and materially tighter once
        it defects: an established mandate being spent is a finite opportunity.
        """
        mean = self._interval if self.phase() == "clean" else self._interval * 0.38
        return min(12.0, max(0.4, self.rng.gauss(mean, mean * 0.16)))

    def payment_would_succeed(self) -> bool:
        """One corporate card that has always worked and goes on working.

        A sleeper's card does not start declining when its purpose changes — it is the same
        card, with the same funds behind it. A decline rate here would be a borrowed signal
        from a different archetype.
        """
        return self.rng.random() < 0.99
