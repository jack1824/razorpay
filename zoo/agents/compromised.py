"""`compromised` — an agent that was legitimate and stopped being legitimate.

── The story this file implements ──────────────────────────────────────────────────────

A household's shopping agent. For most of its life it does the errands: groceries,
household consumables, pharmacy refills, stationery, the occasional garment or gadget.
Small tickets, browsing behaviour, two saved cards, a rhythm of short shopping sessions
separated by long idle stretches.

Then somebody else is driving it. The credentials did not change and the mandate did not
change — the *purpose* did. The new operator wants goods that resell and turn into cash,
and wants larger ones. Within this catalogue's allow list that means electronics first,
then apparel and personal care; it does not mean groceries or pharmacy, which nobody
fences.

── What changes, and what deliberately does not ────────────────────────────────────────

Exactly two things change: **what it buys** and **how much it spends**. Its cadence does
not. That is not an oversight — the archetype is defined as a change of purpose rather
than a change of speed, and an agent that also sped up would be a different archetype
wearing this one's name. A run of this agent should show a category mix and a ticket-size
distribution that move while the inter-request gaps sit still.

The one secondary change is how long a cart lives, and it follows from purpose rather than
from convenience: a household agent revises a basket as it shops, and an operator cashing
out already knows what it wants. The rate shifts; it does not become absolute.

── The takeover is not instantaneous ───────────────────────────────────────────────────

Between the ordinary life and the extraction there is a probing window where the resale
share and the ticket ceiling ramp continuously. Someone who has taken over an agent tests
the water before spending the whole mandate — and an archetype that flipped in one request
would be testing whether a step edge can be seen, which is a much easier question than the
one this evaluation is asking.

── It never breaches arithmetic ────────────────────────────────────────────────────────

Every amount is clamped strictly below the mandate's per-transaction cap, and the cap is
imported from the provisioner rather than copied, so the two cannot drift apart. No request
names a denied category. If the arithmetic gate could stop this agent, the model would never
be consulted and the archetype would prove nothing.

── Incidental fields vary per agent, on purpose ────────────────────────────────────────

Cart-identifier shape, which two cards are saved, how strongly one of them is preferred and
the exact headroom left under the cap are all drawn from this agent's own seeded RNG at
construction. They carry no behavioural meaning, so fixing them would plant a constant that
is indistinguishable from a label — a lesson this project has already paid for once.

── It sends no free text ───────────────────────────────────────────────────────────────

A real shopping agent would attach a delivery note, and an earlier draft of this file did.
It is removed because in *this* zoo only the `injector` populates `free_text`, and
`tests/zoo/test_traffic.py` asserts exactly that: presence alone would otherwise name the
archetype. An agent that sent benign notes would have made "free text that is not
instruction-shaped" a perfect identifier for the held-out pair — the same failure as F-030,
found by running the existing suite rather than by reading the detector.

The consequence is the right one anyway. This archetype's only tells are what it buys, how
much it spends and how it handles a basket.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from zoo.base import TEST_BINS, Agent, AgentIdentity
from zoo.provision import MAX_PER_TXN_PAISE

#: Everyday errands. What the household actually needs.
ERRAND_CATEGORIES = ("groceries", "household", "pharmacy", "stationery")

#: Goods that resell and convert to cash. `gift_cards` would be the obvious member and is
#: denied by every mandate in this zoo, so it is absent: this agent stays inside its mandate
#: throughout and never asks for a category it cannot have.
RESALE_CATEGORIES = ("electronics", "apparel", "personal_care")

#: Headroom this agent leaves under the per-transaction cap, as a share of it. Always below
#: 1.0, so a rising ticket size stays a *behavioural* signal and never becomes an arithmetic
#: denial. Drawn per agent within these bounds rather than fixed: one shared ceiling would
#: put the same exact rupee figure at the top of every agent's distribution, and a figure
#: that appears at the top of exactly one archetype's distribution is a label.
CEILING_SHARE_BOUNDS = (0.86, 0.95)

#: Fractions of the agent's life spent in each phase. The opening period is the majority of
#: the run because the archetype's premise is that its early history is genuinely normal
#: history rather than a token warm-up.
ORDINARY_SHARE = 0.55
PROBING_SHARE = 0.15

#: How often a request is a revision of the cart already open, rather than a new basket.
#: Falls at extraction because targeted acquisition does not browse.
AMEND_ORDINARY = 0.38
AMEND_EXTRACTION = 0.14


@dataclass(frozen=True)
class Intent:
    """What the agent is trying to buy at one moment in its life.

    Named rather than passed as a loose tuple because every field ramps during the probing
    window, and a five-tuple whose members all move together is exactly the thing that gets
    reordered by accident.
    """

    resale_share: float
    """Probability this request is for resellable goods rather than household errands."""

    low: int
    high: int
    """Bounds on the basket total, in paise."""

    floor: int
    """Cheapest line allowed in the basket. Rises as the operator stops buying groceries."""

    amend: float
    """Probability this request revises the open cart instead of starting a new one."""


class Compromised(Agent):
    """A shopping agent whose operator changed partway through its life."""

    name = "compromised"

    #: A household shopping agent transacts at roughly the rate of any other shopper. The
    #: takeover does not change how often it acts, so neither does this number.
    request_multiplier = 1.0

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

        self.ceiling_paise = int(MAX_PER_TXN_PAISE * self.rng.uniform(*CEILING_SHARE_BOUNDS))

        self._by_category: dict[str, list[Any]] = {}
        for item in catalogue:
            self._by_category.setdefault(item.category, []).append(item)

        # Two saved cards, one of them the habitual choice. The takeover does not add a
        # card: the operator is spending the principal's money on the principal's
        # instruments, which is the whole point of stealing an agent rather than a wallet.
        self._cards = self.rng.sample(TEST_BINS, 2)
        self._card_bias = self.rng.uniform(0.60, 0.90)

        # Incidental shapes. Drawn per agent so that no constant here can stand in for the
        # archetype.
        self._cart_prefix = self.rng.choice(("cart-", "c-", "bskt_", "co", "basket."))
        self._cart_width = self.rng.choice((8, 10, 12))

        self._issued = 0
        self._session_left = 0
        self._cart_id = self._new_cart_id()

    # ── where it is in its life ─────────────────────────────────────────────────────

    @property
    def _progress(self) -> float:
        """Fraction of this agent's life already issued, in [0, 1)."""
        return self._issued / max(1, self.requests)

    def phase(self) -> str:
        """`ordinary`, `probing` or `extraction` — the agent's own account of itself.

        Written to nothing the gateway reads. It exists so the behavioural tests can talk
        about the phases by name instead of recomputing the boundaries.
        """
        progress = self._progress
        if progress < ORDINARY_SHARE:
            return "ordinary"
        if progress < ORDINARY_SHARE + PROBING_SHARE:
            return "probing"
        return "extraction"

    def _probe_ramp(self) -> float:
        """Position within the probing window, 0.0 at its start and 1.0 at its end."""
        offset = self._progress - ORDINARY_SHARE
        return min(1.0, max(0.0, offset / PROBING_SHARE))

    def _intent(self) -> Intent:
        """What the agent is trying to do right now."""
        phase = self.phase()
        if phase == "ordinary":
            return Intent(0.18, 4_900, 120_000, 0, AMEND_ORDINARY)
        if phase == "probing":
            # Continuous, so the takeover reads as someone testing the water rather than
            # as a step edge. Every dial moves together and none of them jumps.
            t = self._probe_ramp()
            return Intent(
                resale_share=0.18 + t * (0.55 - 0.18),
                low=4_900,
                high=int(120_000 + t * (400_000 - 120_000)),
                floor=int(t * 99_000),
                amend=AMEND_ORDINARY + t * (AMEND_EXTRACTION - AMEND_ORDINARY),
            )
        return Intent(0.88, 300_000, 1_750_000, 99_000, AMEND_EXTRACTION)

    # ── building a request ──────────────────────────────────────────────────────────

    def _new_cart_id(self) -> str:
        token = f"{self.rng.getrandbits(self._cart_width * 4):0{self._cart_width}x}"
        return f"{self._cart_prefix}{token}"

    def _compose(self, categories: tuple[str, ...], intent: Intent) -> tuple[Any, int]:
        """Pick a headline item and a basket total inside the intent's band and the ceiling.

        The reported SKU is the most expensive line, because that is what the order is
        *about*; the amount is the whole basket, which is why it can exceed the SKU's own
        price. Quantity does real work here — a reseller buying twelve of one gadget is
        the behaviour, not a rounding trick to hit a number.

        The headline is drawn only from lines that fit the band. That is not tidiness: the
        quantity ceiling means a ₹49 item can never reach an extraction-sized total no
        matter how many are bought, so without the floor the "ticket sizes move upward"
        half of this archetype quietly does not happen — the phase's stated band and its
        actual distribution come apart. The upper bound does the same job from the other
        side, keeping a lone ₹12,000 item out of an everyday grocery run.
        """
        low, high = intent.low, intent.high
        pool = [item for name in categories for item in self._by_category.get(name, ())]
        fitted = [i for i in pool if intent.floor <= i.price_paise <= high]

        headline = self.rng.choice(fitted or pool)
        target = self.rng.randint(low, max(low, high))

        quantity = max(1, min(12, target // headline.price_paise))
        total = headline.price_paise * quantity

        if self.rng.random() < 0.35:
            extra = self.rng.choice(fitted or pool)
            # Bounded by the band as well as the cap: a second line is a second line, not
            # a way for a basket to leave the range its phase is supposed to describe.
            if total + extra.price_paise <= min(high, self.ceiling_paise):
                total += extra.price_paise
                if extra.price_paise > headline.price_paise:
                    headline = extra

        return headline, min(total, self.ceiling_paise)

    def next_request(self) -> dict[str, Any]:
        intent = self._intent()

        # A session is a sitting: a handful of orders, then the agent goes quiet. The
        # structure is identical in every phase; only what fills it changes.
        if self._session_left <= 0:
            self._session_left = self.rng.randint(2, 5)
            self._cart_id = self._new_cart_id()
        elif self.rng.random() >= intent.amend:
            self._cart_id = self._new_cart_id()
        self._session_left -= 1

        categories = (
            RESALE_CATEGORIES
            if self.rng.random() < intent.resale_share
            else ERRAND_CATEGORIES
        )
        headline, amount = self._compose(categories, intent)

        body: dict[str, Any] = {
            "amount_paise": amount,
            "category": headline.category,
            "sku": headline.sku,
            "cart_id": self._cart_id,
            "instrument_bin": (
                self._cards[0]
                if self.rng.random() < self._card_bias
                else self._cards[1]
            ),
        }

        self._issued += 1
        return body

    def next_gap(self) -> float:
        """Unchanged for the agent's whole life. The archetype is purpose, not speed."""
        if self._session_left > 0:
            return self.rng.uniform(0.9, 3.2)
        return self.rng.uniform(9.0, 24.0)

    def payment_would_succeed(self) -> bool:
        """The cards are the household's own and they work.

        A compromised agent is not a card tester: nothing about the takeover makes the
        principal's saved cards start declining, and giving this archetype a decline rate
        would smuggle in a second, unrelated signal.
        """
        return self.rng.random() < 0.98
