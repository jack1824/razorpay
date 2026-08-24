"""A legitimate shopping agent — and, 3% of the time, one that looks like an adversary.

── Distributions ───────────────────────────────────────────────────────────────────────

    inter-arrival   Exponential(mean 4s), with a diurnal multiplier
    amounts         Log-normal, centred near the catalogue price of the chosen item
    categories      Dirichlet-sampled mix per agent, so no two shoppers look alike
    decline ratio   Beta(2, 18) — around 10%, which is a normal card decline rate
    session length  Negative binomial, then a long gap

The diurnal cycle is applied ONLY here. Adversaries deliberately do not follow it, and that
asymmetry is itself an honest signal rather than a planted one: a human-driven shopping agent
is quiet at 4am and a card-testing script is not.

── The 3% that must produce false positives ────────────────────────────────────────────

A fraction of legitimate agents are marked `bursty`. **These must generate false positives.**

A generator whose classes are cleanly separable is a generator that lies. It would give the
model near-perfect scores and would make the one number this project has committed to
reporting honestly — the false-positive cost in rupees — pure fiction.

**The burst has to land in adversary feature space, not merely be faster than usual.** The
first version was a run of same-category purchases at ten times the normal rate. It produced
exactly zero flags — correctly, because a shopper at fifteen requests a minute looks nothing
like a card tester at two hundred and forty, and the model was right to ignore it. A "burst"
no model would ever flag is an overlap that exists only in a README.

So the burst models a specific and entirely legitimate scenario: **a customer whose card
keeps being declined, retrying fast, reaching for a second and third card.** That produces
high velocity, low cadence entropy, elevated BIN diversity and a high decline ratio — the
exact four signals that define card testing. It is the customer the model would block, and
being able to point at them is the whole reason the class overlap exists.

The bursty agents are chosen deterministically from the run seed, and the burst fires at a
seeded request index rather than on a per-request coin flip, so a short run cannot silently
contain no burst at all. The actual fraction is computed and printed at run time rather than
asserted, and `tools/train_risk.py` reports their flag rate separately and warns loudly when
it is zero.
"""

from __future__ import annotations

import math
import time
from typing import Any

from zoo.base import TEST_BINS, Agent, BinPool
from zoo.catalogue import by_category

#: Mean seconds between requests. Fast for a human, ordinary for an agent: this is a
#: program deciding what to buy, not a person browsing. No time compression is applied
#: anywhere in this package, so the velocity a model trains on is the velocity it serves.
MEAN_GAP_SECONDS = 4.0

#: Beta(2, 18): mean 0.10. A tenth of card attempts failing is unremarkable.
DECLINE_ALPHA, DECLINE_BETA = 2.0, 18.0

#: Requests before a long pause. Negative binomial via its Gamma-Poisson mixture.
SESSION_R, SESSION_P = 6.0, 0.5
SESSION_BREAK_SECONDS = 25.0

#: The declined-card retry storm. Sized to land in the same feature region a card tester
#: occupies rather than merely above a shopper's baseline: the same cadence, enough attempts
#: to lift a one-minute velocity, and a decline rate that says why the customer is retrying.
BURST_MIN, BURST_MAX = 20, 32
BURST_GAP_SECONDS = 0.25
BURST_DECLINE_RATE = 0.75


class LegitShopper(Agent):
    name = "legit_shopper"
    request_multiplier = 1.0

    def __init__(self, *args: Any, bursty: bool = False, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.bursty = bursty
        self.grouped = by_category(self.catalogue)
        self._burst_item = None

        # A Dirichlet mix over categories, so each shopper has its own habits and
        # `category_drift` measures a real change rather than the absence of a habit.
        # Sampled as normalised Gammas, which is what a Dirichlet is.
        self.categories = sorted(self.grouped)
        weights = [self.rng.gammavariate(1.6, 1.0) for _ in self.categories]
        total = sum(weights)
        self.mix = [w / total for w in weights]

        # One or two saved cards. This is what makes `bin_diversity` mean something: a
        # principal has a wallet, not a bin range.
        self.bins = BinPool(
            [self.rng.choice(TEST_BINS) for _ in range(self.rng.randint(1, 2))]
        )

        self._cart_id = f"cart-{self.rng.getrandbits(32):08x}"
        self.remaining_in_session = self._session_length()
        self.burst_remaining = 0
        self.burst_category: str | None = None
        self._decline_rate = self.rng.betavariate(DECLINE_ALPHA, DECLINE_BETA)

        # Deterministic: a bursty agent bursts once, starting here. A per-request coin flip
        # meant a short run could contain no burst at all, and "the overlap did not happen
        # this time" is indistinguishable from "there is no overlap".
        self._burst_at = self.rng.randint(4, 10) if self.bursty else None
        self._request_index = 0

        # The extra cards reached for when the first one keeps failing. This is what lifts
        # `bin_diversity` into card-tester territory during a burst.
        self._retry_bins = [self.rng.choice(TEST_BINS) for _ in range(2)]

    def _session_length(self) -> int:
        """Negative binomial, as a Gamma-Poisson mixture."""
        lam = self.rng.gammavariate(SESSION_R, (1 - SESSION_P) / SESSION_P)
        # Poisson by inversion; lam is small enough that this is cheap and exact.
        target, product, count = math.exp(-lam), self.rng.random(), 0
        cumulative = target
        while product > cumulative and count < 60:
            count += 1
            target *= lam / count
            cumulative += target
        return max(2, count)

    def _pick_category(self) -> str:
        draw, cumulative = self.rng.random(), 0.0
        for category, weight in zip(self.categories, self.mix, strict=True):
            cumulative += weight
            if draw <= cumulative:
                return category
        return self.categories[-1]

    def next_request(self) -> dict[str, Any]:
        self._request_index += 1
        if self._burst_at is not None and self._request_index == self._burst_at:
            # The declined-card retry storm: one item, one category, many attempts, several
            # cards. Entirely legitimate and shaped exactly like card testing.
            self.burst_remaining = self.rng.randint(BURST_MIN, BURST_MAX)
            self.burst_category = self._pick_category()
            self._burst_item = self.rng.choice(self.grouped[self.burst_category])

        in_burst = self.burst_remaining > 0
        category = (
            self.burst_category if in_burst and self.burst_category else self._pick_category()
        )
        item = self._burst_item if in_burst else self.rng.choice(self.grouped[category])

        if in_burst:
            # Retrying ONE purchase, so the amount barely moves. That collapses
            # `amount_entropy` the same way a card tester's tight range does.
            amount = max(100, int(item.price_paise * self.rng.uniform(0.98, 1.02)))
            card = self.rng.choice([*self._retry_bins, self.bins.bins[0]])
            self.burst_remaining -= 1
        else:
            # Log-normal around the catalogue price. Real baskets vary in size; a fixed
            # price would make `amount_entropy` a constant and the feature useless.
            amount = max(100, int(item.price_paise * math.exp(self.rng.gauss(0.0, 0.35))))
            card = self.bins.draw(self.rng)

        self.remaining_in_session -= 1
        if self.remaining_in_session <= 0 and not in_burst:
            self.remaining_in_session = self._session_length()
            self._cart_id = f"cart-{self.rng.getrandbits(32):08x}"

        return {
            "amount_paise": amount,
            "category": category,
            "sku": item.sku,
            "instrument_bin": card,
            "cart_id": self._cart_id,
        }

    def next_gap(self) -> float:
        if self.burst_remaining > 0:
            # The same cadence a card tester runs at. A slower burst is a burst no model
            # would ever flag, which is an overlap that exists only on paper.
            return BURST_GAP_SECONDS + self.rng.expovariate(1.0 / BURST_GAP_SECONDS)
        if self.remaining_in_session <= 1:
            return SESSION_BREAK_SECONDS * self.rng.uniform(0.5, 1.5)

        # Diurnal: quiet in the small hours, busy in the evening. Applied to legitimate
        # traffic only — adversaries ignoring the clock is a real signal, not a planted one.
        hour = time.localtime().tm_hour
        diurnal = 1.0 + 0.9 * math.cos((hour - 20) / 24 * 2 * math.pi)
        return self.rng.expovariate(1.0 / (MEAN_GAP_SECONDS * max(0.25, diurnal)))

    def payment_would_succeed(self) -> bool:
        # The burst exists BECAUSE the card is failing. A retry storm with a normal decline
        # rate is not a retry storm, and `failure_ratio` — the feature that most directly
        # describes card testing — would stay flat through the one event meant to trip it.
        rate = BURST_DECLINE_RATE if self.burst_remaining > 0 else self._decline_rate
        return self.rng.random() >= rate
