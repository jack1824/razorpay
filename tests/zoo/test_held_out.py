"""Behavioural assertions for the two held-out archetypes.

── What this file is allowed to assert ─────────────────────────────────────────────────

That the agents DO what their specification says they do: that `compromised`'s category mix
and ticket sizes shift, that `sleeper` has a change-point in its own history, that both stay
inside their mandate for their whole lives, and that both are reproducible under a seed.

── What this file must never assert ────────────────────────────────────────────────────

Anything about whether the model catches them. Not a score, not a band, not a decision, not
a feature name. A test that asserted "the detector flags `sleeper`" would close exactly the
feedback loop the isolation exists to prevent: the agents would be tuned until the assertion
passed, and evaluation day would then measure the tuning rather than the system. The
detector's opinion is an evaluation-day output, and the only honest place to read it is
once, afterwards.

Nothing here starts a gateway or sends a request. Every assertion is made against request
bodies built in memory.
"""

from __future__ import annotations

import re
from statistics import median

import pytest

from zoo import catalogue as cataloguemod
from zoo.agents import ARCHETYPES, HELD_OUT, LEGITIMATE
from zoo.agents.compromised import Compromised
from zoo.agents.sleeper import Sleeper
from zoo.base import AgentIdentity
from zoo.provision import ALLOW_CATEGORIES, DENY_CATEGORIES, MAX_PER_TXN_PAISE

BASE_URL = "http://127.0.0.1:8080"

#: Long enough that each archetype's phases contain enough requests to describe a
#: distribution, and that a change-point has a baseline on both sides of it.
REQUESTS = 200

#: Every distributional claim is asserted across several agents rather than one.
#: A behavioural threshold that holds at exactly one seed is a coincidence with a test
#: around it, and these archetypes are run in groups on evaluation day anyway.
#:
#: The bounds below are set with real margin under the worst case observed over a 200-seed
#: sweep, so the suite fails when an archetype stops behaving and not when a draw is
#: unlucky. Widening one to make it pass would be the tell that the behaviour changed.
SEEDS = (3, 17, 90210, 20260827)


def identity(suffix: str = "held00") -> AgentIdentity:
    return AgentIdentity(
        agent_id=f"agt_{'0' * (12 - len(suffix))}{suffix}"[:16],
        principal_id="prn_000000000001",
        mandate_id="mnd_000000000001",
        seed=4242,
    )


@pytest.fixture(scope="module")
def catalogue():
    return cataloguemod.load()


def build(cls, catalogue, *, seed: int = 90210, requests: int = REQUESTS):
    return cls(
        identity(),
        base_url=BASE_URL,
        seed=seed,
        catalogue=catalogue,
        requests=requests,
    )


def drain(agent) -> list[dict]:
    """Every request body the agent would send, with the gap it would wait afterwards.

    Uses `build_body` rather than `next_request` so the bodies are exactly what would go on
    the wire, idempotency key included.
    """
    bodies = []
    for _ in range(agent.requests):
        # Read the phase BEFORE building: `next_request` advances the agent's counter, so
        # asking afterwards labels each request with the phase of the one that follows it
        # and smears the change-point by exactly one request.
        phase = agent.phase()
        body = agent.build_body()
        body["_gap"] = agent.next_gap()
        body["_phase"] = phase
        bodies.append(body)
    return bodies


# ── registration ────────────────────────────────────────────────────────────────────


def test_both_archetypes_are_registered():
    assert ARCHETYPES["compromised"] is Compromised
    assert ARCHETYPES["sleeper"] is Sleeper


def test_neither_is_labelled_legitimate():
    assert not HELD_OUT & LEGITIMATE
    assert {"compromised", "sleeper"} == HELD_OUT


def test_neither_is_wired_into_the_runner_defaults():
    """They are invoked explicitly on evaluation day, never by running `python -m zoo.run`."""
    source = (__import__("pathlib").Path("zoo/run.py")).read_text(encoding="utf-8")
    assert "compromised" not in source
    assert "sleeper" not in source


# ── the mandate holds for both, for their whole lives ───────────────────────────────


@pytest.mark.parametrize("cls", [Compromised, Sleeper])
def test_never_breaches_the_per_transaction_cap(cls, catalogue):
    """If arithmetic could stop these agents they would prove nothing.

    Asserted against the provisioner's own constant, not a copy, so tightening the mandate
    cannot silently turn either archetype into a budget breacher.
    """
    amounts = [body["amount_paise"] for body in drain(build(cls, catalogue))]
    assert amounts
    assert max(amounts) < MAX_PER_TXN_PAISE
    assert min(amounts) >= 1


@pytest.mark.parametrize("cls", [Compromised, Sleeper])
def test_never_requests_a_denied_category(cls, catalogue):
    categories = {body["category"] for body in drain(build(cls, catalogue))}
    assert not categories & set(DENY_CATEGORIES)
    assert categories <= set(ALLOW_CATEGORIES)


@pytest.mark.parametrize("cls", [Compromised, Sleeper])
def test_neither_sends_free_text(cls, catalogue):
    """Only the `injector` populates `free_text` in this zoo.

    Both of these archetypes would plausibly attach a note — a delivery instruction, a
    purchase-order reference — and both earlier drafts did. Presence alone would then have
    identified the held-out pair as "free text that is not instruction-shaped", which is
    F-030 again in a different field. `tests/zoo/test_traffic.py` asserts the invariant
    across every archetype; this asserts it where it would be reintroduced.
    """
    assert all("free_text" not in body for body in drain(build(cls, catalogue)))


@pytest.mark.parametrize("cls", [Compromised, Sleeper])
def test_bodies_satisfy_the_wire_contract(cls, catalogue):
    """Field-level shape, so an agent cannot fail evaluation day on a 422."""
    for body in drain(build(cls, catalogue)):
        assert body["action"] == "purchase"
        assert 16 <= len(body["idempotency_key"]) <= 64
        assert re.fullmatch(r"[0-9]{6}", body["instrument_bin"])
        assert 0 < len(body["cart_id"]) <= 64
        assert len(body["sku"]) <= 128
        assert len(body["category"]) <= 64


# ── reproducibility ─────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("cls", [Compromised, Sleeper])
def test_same_seed_reproduces_the_same_behaviour(cls, catalogue):
    """Two runs at one seed issue the same amounts, categories, SKUs, carts and gaps.

    The idempotency key is excluded because the base class draws it from `uuid4` — that is
    the base's decision and it is the right one, since a repeated key would be a replay.
    """
    fields = ("amount_paise", "category", "sku", "cart_id", "instrument_bin", "_gap")

    def signature(seed):
        return [
            tuple(body[f] for f in fields)
            for body in drain(build(cls, catalogue, seed=seed))
        ]

    assert signature(11) == signature(11)
    assert signature(11) != signature(12)


@pytest.mark.parametrize("cls", [Compromised, Sleeper])
def test_incidental_shapes_differ_between_agents_of_one_archetype(cls, catalogue):
    """Rule 5: an incidental constant is indistinguishable from a label.

    Cart-identifier shape, free-text keys and card choice carry no behavioural meaning, so
    two agents of the same archetype must not share them. If they did, the archetype would
    be recognisable by a coding convention rather than by what it does.
    """

    def shapes(seed):
        bodies = drain(build(cls, catalogue, seed=seed))
        prefix = re.match(r"^[^0-9a-f]*", bodies[0]["cart_id"]).group(0)
        bins = frozenset(b["instrument_bin"] for b in bodies)
        widths = frozenset(len(b["cart_id"]) for b in bodies)
        return prefix, bins, widths

    variants = {shapes(seed) for seed in (1, 2, 3, 4, 5, 6, 7, 8)}
    assert len(variants) > 1


# ── compromised: a change of purpose ────────────────────────────────────────────────


def _resale_share(bodies) -> float:
    resale = {"electronics", "apparel", "personal_care"}
    return sum(b["category"] in resale for b in bodies) / len(bodies)


@pytest.mark.parametrize("seed", SEEDS)
def test_compromised_category_mix_shifts_toward_resale(seed, catalogue):
    bodies = drain(build(Compromised, catalogue, seed=seed))
    ordinary = [b for b in bodies if b["_phase"] == "ordinary"]
    extraction = [b for b in bodies if b["_phase"] == "extraction"]

    assert ordinary and extraction
    assert _resale_share(extraction) > _resale_share(ordinary) + 0.4


@pytest.mark.parametrize("seed", SEEDS)
def test_compromised_ticket_sizes_move_upward(seed, catalogue):
    """Upward within what the mandate still permits — never through it."""
    bodies = drain(build(Compromised, catalogue, seed=seed))
    ordinary = [b["amount_paise"] for b in bodies if b["_phase"] == "ordinary"]
    extraction = [b["amount_paise"] for b in bodies if b["_phase"] == "extraction"]

    assert median(extraction) > median(ordinary) * 8


@pytest.mark.parametrize("seed", SEEDS)
def test_compromised_tests_the_water_before_it_commits(seed, catalogue):
    """The takeover is not instantaneous: probing sits between the two, on every measure.

    Someone who has taken over an agent spends a little before spending a lot. An
    archetype that flipped in a single request would be posing an easier question than
    the one this evaluation is asking.
    """
    bodies = drain(build(Compromised, catalogue, seed=seed))
    by_phase = {
        phase: [b for b in bodies if b["_phase"] == phase]
        for phase in ("ordinary", "probing", "extraction")
    }
    assert all(by_phase.values())

    shares = {p: _resale_share(b) for p, b in by_phase.items()}
    assert shares["ordinary"] < shares["probing"] < shares["extraction"]

    peaks = {p: max(x["amount_paise"] for x in b) for p, b in by_phase.items()}
    assert peaks["ordinary"] <= peaks["probing"] <= peaks["extraction"]

    middles = {p: median([x["amount_paise"] for x in b]) for p, b in by_phase.items()}
    assert middles["ordinary"] < middles["probing"] < middles["extraction"]


def test_compromised_opening_period_is_a_real_history(catalogue):
    """Not a token warm-up. The majority of its life is ordinary."""
    bodies = drain(build(Compromised, catalogue))
    ordinary = [b for b in bodies if b["_phase"] == "ordinary"]
    assert len(ordinary) / len(bodies) > 0.5


@pytest.mark.parametrize("seed", SEEDS)
def test_compromised_does_not_change_speed(seed, catalogue):
    """The archetype is a change of purpose, not a burst.

    Asserted rather than assumed, because a cadence shift would quietly turn this agent
    into a different archetype wearing its name.
    """
    bodies = drain(build(Compromised, catalogue, seed=seed))
    ordinary = [b["_gap"] for b in bodies if b["_phase"] == "ordinary"]
    extraction = [b["_gap"] for b in bodies if b["_phase"] == "extraction"]

    assert 0.7 < median(extraction) / median(ordinary) < 1.4


def test_compromised_does_not_change_instruments(catalogue):
    """The takeover steals an agent, not a wallet: no new cards appear at the change."""
    bodies = drain(build(Compromised, catalogue))
    ordinary = {b["instrument_bin"] for b in bodies if b["_phase"] == "ordinary"}
    extraction = {b["instrument_bin"] for b in bodies if b["_phase"] == "extraction"}

    assert extraction <= ordinary
    assert len(ordinary) <= 2


# ── sleeper: a change-point in its own history ──────────────────────────────────────


@pytest.mark.parametrize("seed", SEEDS)
def test_sleeper_is_established_before_it_defects(seed, catalogue):
    """Its history is not merely normal but long."""
    bodies = drain(build(Sleeper, catalogue, seed=seed))
    clean = [b for b in bodies if b["_phase"] == "clean"]

    assert len(clean) / len(bodies) >= 0.75
    assert len(clean) > 100


@pytest.mark.parametrize("seed", SEEDS)
def test_sleeper_baseline_is_narrow(seed, catalogue):
    """A change-point needs a baseline tight enough for a change in it to mean something."""
    bodies = [
        b for b in drain(build(Sleeper, catalogue, seed=seed)) if b["_phase"] == "clean"
    ]

    assert len({b["category"] for b in bodies}) <= 4
    assert max(b["amount_paise"] for b in bodies) <= 120_000


@pytest.mark.parametrize("seed", SEEDS)
def test_sleeper_defection_is_a_step_not_a_ramp(seed, catalogue):
    """Patience buys the right to skip the ramp.

    The very first defecting request is already at full size — that is the difference
    between an agent with an established history and one without.
    """
    bodies = drain(build(Sleeper, catalogue, seed=seed))
    clean = [b["amount_paise"] for b in bodies if b["_phase"] == "clean"]
    defecting = [b["amount_paise"] for b in bodies if b["_phase"] == "defecting"]

    assert defecting
    assert defecting[0] > max(clean) * 5
    assert min(defecting) > max(clean)


@pytest.mark.parametrize("seed", SEEDS)
def test_sleeper_defection_is_unusual_for_itself_not_for_an_agent(seed, catalogue):
    """Large against its own history; ordinary against the catalogue.

    Every defecting amount stays at or below what a single catalogue item costs times a
    small quantity — these are purchases other agents make routinely. The anomaly is the
    sequence, not the number.
    """
    bodies = drain(build(Sleeper, catalogue, seed=seed))
    clean = [b["amount_paise"] for b in bodies if b["_phase"] == "clean"]
    defecting = [b["amount_paise"] for b in bodies if b["_phase"] == "defecting"]

    assert median(defecting) > median(clean) * 10
    assert max(defecting) < MAX_PER_TXN_PAISE


@pytest.mark.parametrize("seed", SEEDS)
def test_sleeper_enters_categories_it_never_touched(seed, catalogue):
    bodies = drain(build(Sleeper, catalogue, seed=seed))
    clean = {b["category"] for b in bodies if b["_phase"] == "clean"}
    defecting = {b["category"] for b in bodies if b["_phase"] == "defecting"}

    assert not clean & defecting


@pytest.mark.parametrize("seed", SEEDS)
def test_sleeper_cadence_tightens_at_the_change_point(seed, catalogue):
    """Once an established mandate is being spent, the window is closing."""
    bodies = drain(build(Sleeper, catalogue, seed=seed))
    clean = [b["_gap"] for b in bodies if b["_phase"] == "clean"]
    defecting = [b["_gap"] for b in bodies if b["_phase"] == "defecting"]

    assert median(defecting) < median(clean) * 0.6


@pytest.mark.parametrize("seed", SEEDS)
def test_sleeper_does_not_change_instruments(seed, catalogue):
    """One corporate card, for life."""
    bodies = drain(build(Sleeper, catalogue, seed=seed))
    assert len({b["instrument_bin"] for b in bodies}) == 1
