"""The traffic generator: reproducible, loopback-only, and honest about its overlap.

Three properties, and the third is the one most likely to be quietly lost:

    loopback     an agent refuses any non-local target, in the base class
    reproducible same seed, same requests, in the same order
    overlapping  ~3% of legitimate agents behave like something worth stopping, and those
                 MUST produce false positives

A generator whose classes never overlap gives the model near-perfect scores and makes the
false-positive cost in rupees — the one number this project has committed to reporting
honestly — pure fiction.
"""

from __future__ import annotations

import pytest

from zoo import catalogue as cataloguemod
from zoo import run as runmod
from zoo.agents import ARCHETYPES, LEGITIMATE
from zoo.base import AgentIdentity, NonLoopbackTarget, assert_loopback

IDENTITY = AgentIdentity(
    agent_id="agt_000000000001",
    principal_id="prn_000000000001",
    mandate_id="mnd_000000000001",
    seed=20260827,
)


def build(archetype: str, seed: int = 7, requests: int = 30, **kwargs):
    cls = ARCHETYPES[archetype]
    if archetype == "budget_breacher":
        kwargs.setdefault("max_per_txn_paise", 2_000_000)
    return cls(
        IDENTITY,
        base_url="http://127.0.0.1:8080",
        seed=seed,
        catalogue=cataloguemod.load(),
        requests=requests,
        **kwargs,
    )


# ── loopback ────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "url",
    [
        "https://api.razorpay.com",
        "http://192.168.1.10:8080",
        "http://example.com",
        "http://127.0.0.1.evil.com",
    ],
)
def test_agents_refuse_a_non_loopback_target(url):
    """This package generates deliberately abusive traffic. The only thing separating an
    evaluation harness from an attack tool is where it points, so the check is in the base
    class rather than in a README."""
    with pytest.raises(NonLoopbackTarget):
        assert_loopback(url)


@pytest.mark.parametrize("url", ["http://127.0.0.1:8080", "http://localhost:8080"])
def test_loopback_targets_are_accepted(url):
    assert_loopback(url)  # raises on refusal; returning None is the accepted path


def test_construction_against_a_remote_host_raises():
    """Enforced at CONSTRUCTION, not at send time. A half-built run pointed at the wrong
    host has already decided what it intends to do."""
    for archetype, cls in ARCHETYPES.items():
        kwargs = {"max_per_txn_paise": 1} if archetype == "budget_breacher" else {}
        with pytest.raises(NonLoopbackTarget):
            cls(
                IDENTITY,
                base_url="http://198.51.100.4:8080",
                seed=1,
                catalogue=cataloguemod.load(),
                requests=1,
                **kwargs,
            )


# ── reproducibility ─────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("archetype", sorted(ARCHETYPES))
def test_the_same_seed_produces_the_same_requests(archetype):
    """Without this, no run is comparable to any other and no result is reproducible."""
    left = [build(archetype, seed=42).next_request() for _ in range(1)]
    a, b = build(archetype, seed=42), build(archetype, seed=42)
    assert [a.next_request() for _ in range(20)] == [b.next_request() for _ in range(20)]
    assert left


@pytest.mark.parametrize("archetype", sorted(ARCHETYPES))
def test_different_seeds_produce_different_requests(archetype):
    """Two agents of one archetype must not issue identical streams, or every feature
    computed over them is measured on one agent repeated N times."""
    a = [build(archetype, seed=1).next_request() for _ in range(1)]
    left = build(archetype, seed=1)
    right = build(archetype, seed=2)
    assert [left.next_request() for _ in range(20)] != [
        right.next_request() for _ in range(20)
    ]
    assert a


# ── archetype behaviour ─────────────────────────────────────────────────────────────


def test_card_tester_arrives_roughly_twenty_times_faster_than_a_shopper():
    """From the simulation spec. It is also the thing that makes the cadence features
    meaningful: if every archetype arrived at the same rate, `burst_index` and
    `cadence_entropy` would be measuring noise."""
    shopper = build("legit_shopper", seed=3)
    tester = build("card_tester", seed=3)
    shopper_gaps = [shopper.next_gap() for _ in range(400)]
    tester_gaps = [tester.next_gap() for _ in range(400)]
    ratio = (sum(shopper_gaps) / len(shopper_gaps)) / (sum(tester_gaps) / len(tester_gaps))
    assert 5 < ratio < 60, f"arrival-rate ratio is {ratio:.1f}, expected roughly 20x"


def test_card_tester_has_far_higher_bin_diversity():
    tester = build("card_tester", seed=5)
    shopper = build("legit_shopper", seed=5)
    tester_bins = {tester.next_request()["instrument_bin"] for _ in range(40)}
    shopper_bins = {shopper.next_request()["instrument_bin"] for _ in range(40)}
    assert len(tester_bins) > len(shopper_bins) * 3


def test_card_tester_declines_far_more_often_than_a_shopper():
    """Beta(14,6) against Beta(2,18). The decline ratio is a PSP outcome, never one of our
    own denials — a ratio over authorization denials would be a readout of the arithmetic
    gate."""
    tester = build("card_tester", seed=11)
    shopper = build("legit_shopper", seed=11)
    tester_rate = sum(not tester.payment_would_succeed() for _ in range(500)) / 500
    shopper_rate = sum(not shopper.payment_would_succeed() for _ in range(500)) / 500
    assert tester_rate > 0.4
    assert shopper_rate < 0.35
    assert tester_rate > shopper_rate * 2


def test_budget_breacher_asks_for_more_than_it_may():
    breacher = build("budget_breacher", seed=9)
    amounts = [breacher.next_request()["amount_paise"] for _ in range(60)]
    over = [a for a in amounts if a > 2_000_000]
    assert over, "a breacher that never breaches is a breacher in name only"
    assert len(over) < len(amounts), (
        "it must also make requests UNDER the cap, or nothing about it ever reaches the "
        "model and the archetype demonstrates only the arithmetic gate"
    )


def test_budget_breacher_probes_one_sku_at_many_prices():
    breacher = build("budget_breacher", seed=9)
    requests = [breacher.next_request() for _ in range(60)]
    by_sku: dict[str, set[int]] = {}
    for entry in requests:
        by_sku.setdefault(entry["sku"], set()).add(entry["amount_paise"])
    assert max(len(amounts) for amounts in by_sku.values()) > 3


def test_injector_sends_instruction_shaped_text_and_benign_lookalikes():
    """The lookalikes are the point. "Ignore" is a real cosmetics brand, and a detector that
    fires on `Ignore lip balm` blocks a customer trying to buy lip balm."""
    from zoo.agents.injector import BENIGN_LOOKALIKES, INJECTION_PAYLOADS

    injector = build("injector", seed=13)
    texts = [injector.next_request()["free_text"]["search_term"] for _ in range(40)]
    assert any(text in INJECTION_PAYLOADS for text in texts)
    assert any(text in BENIGN_LOOKALIKES for text in texts), (
        "no benign lookalikes generated; the detector would be measured only against the "
        "strings that look alarming"
    )


def test_no_archetype_sends_free_text_except_the_injector():
    """Otherwise `free_text` presence alone would identify the archetype."""
    for archetype in ARCHETYPES:
        if archetype == "injector":
            continue
        agent = build(archetype, seed=17)
        assert all("free_text" not in agent.next_request() for _ in range(20))


# ── the 3% overlap ──────────────────────────────────────────────────────────────────


def test_some_legitimate_agents_are_marked_bursty():
    """Without this the false-positive rate is measured against traffic that never looks
    suspicious, and the rupee figure is fiction."""
    plan = runmod.build_plan(
        {"legit_shopper": 30, "card_tester": 4, "budget_breacher": 4, "injector": 4},
        seed=20260827,
    )
    legit = [entry for entry in plan if entry[0] in LEGITIMATE]
    bursty = [entry for entry in legit if entry[2]]
    assert bursty, "no legitimate agent was marked bursty; there is no class overlap"
    assert len(bursty) / len(legit) <= 0.15, (
        "too many legitimate agents are bursty; the overlap is meant to be a tail, not a "
        "second archetype"
    )


def test_a_small_run_still_contains_the_overlap():
    """`max(1, ...)` rather than a plain fraction: rounding the overlap away in a small run
    would silently produce a generator with no class overlap at all."""
    plan = runmod.build_plan({"legit_shopper": 4}, seed=1)
    assert any(entry[2] for entry in plan)


def test_only_legitimate_agents_can_be_bursty():
    plan = runmod.build_plan(
        {"legit_shopper": 20, "card_tester": 5, "injector": 5}, seed=99
    )
    for archetype, _suffix, bursty in plan:
        if bursty:
            assert archetype in LEGITIMATE


def test_a_bursty_shopper_lands_in_card_tester_feature_space():
    """The flag has to change behaviour, and change it ENOUGH.

    The first version of the burst ran at ten times a shopper's normal rate and produced
    zero model flags — correctly, because fifteen requests a minute looks nothing like two
    hundred and forty. An overlap no model would ever flag is an overlap that exists only in
    a README.

    So this asserts the four signals that actually define card testing, rather than
    asserting that something changed:

        a RUN of requests at card-tester cadence   -> velocity, cadence entropy
        several cards inside that run              -> bin diversity
        one item at one price                      -> amount entropy collapses
        a high decline rate during it              -> failure ratio
    """
    from zoo.agents.card_tester import MEAN_GAP_SECONDS as TESTER_GAP

    calm = build("legit_shopper", seed=21, bursty=False, requests=60)
    wild = build("legit_shopper", seed=21, bursty=True, requests=60)

    def trace(agent):
        gaps, cards, amounts, declines = [], [], [], 0
        for _ in range(60):
            request = agent.next_request()
            gaps.append(agent.next_gap())
            cards.append(request["instrument_bin"])
            amounts.append(request["amount_paise"])
            declines += not agent.payment_would_succeed()
        return gaps, cards, amounts, declines

    calm_gaps, calm_cards, _, calm_declines = trace(calm)
    wild_gaps, wild_cards, wild_amounts, wild_declines = trace(wild)

    fast = [gap for gap in wild_gaps if gap <= TESTER_GAP * 3]
    calm_fast = [gap for gap in calm_gaps if gap <= TESTER_GAP * 3]

    assert len(fast) >= 15, (
        f"only {len(fast)} requests at card-tester cadence; a burst this short does not "
        "lift a one-minute velocity into the region the model reacts to"
    )
    assert len(fast) > len(calm_fast) * 3

    assert len(set(wild_cards)) > len(set(calm_cards)), (
        "the retry storm must reach for another card, or bin_diversity does not move"
    )
    assert wild_declines > calm_declines * 2, (
        "the burst exists BECAUSE the card is failing; without the declines the one feature "
        "that most directly describes card testing stays flat through it"
    )

    # The burst is ONE purchase retried, so its amounts cluster tightly — which is what
    # collapses `amount_entropy` into the region a card tester occupies. Compared against
    # the same agent's non-burst amounts rather than against an absolute number.
    burst = [a for a, g in zip(wild_amounts, wild_gaps, strict=True) if g <= TESTER_GAP * 3]
    other = [a for a, g in zip(wild_amounts, wild_gaps, strict=True) if g > TESTER_GAP * 3]

    def spread(values):
        mean = sum(values) / len(values)
        return (sum((v - mean) ** 2 for v in values) / len(values)) ** 0.5 / mean

    assert spread(burst) < spread(other) / 5, (
        f"burst amounts spread {spread(burst):.3f} against {spread(other):.3f} outside it; "
        "a retry storm re-presents one price, and without that amount_entropy does not move"
    )


def test_a_bursty_agent_always_bursts_within_a_short_run():
    """Seeded index, not a per-request coin flip. "The overlap did not happen this time" is
    indistinguishable from "there is no overlap"."""
    from zoo.agents.card_tester import MEAN_GAP_SECONDS as TESTER_GAP

    for seed in range(1, 12):
        agent = build("legit_shopper", seed=seed, bursty=True, requests=40)
        gaps = []
        for _ in range(40):
            agent.next_request()
            gaps.append(agent.next_gap())
        assert sum(1 for gap in gaps if gap <= TESTER_GAP * 3) >= 15, (
            f"seed {seed} produced no burst inside a 40-request run"
        )


# ── the mandates ────────────────────────────────────────────────────────────────────


def test_every_archetype_gets_an_identical_mandate():
    """The single most important line in `zoo/provision.py`.

    If adversarial agents held tighter mandates, the mandate would BE the label: the gateway
    would deny them more often for reasons unrelated to behaviour, the model would learn the
    difference, and the evaluation would measure how the fixtures were written.
    """
    from pathlib import Path

    from tests._support.sourcescan import strip_python
    from zoo import provision

    code = strip_python(Path(provision.__file__).read_text(encoding="utf-8"))
    for archetype in ARCHETYPES:
        assert archetype not in code, (
            f"zoo/provision.py branches on {archetype!r}; mandates must be identical across "
            "archetypes or the mandate becomes the label"
        )


def test_the_display_name_does_not_contain_the_archetype():
    """An agent called `card_tester_01` would put the label in the database, in every log
    line and on the console — the leak complete before a single feature was computed."""
    plan = runmod.build_plan({"legit_shopper": 2, "card_tester": 2}, seed=5)
    for archetype, suffix, _ in plan:
        assert archetype not in f"zoo-agent-{suffix}"
