"""Feature computation: deterministic, integral, and about behaviour.

The three properties that make `decision_records.features` worth writing down:

    deterministic   same window, same request, same clock -> same vector, bit for bit
    integral        no floats, because a signed payload cannot contain one
    behavioural     every value describes what the agent DID, not what it was allowed to do

The third is tested in `test_feature_leakage.py`, which is where the interesting assertions
live. This file covers the first two and the arithmetic of each individual feature.
"""

from __future__ import annotations

import math

import pytest

from dwaar.risk import features as f
from dwaar.risk.observations import Observation, WindowSnapshot

NOW = 1_800_000_000.0


def obs(offset: float, **kwargs) -> Observation:
    """One observation `offset` seconds before NOW."""
    return Observation(
        ts=NOW - offset,
        amount_paise=kwargs.get("amount", 100_000),
        category=kwargs.get("category", "groceries"),
        sku_hash=kwargs.get("sku", "sku0000000a"),
        bin_hash=kwargs.get("bin", "bin0000000a"),
        cart_hash=kwargs.get("cart", "cart000000a"),
    )


def window(*observations, outcomes=()) -> WindowSnapshot:
    return WindowSnapshot(tuple(observations), tuple(outcomes))


# ── the two structural properties ───────────────────────────────────────────────────


def test_every_value_is_an_integer():
    """A float here is a `TypeError` from the canonicaliser at stage 8, three stages later.

    `dwaar/crypto/jcs.py` refuses floats in a signed payload because RFC 8785 float
    serialisation depends on the number-to-string algorithm, so a verifier in another
    language could canonicalise the same record to different bytes. Quantising once here is
    what keeps a stored row exactly replayable.
    """
    vector = f.compute(obs(0), window(obs(10), obs(20)), now=NOW)
    assert set(vector) == set(f.FEATURE_NAMES)
    for name, value in vector.items():
        assert isinstance(value, int) and not isinstance(value, bool), (
            f"{name} is {type(value).__name__}, and a signed payload cannot hold one"
        )


def test_the_signed_payload_accepts_the_vector():
    """The assertion above, made against the real canonicaliser rather than against a
    restatement of its rule."""
    from dwaar.crypto.jcs import canonicalize

    vector = f.compute(obs(0), window(obs(3), obs(9)), now=NOW)
    assert canonicalize(vector)


def test_computation_is_deterministic():
    snapshot = window(obs(5), obs(17), obs(400, category="apparel"))
    first = f.compute(obs(0), snapshot, now=NOW)
    second = f.compute(obs(0), snapshot, now=NOW)
    assert first == second


def test_computation_does_not_read_the_clock():
    """A feature that moves between two calls makes the record an account of something that
    did not happen. `now` is a parameter for exactly this reason."""
    import time

    snapshot = window(obs(5), obs(17))
    first = f.compute(obs(0), snapshot, now=NOW)
    time.sleep(0.01)
    assert f.compute(obs(0), snapshot, now=NOW) == first


def test_round_tripping_through_natural_units_and_back():
    vector = f.compute(obs(0), window(obs(2), obs(30)), now=NOW)
    natural = f.to_natural(vector)
    for name in f.FEATURE_NAMES:
        assert natural[name] == pytest.approx(vector[name] / f.FEATURE_SCALE)


def test_to_vector_fills_every_slot_but_to_natural_does_not():
    """The asymmetry is deliberate.

    The model needs a complete tensor, so a missing feature becomes 0.0. A RULE must see
    `None` for a missing feature, so that `velocity_1m < 10` is FALSE rather than
    accidentally true against a fabricated zero — an absent feature can never *cause* an
    allow.
    """
    partial = {"velocity_1m": 5_000_000}
    assert len(f.to_vector(partial)) == len(f.FEATURE_NAMES)
    assert f.to_natural(partial) == {"velocity_1m": 5.0}


# ── individual features ─────────────────────────────────────────────────────────────


def test_velocity_counts_the_current_request():
    """The features OF this request in its context. Excluding it would score the first
    request of a burst as though the burst had not started."""
    vector = f.to_natural(f.compute(obs(0), window(), now=NOW))
    assert vector["velocity_1m"] == 1.0
    assert vector["velocity_1h"] == 1.0


def test_velocity_windows_are_wall_clock():
    inside = [obs(i * 5) for i in range(1, 6)]     # 5s..25s ago
    outside = [obs(120), obs(3000)]                # beyond a minute
    vector = f.to_natural(f.compute(obs(0), window(*inside, *outside), now=NOW))
    assert vector["velocity_1m"] == 6.0
    assert vector["velocity_1h"] == 8.0


def test_burst_index_is_near_one_for_steady_traffic():
    """A steady agent has a last minute like its average minute.

    Tested at ten requests per minute rather than one, because the feature is biased upward
    at very low rates — an agent making one request per minute counts itself and its
    predecessor inside the window and reads ~2.0 while being perfectly steady. That bias is
    documented at the computation; this asserts it is a low-rate artifact and not the
    feature's general behaviour.
    """
    steady = [obs(i * 6.0) for i in range(1, 400)]
    vector = f.to_natural(f.compute(obs(0), window(*steady), now=NOW))
    assert vector["burst_index"] == pytest.approx(1.0, abs=0.3)


def test_burst_index_rises_on_a_burst():
    burst = [obs(i * 0.5) for i in range(1, 40)]
    quiet = [obs(600 + i * 60.0) for i in range(1, 20)]
    vector = f.to_natural(f.compute(obs(0), window(*burst, *quiet), now=NOW))
    assert vector["burst_index"] > 10.0


def test_regular_cadence_has_lower_entropy_than_ragged_cadence():
    """Machine regularity IS the signal. A card tester firing every 400ms is more
    predictable than a shopper, and predictability is what this measures."""
    regular = [obs(i * 0.4) for i in range(1, 40)]
    ragged = [obs(sum(0.1 * (j % 97) + 0.4 for j in range(i))) for i in range(1, 40)]

    regular_v = f.to_natural(f.compute(obs(0), window(*regular), now=NOW))
    ragged_v = f.to_natural(f.compute(obs(0), window(*ragged), now=NOW))
    assert regular_v["cadence_entropy"] < ragged_v["cadence_entropy"]
    assert regular_v["inter_arrival_variance"] < ragged_v["inter_arrival_variance"]


def test_amount_entropy_collapses_when_every_amount_is_the_same_size():
    same = [obs(i, amount=4_900) for i in range(1, 30)]
    varied = [obs(i, amount=(10 ** (1 + i % 6))) for i in range(1, 30)]
    assert (
        f.compute(obs(0, amount=4_900), window(*same), now=NOW)["amount_entropy"]
        < f.compute(obs(0, amount=500), window(*varied), now=NOW)["amount_entropy"]
    )


def test_bin_diversity_is_the_share_of_distinct_cards():
    one_card = [obs(i, bin="aaa") for i in range(1, 10)]
    many = [obs(i, bin=f"bin{i:08d}") for i in range(1, 10)]
    assert f.to_natural(f.compute(obs(0, bin="aaa"), window(*one_card), now=NOW))[
        "bin_diversity"
    ] == pytest.approx(0.1)
    assert f.to_natural(f.compute(obs(0, bin="zzz"), window(*many), now=NOW))[
        "bin_diversity"
    ] == pytest.approx(1.0)


def test_failure_ratio_comes_only_from_payment_outcomes():
    """It must never be computable from our own denials.

    A ratio over authorization denials would be a direct readout of the arithmetic gate —
    the one thing no feature may encode — and a budget breacher would score 1.0 for a reason
    the model deserves no credit for. The only input is the PSP's outcome list.
    """
    snapshot = window(obs(5), obs(10), outcomes=[False, False, False, True])
    assert f.to_natural(f.compute(obs(0), snapshot, now=NOW))["failure_ratio"] == 0.75

    no_outcomes = window(obs(5), obs(10))
    assert f.to_natural(f.compute(obs(0), no_outcomes, now=NOW))["failure_ratio"] == 0.0


def test_category_drift_is_zero_without_a_drift():
    steady = [obs(i * 10, category="groceries") for i in range(1, 20)]
    assert f.compute(obs(0, category="groceries"), window(*steady), now=NOW)[
        "category_drift"
    ] == 0


def test_category_drift_rises_when_the_mix_moves():
    """Against the agent's OWN earlier mix, never against the mandate's allow list.

    A category the mandate forbids is denied by set membership and never reaches here, so a
    "drift vs mandate" feature could only fire on requests the gate had already permitted —
    it would be measuring nothing. What matters is an agent that moves from groceries to
    electronics while both remain permitted.
    """
    early = [obs(300 + i * 10, category="groceries") for i in range(1, 15)]
    late = [obs(i * 10, category="electronics") for i in range(1, 8)]
    drifted = f.compute(obs(0, category="electronics"), window(*early, *late), now=NOW)
    assert drifted["category_drift"] > 0


def test_cart_mutation_rate_counts_variants_of_one_cart():
    edits = [obs(i, amount=1000 * i, cart="same") for i in range(1, 6)]
    stable = [obs(i, amount=5000, cart="same") for i in range(1, 6)]
    assert (
        f.compute(obs(0, amount=99_000, cart="same"), window(*edits), now=NOW)[
            "cart_mutation_rate"
        ]
        > f.compute(obs(0, amount=5000, cart="same"), window(*stable), now=NOW)[
            "cart_mutation_rate"
        ]
    )


def test_price_probe_score_fires_on_one_sku_at_many_prices():
    """It counts the agent repricing its OWN request. It does not reference a cap, cannot
    see one, and would fire identically on an agent probing something else."""
    probing = [obs(i, sku="target", amount=500_000 - 50_000 * i) for i in range(1, 6)]
    shopping = [obs(i, sku=f"sku{i}", amount=100_000) for i in range(1, 6)]
    assert f.to_natural(f.compute(obs(0, sku="target", amount=100_000),
                                  window(*probing), now=NOW))["price_probe_score"] > 0.5
    assert f.compute(obs(0, sku="other", amount=100_000),
                     window(*shopping), now=NOW)["price_probe_score"] == 0


def test_session_duration_resets_after_a_long_gap():
    recent = [obs(30), obs(60), obs(90)]
    old = [obs(30), obs(60), obs(90), obs(10_000), obs(10_060)]
    short = f.to_natural(f.compute(obs(0), window(*recent), now=NOW))
    long = f.to_natural(f.compute(obs(0), window(*old), now=NOW))
    assert short["session_duration_s"] == pytest.approx(long["session_duration_s"])
    assert short["session_duration_s"] == pytest.approx(math.log1p(90.0), abs=0.01)


def test_an_empty_window_produces_a_complete_vector():
    """A first-time agent is a normal thing. Every slot must still be present, or the model
    receives a short tensor and the record is missing keys the verifier expects."""
    vector = f.compute(obs(0), window(), now=NOW)
    assert set(vector) == set(f.FEATURE_NAMES)


def test_empty_is_all_zeros_and_complete():
    assert set(f.empty()) == set(f.FEATURE_NAMES)
    assert set(f.empty().values()) == {0}
