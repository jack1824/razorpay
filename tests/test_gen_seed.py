"""`tools/gen_seed.py`: determinism, the ADR corrections, and key hygiene.

The determinism claim is the one that matters. Everything downstream — the eval harness,
the demo timeline, the reproducibility of any number we say out loud — rests on "same seed,
same bytes". The strategy package's generator *claimed* this while writing
``datetime.now()`` into `SEED.txt`, so the file asserting determinism was the only one
breaking it. That is why this test compares bytes rather than trusting the claim.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from dwaar.crypto import mandate as mandatemod
from tools.gen_seed import DEFAULT_SEED, build, write

REPO_ROOT = Path(__file__).resolve().parents[1]
SEED_DIR = REPO_ROOT / "data" / "seed"


@pytest.fixture(scope="module")
def generated():
    return build(DEFAULT_SEED, keys_dir=None)


# ── determinism ─────────────────────────────────────────────────────────────────────

def test_same_seed_produces_byte_identical_output(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    write(build(DEFAULT_SEED, None), a, DEFAULT_SEED)
    write(build(DEFAULT_SEED, None), b, DEFAULT_SEED)

    names = sorted(p.name for p in a.iterdir())
    assert names == sorted(p.name for p in b.iterdir())
    for name in names:
        assert (a / name).read_bytes() == (b / name).read_bytes(), f"{name} is not deterministic"


def test_seed_file_contains_no_timestamp(tmp_path):
    """The defect in the original: a wall-clock read inside the determinism artifact."""
    write(build(DEFAULT_SEED, None), tmp_path, DEFAULT_SEED)
    content = (tmp_path / "SEED.txt").read_text()
    assert content == f"seed={DEFAULT_SEED}\n"
    assert "generated" not in content


def test_a_different_seed_produces_different_output(tmp_path):
    """Guard against a generator that ignores its seed and is 'deterministic' trivially."""
    a, b = tmp_path / "a", tmp_path / "b"
    write(build(DEFAULT_SEED, None), a, DEFAULT_SEED)
    write(build(DEFAULT_SEED + 1, None), b, DEFAULT_SEED + 1)
    assert (a / "agents.json").read_bytes() != (b / "agents.json").read_bytes()


def test_committed_seed_data_matches_the_generator(tmp_path):
    """`data/seed/` must be regenerable, never hand-edited.

    If this fails, someone edited a fixture instead of the generator — which is the same
    failure as editing an expected metric to match a wrong output.
    """
    write(build(DEFAULT_SEED, None), tmp_path, DEFAULT_SEED)
    for path in sorted(tmp_path.iterdir()):
        committed = SEED_DIR / path.name
        assert committed.is_file(), f"data/seed/{path.name} is missing; run `make seed`"
        assert committed.read_bytes() == path.read_bytes(), (
            f"data/seed/{path.name} differs from generator output — regenerate, do not edit"
        )


# ── keys (F-004, ADR item 14) ───────────────────────────────────────────────────────

def test_public_keys_are_real_ed25519_not_placeholders(generated):
    for agent in generated["agents"]:
        assert "public_key_placeholder" not in agent
        assert len(bytes.fromhex(agent["public_key"])) == 32
    for principal in generated["principals"]:
        assert len(bytes.fromhex(principal["public_key"])) == 32


def test_key_derivation_is_deterministic():
    assert build(DEFAULT_SEED, None)["agents"] == build(DEFAULT_SEED, None)["agents"]


def test_private_keys_are_written_only_to_the_keys_dir(tmp_path):
    keys = tmp_path / ".keys"
    build(DEFAULT_SEED, keys)
    written = list(keys.rglob("*.key"))
    assert len(written) == 12, "6 agents + 6 principals"
    assert all(len(p.read_bytes()) == 32 for p in written)
    assert all(p.stat().st_mode & 0o077 == 0 for p in written), "private keys must be 0600"


def test_no_private_key_material_in_the_json(generated):
    """The failure this whole scheme exists to prevent."""
    blob = json.dumps(generated)
    assert "private" not in blob.lower()
    assert "_key" not in blob.replace("public_key", "")


def test_keys_dir_is_gitignored():
    """Asserted, because F-004 is only closed if this stays true."""
    ignore = (REPO_ROOT / ".gitignore").read_text()
    assert ".keys/" in ignore


# ── mandates are loadable and genuinely signed ──────────────────────────────────────

def test_every_mandate_signature_verifies(generated):
    principals = {p["principal_id"]: p for p in generated["principals"]}
    for mandate in generated["mandates"]:
        pub = Ed25519PublicKey.from_public_bytes(
            bytes.fromhex(principals[mandate["principal_id"]]["public_key"])
        )
        # Raises InvalidSignature on failure.
        pub.verify(
            bytes.fromhex(mandate["signature"]),
            mandate["canonical_json"].encode("utf-8"),
        )


def test_mandates_carry_every_not_null_column(generated):
    """F-004: the original fixtures could not be inserted at all."""
    for mandate in generated["mandates"]:
        for column in ("canonical_json", "signature", "mandate_hash"):
            assert mandate.get(column), f"mandate missing {column}, which is NOT NULL"


def test_mandate_hash_matches_its_canonical_json(generated):
    import hashlib

    for mandate in generated["mandates"]:
        expected = hashlib.sha256(mandate["canonical_json"].encode()).hexdigest()
        assert mandate["mandate_hash"] == expected


def test_canonical_json_contains_all_ten_signed_fields(generated):
    for mandate in generated["mandates"]:
        payload = json.loads(mandate["canonical_json"])
        assert set(payload) == set(mandatemod.SIGNED_FIELDS)


def test_mandate_satisfies_schema_checks(generated):
    for mandate in generated["mandates"]:
        assert mandate["max_total_paise"] > 0
        assert mandate["max_per_txn_paise"] > 0
        assert mandate["max_per_txn_paise"] <= mandate["max_total_paise"]
        assert mandate["substitution_tolerance"] in {"none", "same_price", "similar"}


def test_mandate_nonces_are_unique(generated):
    nonces = [m["nonce"] for m in generated["mandates"]]
    assert len(nonces) == len(set(nonces))


# ── money discipline ────────────────────────────────────────────────────────────────

def test_no_float_appears_in_any_money_field(generated):
    """Money is integer paise everywhere, including fixtures."""
    def walk(node):
        if isinstance(node, dict):
            for key, value in node.items():
                if "paise" in key:
                    assert isinstance(value, int) and not isinstance(value, bool), (
                        f"{key} must be int paise, got {type(value).__name__}: {value!r}"
                    )
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(generated)


# ── the ADR corrections (F-001, F-002) ──────────────────────────────────────────────

def _beats(timeline, beat):
    return [event for event in timeline if event.get("beat") == beat]


def test_beat_1_note_uses_the_total_not_the_per_txn_cap(generated):
    """F-002. The console's budget bar is driven by the ledger, not by this note."""
    beat = _beats(generated["timeline"], 1)[0]
    assert "₹50,000" in beat["note"] and "₹48,760" in beat["note"]
    assert "5000 -> 3760" not in beat["note"]

    mandate = next(
        m for m in generated["mandates"] if m["mandate_id"] == beat["mandate"]
    )
    assert mandate["max_total_paise"] - beat["amount_paise"] == 4_876_000


def test_beat_3_is_in_an_allowed_category(generated):
    """F-001, the correction that matters most.

    In `gift_cards` this request died on deterministic set membership and never reached the
    risk model — while asserting `behavioural_drift`. The one beat that shows the model
    earning its place demonstrated the opposite.
    """
    events = [e for e in generated["timeline"] if str(e.get("beat", "")).startswith("3")]
    assert len(events) == 2, "beat 3 is a warm-up plus a drift event"

    for event in events:
        mandate = next(
            m for m in generated["mandates"] if m["mandate_id"] == event["mandate"]
        )
        assert event["category"] in mandate["allow_categories"], (
            f"beat 3 category {event['category']!r} must be ALLOWED, or the request dies "
            "on set membership before the model is ever consulted"
        )
        assert event["category"] not in mandate["deny_categories"]


def test_beat_3_drift_event_is_under_the_per_txn_cap(generated):
    """If it breached the cap, arithmetic would deny it and behaviour would be irrelevant."""
    drift = _beats(generated["timeline"], 3.1)[0]
    mandate = next(m for m in generated["mandates"] if m["mandate_id"] == drift["mandate"])
    assert drift["amount_paise"] < mandate["max_per_txn_paise"], (
        "the drift event must be WITHIN the mandate, so only behaviour can catch it"
    )


def test_beat_3_asserts_a_non_null_risk_score(generated):
    """The exact mirror of beat 2. Together they are the demo's clearest thirty seconds."""
    warm_up, drift = _beats(generated["timeline"], 3.0)[0], _beats(generated["timeline"], 3.1)[0]
    assert warm_up["expect"] == "allow"
    assert drift["expect"] == "deny"
    assert drift["expect_rule"] == "behavioural_drift"
    assert drift["expect_risk_score_non_null"] is True

    breach = _beats(generated["timeline"], 2)[0]
    assert breach["expect_risk_score"] is None
    assert breach["expect_rule"] == "mandate.max_per_txn"


def test_beat_3_events_share_an_agent_and_sku(generated):
    """A drift signal needs a baseline to drift from, and repetition is the pattern."""
    warm_up, drift = _beats(generated["timeline"], 3.0)[0], _beats(generated["timeline"], 3.1)[0]
    assert warm_up["agent"] == drift["agent"]
    assert warm_up["sku"] == drift["sku"]
    assert drift["amount_paise"] > warm_up["amount_paise"] * 5
    assert drift["t"] - warm_up["t"] <= 5, "the burst must be tight enough to read as velocity"


def test_beat_2_breaches_the_per_txn_cap(generated):
    breach = _beats(generated["timeline"], 2)[0]
    mandate = next(m for m in generated["mandates"] if m["mandate_id"] == breach["mandate"])
    assert breach["amount_paise"] > mandate["max_per_txn_paise"]


def test_referenced_skus_exist_in_the_catalogue(generated):
    """A timeline pointing at a SKU that does not exist fails live, on stage."""
    skus = {item["sku"] for item in generated["catalogue"]}
    for event in generated["timeline"]:
        if "sku" in event:
            assert event["sku"] in skus, f"timeline references unknown SKU {event['sku']}"


def test_every_timeline_actor_has_a_matching_mandate(generated):
    """The other way this breaks live: an agent/mandate pair that does not bind."""
    pairs = {(m["agent_id"], m["mandate_id"]) for m in generated["mandates"]}
    for event in generated["timeline"]:
        if "agent" in event:
            assert (event["agent"], event["mandate"]) in pairs


def test_kill_target_matches_a_real_compose_container(generated):
    """`dwaar-ledger` was not a container. The ledger is Postgres."""
    compose = (REPO_ROOT / "docker-compose.yml").read_text()
    for event in generated["timeline"]:
        if event.get("control") == "kill_container":
            target = event["target"]
            if target == "dwaar-llm-explainer":
                continue  # lands day 10
            assert f"container_name: {target}" in compose, (
                f"timeline kills {target!r}, which is not a container in docker-compose.yml"
            )


# ── ground truth stays out of reach ─────────────────────────────────────────────────

def test_no_archetype_label_leaks_into_gateway_visible_data(generated):
    """The gateway sees agents, mandates, catalogue and timeline. None may carry a label."""
    visible = json.dumps({
        k: v for k, v in generated.items() if k != "ground_truth"
    })
    for archetype in ("legit_shopper", "card_tester", "budget_breacher",
                      "injector", "compromised", "sleeper"):
        assert archetype not in visible, (
            f"archetype {archetype!r} leaked into data the gateway can read — the "
            "evaluation would be measuring our ability to read a label"
        )
    assert "archetype" not in visible
    assert "held_out" not in visible


def test_ground_truth_has_exactly_two_held_out(generated):
    held_out = [t for t in generated["ground_truth"] if t["held_out"]]
    assert {t["archetype"] for t in held_out} == {"compromised", "sleeper"}
