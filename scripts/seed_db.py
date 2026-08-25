"""Load `data/seed/` into the database, then drive a few decisions. `make demo-seed`.

Not the demo runner — that is `make demo`, which drives the timeline on its own schedule.
This puts a believable chain in front of the console so the demo does not open on an empty
table.

── The collaborators are REAL, and that was the bug ────────────────────────────────────

This used to call `pipeline.authorize()` with no scorer, no detector and no observation
store. Every stage still ran, so nothing failed and every row it wrote carried
`features_degraded` and `risk_model_unavailable` with `risk_score` NULL.

The console then showed NULL on every decision including the allows, and a
`mandate.max_total` denial — which per DEFENSE entry 4 is scored, because the cumulative cap
needs the ledger and therefore cannot be checked before the model — showed NULL as well. Both
looked like defects in the gateway. Neither was: the seeder was writing an honest record of a
gateway running without a model, and the gateway it was describing was not the one being
demonstrated.

That is the same shape as F-018 one layer up. A fixture that writes records the system would
never write is a fixture that misrepresents the system, and here it misrepresented it on the
one screen an audience actually looks at.

So this builds the scorer, the detector and a Redis observation store exactly as
`dwaar/api/app.py` does. If the model bundle is missing it says so and stops, rather than
producing another chain of degraded rows that read as a broken gateway.

── It also drives demo beat 7 ───────────────────────────────────────────────────────────

`create_refund` above scope, an unmapped tool, and a permitted collection — so the MCP
enforcement panel has something in it before anyone opens the console. Those go through the
same pipeline as everything else; there is no second authorization path to seed.
"""

from __future__ import annotations

import asyncio
import json
import random
import sys
import uuid
from datetime import datetime
from pathlib import Path

import psycopg

from dwaar import clock
from dwaar.authorize import pipeline
from dwaar.authorize.types import AuthorizeRequest
from dwaar.config import get_settings
from dwaar.crypto import http_sig
from dwaar.crypto import keys as keymod
from dwaar.crypto.signer import derive_signer, ensure_registered
from dwaar.db.repositories import agents, mandates, principals
from dwaar.nonce import InMemoryNonceStore

REPO_ROOT = Path(__file__).resolve().parents[1]
SEED_DIR = REPO_ROOT / "data" / "seed"
SEED = 20260905


def load(name: str):
    return json.loads((SEED_DIR / f"{name}.json").read_text())


async def seed(dsn: str) -> None:
    settings = get_settings()
    signer = derive_signer(settings.signing_seed, keys_dir=settings.keys_dir)

    async with await psycopg.AsyncConnection.connect(dsn) as conn:
        await ensure_registered(conn, signer)

        for agent in load("agents"):
            if await agents.get(conn, agent["agent_id"]) is None:
                await agents.create(
                    conn,
                    agent_id=agent["agent_id"],
                    display_name=agent["display_name"],
                    public_key=agent["public_key"],
                    registered_by=agent["registered_by"],
                    status=agent["status"],
                )

        for principal in load("principals"):
            if await principals.get(conn, principal["principal_id"]) is None:
                await principals.create(
                    conn,
                    principal_id=principal["principal_id"],
                    merchant_id=principal["merchant_id"],
                    public_key=principal["public_key"],
                )

        for mandate in load("mandates"):
            # ── A stored mandate that no longer matches the fixture is REFUSED ─────────
            #
            # Identities in `data/seed/` come from an RNG stream keyed on the seed, not from
            # the mandate's content, so changing a signed term — adding `scopes`, say —
            # produces the same id with different bytes. The insert below is guarded by
            # "does it exist", so the stale row silently wins and the fixture is ignored.
            #
            # That happened: scopes were added to the seed, the database kept mandates
            # without them, and demo beat 7 denied `create_order` — a call the fixture
            # explicitly delegates — with `mcp.scope.collect.create`. The panel looked like
            # a working scope check refusing a permitted tool.
            #
            # The mandate is NOT patched into line. Its terms are inside what the principal
            # signed, and rewriting a column to match a fixture is F-042 exactly — the
            # column would agree and the signature would cover something else. So this stops
            # and names the remedy.
            existing = await mandates.get(conn, mandate["mandate_id"])
            if existing is not None:
                stored = bytes(existing["mandate_hash"]).hex()
                if stored != mandate["mandate_hash"]:
                    raise SystemExit(
                        f"{mandate['mandate_id']} in the database was signed over different "
                        f"terms than data/seed/mandates.json holds\n"
                        f"  stored   {stored}\n"
                        f"  fixture  {mandate['mandate_hash']}\n\n"
                        "The stored mandate is stale. It is not patched into line, because "
                        "its terms are inside what the principal signed and rewriting a "
                        "column to match a fixture is the tamper the integrity check exists "
                        "to catch (FAILURES.md F-042).\n\n"
                        "  make demo-reset && make demo-seed"
                    )
            if existing is None:
                await mandates.create(
                    conn,
                    mandate_id=mandate["mandate_id"],
                    principal_id=mandate["principal_id"],
                    agent_id=mandate["agent_id"],
                    max_total_paise=mandate["max_total_paise"],
                    max_per_txn_paise=mandate["max_per_txn_paise"],
                    expires_at=datetime.fromisoformat(mandate["expires_at"]),
                    nonce=mandate["nonce"],
                    canonical_json=mandate["canonical_json"],
                    signature=mandate["signature"],
                    mandate_hash=mandate["mandate_hash"],
                    allow_categories=mandate["allow_categories"],
                    deny_categories=mandate["deny_categories"],
                    substitution_tolerance=mandate["substitution_tolerance"],
                    # Signed by the principal like every other term. A column that disagreed
                    # with the bytes it was signed over is exactly the tamper the integrity
                    # check exists to find — F-042, which reached the database once.
                    scopes=mandate.get("scopes"),
                )
        await conn.commit()
    print("seeded agents, principals and mandates")


async def _risk_of(conn, record_id: str | None) -> str:
    """Read the score back OFF THE RECORD rather than reporting what we think we did.

    The seeder's whole failure was writing rows that did not say what anyone assumed. Printing
    the stored value closes that: what appears on this console line is what the console will
    show.
    """
    if record_id is None:
        return "?"
    row = await conn.execute(
        "SELECT risk_score FROM decision_records WHERE record_id = %s", (record_id,)
    )
    found = await row.fetchone()
    if found is None or found[0] is None:
        return "NULL"
    return f"{float(found[0]):.4f}"


async def _collaborators(settings):
    """The scorer, the detector and the observation store — the same three the API builds.

    Returns `(scorer, detector, observation_store, close)`. A missing model bundle is fatal
    here rather than degraded: the whole point of this script is to produce records that look
    like the running system, and a chain of `risk_model_unavailable` rows looks like a broken
    one.
    """
    from redis.asyncio import Redis

    from dwaar.risk import injection as injectionmod
    from dwaar.risk import model as riskmodel
    from dwaar.risk.observations import RedisObservationStore

    scorer = riskmodel.load(settings.model_dir)
    if scorer is None:
        raise SystemExit(
            f"no risk model at {settings.model_dir}. Run `make train` first.\n"
            "Seeding without one writes a chain of degraded, unscored records, and the "
            "console then shows NULL on every decision — which reads as a broken gateway "
            "rather than as a missing bundle."
        )
    detector = injectionmod.load(settings.injection_dir)
    redis = Redis.from_url(settings.redis_url)
    try:
        await redis.ping()
    except Exception as exc:  # noqa: BLE001
        raise SystemExit(
            f"redis unreachable at {settings.redis_url} ({type(exc).__name__}). The rolling "
            "behavioural window lives there; without it every record carries "
            "`features_degraded`."
        ) from exc
    return scorer, detector, RedisObservationStore(redis), redis.aclose


async def drive(dsn: str, rounds: int = 1) -> None:
    """Run the timeline's purchase beats through the real pipeline, with real collaborators."""
    settings = get_settings()
    signer = derive_signer(settings.signing_seed, keys_dir=settings.keys_dir)
    store = InMemoryNonceStore()
    scorer, detector, observations, close = await _collaborators(settings)
    timeline = [beat for beat in load("timeline") if beat.get("action") == "purchase"]

    async with await psycopg.AsyncConnection.connect(dsn) as conn:
        for round_index in range(rounds):
            for beat in timeline:
                request = AuthorizeRequest(
                    agent_id=beat["agent"],
                    mandate_id=beat["mandate"],
                    action="purchase",
                    amount_paise=beat["amount_paise"],
                    idempotency_key=f"seed-{round_index}-{uuid.uuid4().hex[:16]}",
                    category=beat.get("category"),
                    sku=beat.get("sku"),
                    # F-045: a request with no instrument produces `bin_diversity = 0`, a
                    # value no training request ever had, and the anomaly model reads it as
                    # extreme. The timeline carries a card; the seeder used to drop it.
                    instrument_bin=beat.get("instrument_bin"),
                    cart_id=beat.get("cart_id"),
                )
                body = json.dumps({"beat": beat.get("beat")}, separators=(",", ":")).encode()
                private = keymod.derive_private_key(SEED, "agent", request.agent_id)
                headers = http_sig.sign_request(
                    private, method="POST", path="/v1/authorize", body=body,
                    keyid=request.agent_id, created=clock.unix(), nonce=uuid.uuid4().hex,
                )
                try:
                    outcome = await pipeline.authorize(
                        request, conn=conn, signer=signer, settings=settings,
                        headers=headers, body=body, nonce_store=store,
                        scorer=scorer, detector=detector,
                        observation_store=observations,
                    )
                    await conn.commit()
                    print(
                        f"  beat {beat.get('beat'):<4} {outcome.decision.decision:<6} "
                        f"risk={await _risk_of(conn, outcome.record_id):<7} "
                        f"{outcome.decision.rule_fired or outcome.decision.reason_code}"
                        + (f"  DEGRADED {outcome.degraded_mode}" if outcome.degraded_mode else "")
                    )
                except Exception as exc:  # noqa: BLE001
                    await conn.rollback()
                    print(f"  beat {beat.get('beat'):<4} ERROR {type(exc).__name__}: {exc}")
                await asyncio.sleep(0.4)
    await close()


async def drain_one_mandate(dsn: str, max_attempts: int = 24) -> None:
    """Spend one mandate down to its cumulative cap, so the console shows `mandate.max_total`.

    ── Why this beat has to exist ──────────────────────────────────────────────────────

    DEFENSE entry 4 rests on a contrast between two arithmetic denials that behave
    differently, and the console can only show it if both are on screen:

        mandate.max_per_txn   refused at the GATE, before anything is scored.
                              `risk_score` is NULL, and that NULL is the evidence.
        mandate.max_total     the cumulative cap needs the LEDGER, so it cannot be checked
                              until stage 6 — after scoring. The record carries a score.

    Both are arithmetic. Neither is a model decision. They differ only in what they need to
    be computed, and a reader who sees one without the other concludes the wrong thing about
    which denials consult a model.

    Uses the sixth seeded mandate, which the timeline never touches, so draining it cannot
    make `make demo`'s budget preflight refuse to run.

    ── The requests are VARIED, and the first version's were not ───────────────────────

    Twenty-four identical amounts on one SKU at 50ms intervals is the card-tester signature —
    zero amount entropy, zero cadence entropy, one SKU — so the risk model denied them, a
    denial reserves nothing, and the budget never moved. Twenty-four attempts reached 0% of
    the cap.

    That is F-036 for the third time: traffic generated to exercise one path taking a
    different path because of how it was generated.

    Varying the amounts was not enough. At a fixed 50ms interval the requests still scored
    0.93–0.97, because `inter_arrival_variance` is the feature carrying 68% of this model's
    gain and a metronome has none. The pacing is therefore JITTERED and slow — which is not
    a workaround, it is the finding from `eval/RESULTS.md` applied: this model treats
    regularity as adversarial, so a fixture that wants to look ordinary must not be regular.

    A real agent spending a ₹50,000 mandate down does it over days. This does it in about
    twenty seconds, which is as close as a seed step can get and is why the amounts are near
    the per-transaction ceiling rather than realistic.
    """
    settings = get_settings()
    signer = derive_signer(settings.signing_seed, keys_dir=settings.keys_dir)
    store = InMemoryNonceStore()
    scorer, detector, observations, close = await _collaborators(settings)

    spare = load("mandates")[-1]
    agent_id, mandate_id = spare["agent_id"], spare["mandate_id"]
    per_txn = spare["max_per_txn_paise"]

    catalogue = load("catalogue")
    affordable = [
        item for item in catalogue
        if item["price_paise"] < per_txn and item["category"] in {"groceries", "household"}
    ]
    rng = random.Random(SEED)

    async with await psycopg.AsyncConnection.connect(dsn) as conn:
        for attempt in range(max_attempts):
            item = rng.choice(affordable) if affordable else None
            request = AuthorizeRequest(
                agent_id=agent_id, mandate_id=mandate_id, action="purchase",
                # High, so the cap is reached in few enough requests to watch, and always
                # strictly under the per-transaction limit so the GATE never refuses it —
                # the only limit left to hit is the cumulative one.
                amount_paise=rng.randrange(int(per_txn * 0.75), per_txn),
                idempotency_key=f"drain-{uuid.uuid4().hex[:20]}",
                category=item["category"] if item else "groceries",
                sku=item["sku"] if item else "SKU9004",
                cart_id=f"cart-drain-{attempt}",
                instrument_bin="411111",
            )
            body = json.dumps({"drain": attempt}, separators=(",", ":")).encode()
            private = keymod.derive_private_key(SEED, "agent", agent_id)
            headers = http_sig.sign_request(
                private, method="POST", path="/v1/authorize", body=body,
                keyid=agent_id, created=clock.unix(), nonce=uuid.uuid4().hex,
            )
            try:
                outcome = await pipeline.authorize(
                    request, conn=conn, signer=signer, settings=settings,
                    headers=headers, body=body, nonce_store=store,
                    scorer=scorer, detector=detector, observation_store=observations,
                )
                await conn.commit()
            except Exception as exc:  # noqa: BLE001
                await conn.rollback()
                print(f"  drain {attempt:<2} ERROR {type(exc).__name__}: {exc}")
                break

            print(
                f"  drain {attempt:<2} {outcome.decision.decision:<7} "
                f"risk={await _risk_of(conn, outcome.record_id):<7} "
                f"{outcome.decision.rule_fired or outcome.decision.reason_code:<28} "
                f"remaining={outcome.budget_remaining_paise}"
            )
            if outcome.decision.rule_fired == "mandate.max_total":
                score = await _risk_of(conn, outcome.record_id)
                print(
                    "         ^ the cumulative cap. It needs the LEDGER, so it is checked at "
                    "stage 6 — after scoring."
                    if score != "NULL"
                    else "         ^ UNEXPECTED NULL — see DEFENSE entry 4"
                )
                break
            # Jittered, for the reason in the docstring. A fixed interval is a metronome
            # and this model reads a metronome as a machine.
            await asyncio.sleep(rng.uniform(0.9, 3.0))
        else:
            print(
                f"  drain: {max_attempts} attempts did not reach the cumulative cap. The "
                "console will not show `mandate.max_total`, so DEFENSE entry 4's contrast "
                "is only half visible."
            )
    await close()


async def drive_mcp(dsn: str) -> None:
    """Demo beat 7: the three tool calls the MCP enforcement panel exists to show.

    Same pipeline, same chain, same verifier. There is no second authorization path — an MCP
    denial is the same row as an HTTP denial, which is why the panel can read the chain
    rather than a display buffer.
    """
    settings = get_settings()
    signer = derive_signer(settings.signing_seed, keys_dir=settings.keys_dir)
    store = InMemoryNonceStore()
    scorer, detector, observations, close = await _collaborators(settings)

    mandates_seed = load("mandates")[0]
    agent_id, mandate_id = mandates_seed["agent_id"], mandates_seed["mandate_id"]

    from dwaar.mcp import proxy
    from dwaar.mcp import scopes as scopemod

    calls = [
        # The beat. ₹40,000 against a ₹50,000 cap — the AMOUNT is fine and the direction is
        # not, which is the whole distinction.
        ("create_refund", {"amount": 4_000_000}, "DENY on scope"),
        # Not in the map. Unlisted is denied, and that is not a claim the tool is unsafe —
        # it is a statement that nobody has decided.
        ("create_payout_v2", {"amount": 100_000}, "DENY unmapped"),
        # Delegated, and within the cap.
        ("create_order", {"amount": 120_000}, "ALLOW"),
        ("fetch_payment", {}, "ALLOW, read-only, reserves nothing"),
    ]

    async with await psycopg.AsyncConnection.connect(dsn) as conn:
        for tool, arguments, note in calls:
            rule = scopemod.rule_for(tool)
            request = AuthorizeRequest(
                agent_id=agent_id, mandate_id=mandate_id,
                action=proxy.action_for(rule) if rule else "payout",
                amount_paise=arguments.get("amount", 0),
                idempotency_key=f"mcp-{uuid.uuid4().hex[:20]}",
                tool=tool, tool_arguments=arguments,
            )
            body = json.dumps({"tool": tool}, separators=(",", ":")).encode()
            private = keymod.derive_private_key(SEED, "agent", agent_id)
            headers = http_sig.sign_request(
                private, method="POST", path="/v1/mcp/call", body=body,
                keyid=agent_id, created=clock.unix(), nonce=uuid.uuid4().hex,
            )
            try:
                outcome = await pipeline.authorize(
                    request, conn=conn, signer=signer, settings=settings,
                    headers=headers, body=body, path="/v1/mcp/call", nonce_store=store,
                    scorer=scorer, detector=detector, observation_store=observations,
                )
                await conn.commit()
                print(
                    f"  {tool:<18} {outcome.decision.decision:<6} "
                    f"{outcome.decision.rule_fired or outcome.decision.reason_code:<28} "
                    f"risk={await _risk_of(conn, outcome.record_id):<7} — {note}"
                )
            except Exception as exc:  # noqa: BLE001
                await conn.rollback()
                print(f"  {tool:<18} ERROR {type(exc).__name__}: {exc}")
            # Spaced, so four tool calls in a row do not themselves read as a burst.
            await asyncio.sleep(1.2)
    await close()


if __name__ == "__main__":
    dsn = sys.argv[1] if len(sys.argv) > 1 else get_settings().database_url_app
    rounds = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    asyncio.run(seed(dsn))
    asyncio.run(drive(dsn, rounds))
    # Beat 7 BEFORE the drain. The drain deliberately pushes one agent's rolling window
    # hard, and the MCP calls share a gateway with it; running them first keeps the panel's
    # four rows about scope rather than about whatever the window looked like afterwards.
    print("demo beat 7 — MCP scope enforcement")
    asyncio.run(drive_mcp(dsn))
    print("cumulative cap — the scored arithmetic denial (DEFENSE entry 4)")
    asyncio.run(drain_one_mandate(dsn))
