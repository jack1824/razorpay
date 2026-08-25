"""Drive the zoo against a local gateway and write a run manifest.

    python -m zoo.run --requests 60 --seed 20260827

── What this produces, and what it deliberately does not ───────────────────────────────

A manifest at `data/traffic/<run_id>.jsonl`: one line per attempt, plus a header line naming
the run's parameters and which archetype each agent was.

It does **not** produce a training set. The training set is the audit trail —
`decision_records`, written by the gateway from its own features. `tools/train_risk.py` reads
those rows and joins them to this manifest on `agent_id` to attach a label.

That split is the whole design. The gateway never sees a label; this file never sees a
feature. Neither side can encode the other's answer because neither side has it.

── The simulated PSP ───────────────────────────────────────────────────────────────────

After the gateway allows a request, this runner decides whether the *card* would have been
accepted and writes that outcome to the rolling window. It is standing in for the settlement
webhook until Razorpay test mode lands on 29 August, and it is marked `[MOCK PSP]` wherever
it appears.

The agent does not report its own outcome. A card tester telling us its decline rate would be
the model asking the adversary for the answer, and `failure_ratio` would become an agent-
controlled feature.

── Localhost only ──────────────────────────────────────────────────────────────────────

Enforced by `zoo/base.py` on every agent, before any request is built.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import random
import time
from collections import Counter
from dataclasses import asdict
from pathlib import Path

import httpx

from dwaar import clock
from zoo import catalogue as cataloguemod
from zoo.agents import ARCHETYPES, LEGITIMATE
from zoo.base import Agent, Attempt, assert_loopback
from zoo.provision import MAX_PER_TXN_PAISE, Provisioned, provision

DEFAULT_BASE_URL = "http://127.0.0.1:8080"
DEFAULT_MERCHANT = "mch_demo0001"
TRAFFIC_DIR = Path("data/traffic")

#: The simulation spec's requirement: roughly this fraction of LEGITIMATE agents behave, for
#: at least one session, like something worth stopping.
#:
#: **These must generate false positives.** A generator whose classes never overlap gives the
#: model near-perfect scores and makes the false-positive cost in rupees — the one number
#: this project has committed to reporting honestly — pure fiction.
#:
#: `max(1, ...)` rather than a plain fraction, so a small run still contains the overlap
#: instead of rounding it away. The ACTUAL fraction is computed and printed at run time; it
#: is never asserted to be 3%.
BURSTY_FRACTION = 0.03


def build_plan(counts: dict[str, int], seed: int) -> list[tuple[str, str, bool]]:
    """`(archetype, suffix, bursty)` for every agent in the run."""
    rng = random.Random(seed ^ 0x5EED)
    plan: list[tuple[str, str, bool]] = []

    legit_indices: list[int] = []
    for archetype in sorted(counts):
        for n in range(counts[archetype]):
            if archetype in LEGITIMATE:
                legit_indices.append(len(plan))
            plan.append((archetype, f"{archetype[:4]}{n:02d}", False))

    if legit_indices:
        bursty_count = max(1, round(BURSTY_FRACTION * len(legit_indices)))
        for index in rng.sample(legit_indices, min(bursty_count, len(legit_indices))):
            archetype, suffix, _ = plan[index]
            plan[index] = (archetype, suffix, True)

    return plan


def build_agents(
    provisioned: list[Provisioned], *, base_url: str, seed: int, requests: int
) -> list[Agent]:
    catalogue = cataloguemod.load()
    agents: list[Agent] = []
    for index, entry in enumerate(provisioned):
        cls = ARCHETYPES[entry.archetype]
        kwargs = {
            "base_url": base_url,
            # Distinct per agent, derived from the run seed: two agents of the same
            # archetype must not issue identical request streams, or every feature computed
            # over them is measured on one agent repeated N times.
            "seed": seed * 1000 + index,
            "catalogue": catalogue,
            "requests": max(1, int(round(requests * cls.request_multiplier))),
        }
        if cls.name == "budget_breacher":
            kwargs["max_per_txn_paise"] = MAX_PER_TXN_PAISE
        if cls.name == "legit_shopper":
            kwargs["bursty"] = entry.bursty
        agents.append(cls(entry.identity, **kwargs))
    return agents


async def run_agent(
    agent: Agent, client: httpx.AsyncClient, psp, *, jitter: random.Random
) -> list[Attempt]:
    """One agent's whole run. Failures are recorded, never raised.

    An agent that dies halfway through leaves a truncated behavioural window, and the
    features computed from it would be real features of a run that did not happen.
    """
    # Stagger the start so every agent does not fire its first request in the same
    # millisecond, which would put an artificial burst at the head of every window.
    await asyncio.sleep(jitter.uniform(0.0, 2.0))

    for _ in range(agent.requests):
        payload = agent.build_body()
        attempt = await agent.send(client, payload)
        agent.attempts.append(attempt)

        # [MOCK PSP] Only an allowed request reaches a card. The gateway's own denials never
        # feed a feature — that is the line the arithmetic gate must not be able to cross.
        if attempt.decision in ("allow", "bound"):
            succeeded = agent.payment_would_succeed()
            attempt.payment_succeeded = succeeded
            if psp is not None:
                await psp.record_outcome(
                    agent_id=agent.identity.agent_id,
                    principal_id=agent.identity.principal_id,
                    succeeded=succeeded,
                )

        await asyncio.sleep(max(0.0, agent.next_gap()))

    return agent.attempts


async def main_async(args: argparse.Namespace) -> int:
    assert_loopback(args.base_url)

    counts = {
        "legit_shopper": args.legit,
        "card_tester": args.card_tester,
        "budget_breacher": args.budget_breacher,
        "injector": args.injector,
    }
    counts = {name: n for name, n in counts.items() if n > 0}
    if not counts:
        print("no agents requested")
        return 2

    plan = build_plan(counts, args.seed)
    provisioned = await provision(
        args.dsn, merchant_id=args.merchant, seed=args.seed, plan=plan
    )
    agents = build_agents(
        provisioned, base_url=args.base_url, seed=args.seed, requests=args.requests
    )

    psp = None
    if args.redis_url:
        from redis.asyncio import Redis

        from dwaar.risk.observations import RedisObservationStore

        psp = RedisObservationStore(Redis.from_url(args.redis_url))

    # perf_counter for the DURATION, the seam for the INSTANT. They are different
    # questions and one variable was answering both: `elapsed` wanted a monotonic
    # measure and `run_id` wanted a wall-clock stamp, and a clock step would have
    # corrupted whichever one it hit.
    started_at = clock.now()
    started = time.perf_counter()
    jitter = random.Random(args.seed ^ 0xABCDEF)

    async with httpx.AsyncClient(timeout=10.0) as client:
        await asyncio.gather(
            *(run_agent(agent, client, psp, jitter=jitter) for agent in agents)
        )
    elapsed = time.perf_counter() - started

    run_id = f"{args.seed}-{int(started_at.timestamp())}"
    TRAFFIC_DIR.mkdir(parents=True, exist_ok=True)
    out = Path(args.out) if args.out else TRAFFIC_DIR / f"{run_id}.jsonl"

    by_agent = {entry.identity.agent_id: entry for entry in provisioned}
    decisions: Counter[str] = Counter()
    per_archetype: Counter[str] = Counter()

    with out.open("w", encoding="utf-8") as handle:
        handle.write(
            json.dumps(
                {
                    "kind": "run",
                    "run_id": run_id,
                    "seed": args.seed,
                    "base_url": args.base_url,
                    "merchant_id": args.merchant,
                    "requests_per_agent": args.requests,
                    "started_at": started,
                    "elapsed_seconds": round(elapsed, 3),
                    "agents": [
                        {
                            "agent_id": entry.identity.agent_id,
                            "mandate_id": entry.identity.mandate_id,
                            "principal_id": entry.identity.principal_id,
                            "archetype": entry.archetype,
                            "is_legitimate": entry.archetype in LEGITIMATE,
                            "bursty": entry.bursty,
                        }
                        for entry in provisioned
                    ],
                }
            )
            + "\n"
        )
        for agent in agents:
            entry = by_agent[agent.identity.agent_id]
            for attempt in agent.attempts:
                decisions[attempt.decision or f"http_{attempt.status_code}"] += 1
                per_archetype[entry.archetype] += 1
                handle.write(
                    json.dumps({"kind": "attempt", **asdict(attempt)}) + "\n"
                )

    legit_agents = [e for e in provisioned if e.archetype in LEGITIMATE]
    bursty_agents = [e for e in legit_agents if e.bursty]
    total = sum(per_archetype.values())

    # Every number here is computed from what happened. Rule 4.
    print(f"run {run_id}")
    print(f"  wall clock       {elapsed:8.1f}s")
    print(f"  attempts         {total:8d}")
    for archetype in sorted(per_archetype):
        print(f"    {archetype:<18}{per_archetype[archetype]:6d}")
    print("  decisions")
    for decision in sorted(decisions):
        share = decisions[decision] / total if total else 0.0
        print(f"    {decision:<18}{decisions[decision]:6d}  {share:6.1%}")
    fraction = len(bursty_agents) / len(legit_agents) if legit_agents else 0.0
    print(
        f"  legitimate agents with adversary-like bursts: "
        f"{len(bursty_agents)}/{len(legit_agents)} = {fraction:.1%}"
    )
    if not bursty_agents and legit_agents:
        print("  WARNING: no overlap generated — the false-positive cost would be fiction")
    print(f"  manifest         {out}")

    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    parser.add_argument("--merchant", default=DEFAULT_MERCHANT)
    parser.add_argument("--seed", type=int, default=20260827)
    parser.add_argument("--requests", type=int, default=60, help="per agent")
    parser.add_argument("--legit", type=int, default=20)
    parser.add_argument("--card-tester", type=int, default=3, dest="card_tester")
    parser.add_argument("--budget-breacher", type=int, default=3, dest="budget_breacher")
    parser.add_argument("--injector", type=int, default=3)
    parser.add_argument("--out", default=None)
    parser.add_argument(
        "--dsn",
        default=os.environ.get(
            "DATABASE_URL_MIGRATE",
            "postgresql://dwaar_owner:owner_pw@localhost:5432/dwaar",
        ),
        help="OWNER dsn — provisioning creates agents, principals and mandates",
    )
    parser.add_argument(
        "--redis-url",
        default=os.environ.get("REDIS_URL", "redis://localhost:6379/0"),
        help="[MOCK PSP] where simulated payment outcomes are written",
    )
    return parser


def main() -> int:
    return asyncio.run(main_async(build_parser().parse_args()))


if __name__ == "__main__":
    raise SystemExit(main())
