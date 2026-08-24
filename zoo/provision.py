"""Register the zoo's agents, principals and mandates.

── Every mandate is IDENTICAL ──────────────────────────────────────────────────────────

Same caps, same allow list, same deny list, same expiry, for every archetype.

That is the single most important line in this file. If the adversarial agents held tighter
mandates than the legitimate ones, the mandate would *be* the label: the gateway would deny
them more often for reasons that have nothing to do with their behaviour, the model would
learn the difference, and the evaluation would measure how the fixtures were written.

`tests/zoo/test_traffic.py` asserts the mandates are identical across archetypes, because
this is exactly the kind of thing that drifts when someone tunes a run to make a demo work.

── Keys ────────────────────────────────────────────────────────────────────────────────

Derived by HKDF from a published seed, the same mechanism the gateway and the test fixtures
use. The whole system is reproducible from a handful of integers, and an agent's private key
never has to exist on disk.

── Where this connects ─────────────────────────────────────────────────────────────────

The **owner** DSN, because it creates rows in `agents`, `principals` and `mandates`. That is
correct and it is worth noticing: the zoo provisions like an operator and then makes requests
like an agent, over HTTP, with no privilege at all. The two roles are not mixed.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import psycopg

from dwaar.crypto import keys as keymod
from dwaar.crypto import mandate as mandatemod
from dwaar.db.repositories import agents as agents_repo
from dwaar.db.repositories import mandates as mandates_repo
from dwaar.db.repositories import principals as principals_repo
from zoo.base import AgentIdentity

#: Identical for every archetype. See the module docstring.
#:
#: ₹20,000 per transaction is above almost every catalogue item, so a legitimate shopper is
#: rarely stopped by arithmetic and the model actually gets to see its traffic. ₹5,00,000
#: total is enough that a full run does not exhaust the budget and turn every late request
#: into a cumulative denial — which would put a spending-limit signal into the labels.
MAX_PER_TXN_PAISE = 2_000_000
MAX_TOTAL_PAISE = 50_000_000

#: `gift_cards` is denied for everyone, including the legitimate shoppers, whose category
#: mix occasionally lands there. A legitimate agent asking for something outside its mandate
#: and being refused is normal traffic, not an anomaly, and the record should contain some.
ALLOW_CATEGORIES = [
    "groceries", "apparel", "electronics", "household",
    "personal_care", "pharmacy", "stationery",
]
DENY_CATEGORIES = ["gift_cards"]


@dataclass(frozen=True)
class Provisioned:
    identity: AgentIdentity
    archetype: str
    display_name: str
    bursty: bool = False
    """Legitimate agents only: this one exhibits adversary-like bursts and MUST be allowed
    to produce false positives. Never read by anything under `dwaar/`."""


async def provision(
    dsn: str,
    *,
    merchant_id: str,
    seed: int,
    plan: list[tuple[str, str, bool]],
) -> list[Provisioned]:
    """Create one agent, principal and mandate per entry in `plan`.

    `plan` is a list of `(archetype, agent_suffix, bursty)`. Returns the identities the
    runner signs with. Everything is committed before any traffic starts, so a partial
    provision cannot produce an agent that authenticates against a mandate that does not
    exist.
    """
    provisioned: list[Provisioned] = []
    expires_at = datetime.now(UTC) + timedelta(days=30)

    async with await psycopg.AsyncConnection.connect(dsn) as conn:
        for index, (archetype, suffix, bursty) in enumerate(plan):
            agent_id = f"agt_{_slug(seed, 'agent', index)}"
            principal_id = f"prn_{_slug(seed, 'principal', index)}"
            mandate_id = f"mnd_{_slug(seed, 'mandate', index)}"

            agent_key = keymod.derive_private_key(seed, "agent", agent_id)
            principal_key = keymod.derive_private_key(seed, "principal", principal_id)

            await _ensure_principal(
                conn, principal_id, merchant_id, keymod.public_bytes(principal_key)
            )
            await _ensure_agent(
                conn,
                agent_id,
                # A display name that does NOT contain the archetype. An agent called
                # "card_tester_01" would put the label in the database, in every log line
                # and on the console — the leak would be complete before a single feature
                # was computed.
                display_name=f"zoo-agent-{suffix}",
                public_key=keymod.public_bytes(agent_key),
                merchant_id=merchant_id,
            )

            payload = mandatemod.build_payload(
                mandate_id=mandate_id,
                principal_id=principal_id,
                agent_id=agent_id,
                max_total_paise=MAX_TOTAL_PAISE,
                max_per_txn_paise=MAX_PER_TXN_PAISE,
                allow_categories=ALLOW_CATEGORIES,
                deny_categories=DENY_CATEGORIES,
                substitution_tolerance="same_price",
                expires_at=expires_at,
                nonce=uuid.uuid4().hex,
            )
            canonical = mandatemod.canonical_json(payload)
            await _ensure_mandate(
                conn,
                mandate_id=mandate_id,
                principal_id=principal_id,
                agent_id=agent_id,
                expires_at=expires_at,
                payload=payload,
                canonical=canonical,
                signature=principal_key.sign(canonical.encode()),
            )

            provisioned.append(
                Provisioned(
                    identity=AgentIdentity(
                        agent_id=agent_id,
                        principal_id=principal_id,
                        mandate_id=mandate_id,
                        seed=seed,
                    ),
                    archetype=archetype,
                    display_name=f"zoo-agent-{suffix}",
                    bursty=bursty,
                )
            )
        await conn.commit()

    return provisioned


def _slug(seed: int, kind: str, index: int) -> str:
    """Twelve lowercase hex characters, deterministic in the seed.

    Deterministic so a rerun with the same seed reuses the same identities — otherwise every
    run would leave a fresh set of agents behind and the console would fill with ghosts.
    """
    import hashlib

    digest = hashlib.sha256(f"{seed}:{kind}:{index}".encode()).hexdigest()
    return digest[:12]


async def _ensure_principal(conn, principal_id, merchant_id, public_key) -> None:
    existing = await principals_repo.get(conn, principal_id)
    if existing is None:
        await principals_repo.create(
            conn,
            principal_id=principal_id,
            merchant_id=merchant_id,
            public_key=public_key,
        )


async def _ensure_agent(conn, agent_id, *, display_name, public_key, merchant_id) -> None:
    existing = await agents_repo.get(conn, agent_id)
    if existing is None:
        await agents_repo.create(
            conn,
            agent_id=agent_id,
            display_name=display_name,
            public_key=public_key,
            registered_by=merchant_id,
        )


async def _ensure_mandate(
    conn,
    *,
    mandate_id: str,
    principal_id: str,
    agent_id: str,
    expires_at: datetime,
    payload: dict[str, Any],
    canonical: str,
    signature: bytes,
) -> None:
    existing = await mandates_repo.get(conn, mandate_id)
    if existing is not None:
        return
    await mandates_repo.create(
        conn,
        mandate_id=mandate_id,
        principal_id=principal_id,
        agent_id=agent_id,
        max_total_paise=MAX_TOTAL_PAISE,
        max_per_txn_paise=MAX_PER_TXN_PAISE,
        expires_at=expires_at,
        nonce=payload["nonce"],
        canonical_json=canonical,
        signature=signature,
        mandate_hash=mandatemod.mandate_hash(payload),
        allow_categories=ALLOW_CATEGORIES,
        deny_categories=DENY_CATEGORIES,
        substitution_tolerance="same_price",
    )
