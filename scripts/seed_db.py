"""Load `data/seed/` into the database, then drive a few decisions.

Not the demo runner (that is `make demo`, day 30). This exists so the console has something
to show while the risk model, the zoo and the MCP proxy are being built — which is the
justification for pulling the console forward at all.
"""

from __future__ import annotations

import asyncio
import json
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
            if await mandates.get(conn, mandate["mandate_id"]) is None:
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
                )
        await conn.commit()
    print("seeded agents, principals and mandates")


async def drive(dsn: str, rounds: int = 1) -> None:
    """Run the timeline's purchase beats through the real pipeline."""
    settings = get_settings()
    signer = derive_signer(settings.signing_seed, keys_dir=settings.keys_dir)
    store = InMemoryNonceStore()
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
                    )
                    await conn.commit()
                    print(
                        f"  beat {beat.get('beat'):<4} {outcome.decision.decision:<6} "
                        f"{outcome.decision.rule_fired or outcome.decision.reason_code}"
                    )
                except Exception as exc:  # noqa: BLE001
                    await conn.rollback()
                    print(f"  beat {beat.get('beat'):<4} ERROR {type(exc).__name__}: {exc}")
                await asyncio.sleep(0.4)


if __name__ == "__main__":
    dsn = sys.argv[1] if len(sys.argv) > 1 else get_settings().database_url_app
    rounds = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    asyncio.run(seed(dsn))
    asyncio.run(drive(dsn, rounds))
