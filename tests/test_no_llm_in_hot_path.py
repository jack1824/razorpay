"""Rule 1, behaviourally: no LLM is CALLED during authorize.

The companion to `test_hot_path_purity.py`, which proves the LLM is not *reachable*.
Neither test subsumes the other and the README promises both:

    static closure   catches reachability, including a path no request happened to take.
                     Blind to a raw httpx call — no import involved.
    this test        catches invocation, including dynamic dispatch and a raw HTTP call
                     the walker cannot see. Only covers the requests it actually sends.

The client is monkeypatched to raise, so an invocation cannot be swallowed by a broad
`except` somewhere in the pipeline — it would surface as a failed request, and the assertion
below checks every response.
"""

from __future__ import annotations

import pytest

from dwaar.authorize import pipeline
from dwaar.authorize.types import AuthorizeRequest
from dwaar.metrics import llm_calls_in_hot_path

pytestmark = pytest.mark.db

REQUESTS = 1_000


@pytest.fixture
def exploding_llm(monkeypatch):
    """Any call to the LLM client becomes a loud, unswallowable failure."""
    calls: list[str] = []

    async def explode(*args, **kwargs):
        calls.append("invoked")
        llm_calls_in_hot_path.inc()
        raise AssertionError(
            "LLM invoked in the hot path. 500-2000ms against a 25ms budget is the small "
            "problem; making the decision-maker the injection target is the real one."
        )

    monkeypatch.setattr("dwaar.llm.client.complete", explode)
    return calls


async def test_authorize_never_calls_the_llm(
    app_dsn, owner_dsn, make_mandate, signer, exploding_llm, settings
):
    """1,000 authorize calls, mixed outcomes, zero LLM invocations."""
    import psycopg

    from dwaar.crypto.signer import ensure_registered

    setup = await psycopg.AsyncConnection.connect(owner_dsn)
    mandate = await make_mandate(
        setup, merchant_id="mch_nollm", max_total_paise=1_000_000_000,
        max_per_txn_paise=500_000,
    )
    await ensure_registered(setup, signer)
    await setup.commit()
    await setup.close()

    decisions = set()
    async with await psycopg.AsyncConnection.connect(app_dsn) as conn:
        for i in range(REQUESTS):
            # Deliberately mixed: allows, per-transaction breaches, and denied categories,
            # so the run covers the short-circuit path as well as the full pipeline.
            if i % 3 == 0:
                amount, category = 1_200_000, "apparel"      # breaches per-txn
            elif i % 3 == 1:
                amount, category = 1_000, "gift_cards"       # denied category
            else:
                amount, category = 1_000, "groceries"        # allowed

            outcome = await pipeline.authorize(
                AuthorizeRequest(
                    agent_id=mandate["agent_id"],
                    mandate_id=mandate["mandate_id"],
                    action="purchase",
                    amount_paise=amount,
                    idempotency_key=f"nollm-{i:06d}-{'x' * 8}",
                    category=category,
                ),
                conn=conn,
                signer=signer,
                settings=settings,
            )
            decisions.add(outcome.decision.decision)
            await conn.commit()

    assert exploding_llm == [], f"LLM was invoked {len(exploding_llm)} times"
    assert decisions == {"allow", "deny"}, (
        f"expected the run to exercise both outcomes, got {decisions}"
    )


async def test_the_explode_fixture_actually_works(exploding_llm):
    """A monkeypatch test that silently patched the wrong name would pass forever.

    This asserts the trap is armed, which is the only thing standing between this test and
    a permanent false negative.
    """
    from dwaar.llm import client

    with pytest.raises(AssertionError, match="LLM invoked in the hot path"):
        await client.complete("anything")
    assert exploding_llm == ["invoked"]
