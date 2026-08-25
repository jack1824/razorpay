"""The demo seeder must write records that look like the running system.

── The defect this exists to prevent ───────────────────────────────────────────────────

`scripts/seed_db.py` called `pipeline.authorize()` with no scorer, no detector and no
observation store. Every stage still ran, nothing failed, and every row it wrote carried
`features_degraded` and `risk_model_unavailable` with `risk_score` NULL.

The console then showed NULL on every decision — including the allows — and a
`mandate.max_total` denial showed NULL as well, when per DEFENSE entry 4 that one is scored
because the cumulative cap needs the ledger and therefore cannot be checked before the model.
Both looked like defects in the gateway. Neither was. The seeder was writing an honest record
of a gateway running without a model, and that was not the gateway being demonstrated.

**It cost a demo attempt**, which is the only reason a fixture script gets its own test file.

── Why this is a source check rather than a database one ───────────────────────────────

The database half is already covered: `tests/db/test_authorize_pipeline.py` asserts a healthy
request carries an empty `degraded_mode`. What that cannot see is a *caller* that omits the
collaborators, because omitting them is not an error — it is the documented degraded path, and
it is correct behaviour for a gateway that genuinely has no model.

So the check is on the call site. Same shape as `tests/test_clock_seam.py` and
`tests/test_fixture_discipline.py`, and the sixth caller of the shared stripper.
"""

from __future__ import annotations

import inspect
import re
from pathlib import Path

from tests._support.sourcescan import strip_python

REPO = Path(__file__).resolve().parents[1]
SEEDER = REPO / "scripts" / "seed_db.py"

#: Every collaborator the API builds at startup and injects into the pipeline. A seeder that
#: passes none of them produces a chain of degraded rows; one that passes some of them
#: produces a chain that is wrong in a subtler way.
REQUIRED = ("scorer=", "detector=", "observation_store=")


def _source() -> str:
    return strip_python(SEEDER.read_text(encoding="utf-8"))


def test_the_seeder_passes_every_collaborator_the_api_does():
    source = _source()
    calls = re.findall(r"pipeline\.authorize\((.*?)\n\s*\)", source, re.S)
    assert calls, "no pipeline.authorize call found in the seeder — has it moved?"
    for index, call in enumerate(calls):
        missing = [name for name in REQUIRED if name not in call]
        assert not missing, (
            f"pipeline.authorize call {index + 1} in scripts/seed_db.py omits {missing}. "
            "Every stage still runs without them, so nothing fails — the records it writes "
            "simply carry `features_degraded` and `risk_model_unavailable` with a NULL "
            "score, and the console then shows NULL on every decision including the allows. "
            "That is an honest record of a gateway with no model, and it is not the gateway "
            "being demonstrated."
        )


def test_a_missing_model_is_fatal_rather_than_degraded():
    """`load()` returning None is correct for the API and wrong for the seeder.

    The API reports a missing bundle as a degraded component and keeps serving, because the
    gate, the policy engine and the ledger are unaffected. The seeder must stop: its entire
    purpose is to produce records that look like the running system, and another chain of
    unscored rows reads as a broken gateway rather than as a missing file.
    """
    source = _source()
    body = source[source.index("async def _collaborators") :]
    # The NEXT top-level definition, `async` or not. Matching only `\ndef ` missed it,
    # because everything in this module is a coroutine.
    following = re.search(r"^(?:async )?def ", body[1:], re.M)
    body = body[: following.start() + 1] if following else body
    assert "SystemExit" in body, (
        "scripts/seed_db.py must REFUSE to seed without a model bundle, not seed a degraded "
        "chain. See the module docstring."
    )
    assert "make train" in body, "the refusal should name the remedy"


def test_the_seeder_sends_the_behavioural_context_the_timeline_carries():
    """F-045: a request with no `instrument_bin` produces `bin_diversity = 0`, a value no
    training request ever had, and the anomaly model reads it as extreme. The timeline carries
    a card on every purchase beat; the seeder used to drop it."""
    source = _source()
    for field in ("instrument_bin=", "cart_id="):
        assert field in source, (
            f"the seeder does not forward {field.rstrip('=')!r}. The timeline carries it and "
            "dropping it puts the request outside the training distribution — F-045."
        )


def test_beat_seven_is_seeded():
    """The MCP enforcement panel reads the chain, so it is empty until something puts MCP
    decisions in it. An empty panel on demo day is beat 7 not happening."""
    source = _source()
    assert "drive_mcp" in source
    for tool in ("create_refund", "create_payout_v2", "create_order"):
        assert tool in source, f"beat 7 needs {tool}: scope denied, unmapped, and permitted"


def test_the_module_docstring_records_why_this_matters():
    """Not decoration. The next person to touch this file needs to know that omitting a
    collaborator is silent, and the docstring is where they will look."""
    import scripts.seed_db as seeder

    doc = inspect.getdoc(seeder) or ""
    assert "degraded" in doc.lower(), "the docstring must explain the failure it prevents"
