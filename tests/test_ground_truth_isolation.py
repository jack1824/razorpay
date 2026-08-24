"""`dwaar/` must never read `ground_truth.json`.

`16_DEMO_DATA/ground_truth.json` holds the archetype label and the held-out flag for every
agent. `eval/` loads it; nothing else may. If the gateway can see the label, the evaluation
measures whether we can read a file rather than whether the system works, and every number
in the eval table becomes worthless.

`docs/strategy/16_DEMO_DATA/README.md` asserts *"There is a CI test asserting `dwaar/` never
reads it."* The package documented a control it did not ship. This is that control.

The check is a source scan, not an import walk: the leak this guards against is
``open("ground_truth.json")``, which no import graph would show.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from tests._support import sourcescan
from tests._support.importgraph import REPO_ROOT

DWAAR_ROOT = REPO_ROOT / "dwaar"

# Any mention in CODE. A path built by string concatenation is still caught by
# "ground_truth", and there is no legitimate reason for that substring to appear in
# executable source under dwaar/.
#
# Comments and docstrings are excluded, by the shared stripper rather than by a rule
# invented here. `dwaar/risk/` has to be able to state in prose that it never sees a label
# — that statement is the point of the module — and a check that forbids the word in the
# documentation as well as in the code forces the documentation to be deleted, which is
# the opposite of the outcome wanted. A string literal is NOT prose and is still scanned,
# so `open("ground_truth.json")` is caught exactly as before.
FORBIDDEN_PATTERNS = [
    re.compile(r"ground_truth", re.IGNORECASE),
    re.compile(r"\barchetype\b", re.IGNORECASE),
    re.compile(r"\bheld_out\b", re.IGNORECASE),
]


def _sources() -> list[Path]:
    return sorted(DWAAR_ROOT.rglob("*.py"))


def test_dwaar_has_sources_to_scan():
    """Guard against a vacuous pass."""
    assert len(_sources()) >= 10, (
        f"expected sources under dwaar/, found {len(_sources())}"
    )


@pytest.mark.parametrize("pattern", FORBIDDEN_PATTERNS, ids=lambda p: p.pattern)
def test_dwaar_never_references_ground_truth(pattern):
    result = sourcescan.scan([DWAAR_ROOT], [pattern], relative_to=REPO_ROOT)
    assert result.files_scanned >= 10, (
        f"only {result.files_scanned} sources scanned; a scanner with nothing to scan "
        "passes vacuously"
    )
    assert not result.findings, (
        f"dwaar/ must never reference {pattern.pattern} in code — the gateway cannot be "
        "allowed to see evaluation labels, or the evaluation measures nothing:\n"
        + sourcescan.render(result.findings)
    )


# Where the labelled file is allowed to live. `data/seed/` is the generator's output and
# is read by `eval/` only; `docs/strategy/` is untracked local reference. Anywhere else —
# and especially anywhere under `dwaar/` — is a leak waiting to happen.
ALLOWED_GROUND_TRUTH_DIRS = ("data/seed", "docs/strategy", "eval")


def test_ground_truth_lives_only_where_the_evaluator_reads_it():
    strays = [
        rel
        for p in REPO_ROOT.rglob("ground_truth.json")
        if not str(rel := p.relative_to(REPO_ROOT)).startswith(ALLOWED_GROUND_TRUTH_DIRS)
    ]
    assert not strays, (
        f"ground_truth.json may only live under {list(ALLOWED_GROUND_TRUTH_DIRS)}. "
        f"Found: {strays}"
    )


def test_ground_truth_is_never_inside_the_service_package():
    """The specific failure the control exists for, asserted directly."""
    assert not list((DWAAR_ROOT).rglob("ground_truth.json"))
    assert not list((DWAAR_ROOT).rglob("*archetype*"))
