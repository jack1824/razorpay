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

from tests._support.importgraph import REPO_ROOT

DWAAR_ROOT = REPO_ROOT / "dwaar"

# Any mention at all. A path built by string concatenation is still caught by "ground_truth",
# and there is no legitimate reason for that substring to appear under dwaar/.
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
    violations: list[str] = []
    for path in _sources():
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if pattern.search(line):
                rel = path.relative_to(REPO_ROOT)
                violations.append(f"  {rel}:{lineno}: {line.strip()}")

    assert not violations, (
        f"dwaar/ must never reference {pattern.pattern} — the gateway cannot be allowed to "
        "see archetype labels, or the evaluation measures nothing:\n" + "\n".join(violations)
    )


def test_ground_truth_is_not_copied_into_the_repo():
    """The labelled file must not be vendored anywhere the service could reach it.

    The vendored strategy package under docs/strategy/ is documentation and is not
    importable or served; anywhere else is a leak waiting to happen.
    """
    strays = [
        p.relative_to(REPO_ROOT)
        for p in REPO_ROOT.rglob("ground_truth.json")
        if "docs/strategy" not in str(p.relative_to(REPO_ROOT))
    ]
    assert not strays, (
        "ground_truth.json may only exist under docs/strategy/ (documentation) or eval/ "
        f"once eval/ exists. Found: {strays}"
    )
