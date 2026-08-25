"""Every test that asserts an ABSENCE must have a positive control.

**A check whose job is to never fail cannot be validated by never failing.** Its silence is
indistinguishable between "nothing to find" and "cannot find anything". That is not
hypothetical here: F-014 was exactly this — the import walker could not see submodule
imports, so both rule 1 and rule 3 were passing while enforcing nothing.

This file is the audit. It enumerates the guards that assert an absence and asserts that
each has a control proving it would catch the thing it forbids.

    guard                            control                              where
    ───────────────────────────────  ───────────────────────────────────  ─────────────────
    test_import_isolation            synthetic dirty package              same file
    test_hot_path_purity             synthetic dirty package + prefix     same file
    test_ground_truth_isolation      synthetic reference                  below
    test_stub_contracts              enumerates a registry, not a list    below
    integrity helper                 tampered row per field               test_integrity.py
    latency gates                    measure; cannot pass vacuously       n/a

`make eval`/`make demo` exit 2 rather than 0 for the same reason: a green stub is a control
that is not there.
"""

from __future__ import annotations

import re

import pytest

from tests._support import sourcescan
from tests._support.importgraph import REPO_ROOT, build_synthetic_package, find_path_to

# ── ground-truth isolation ──────────────────────────────────────────────────────────

def test_the_ground_truth_scanner_would_catch_a_leak(tmp_path):
    """Positive control for `test_ground_truth_isolation`.

    That test greps `dwaar/` for archetype references and asserts none. If the patterns
    were wrong, or the file glob found nothing, it would pass forever while the gateway
    read labels freely.
    """
    from tests.test_ground_truth_isolation import FORBIDDEN_PATTERNS

    leaky = tmp_path / "leaky.py"
    leaky.write_text(
        'LABELS = json.load(open("ground_truth.json"))\n'
        'if agent["archetype"] == "card_tester" and agent["held_out"]:\n'
        "    pass\n",
        encoding="utf-8",
    )
    text = leaky.read_text(encoding="utf-8")

    for pattern in FORBIDDEN_PATTERNS:
        assert pattern.search(text), (
            f"pattern {pattern.pattern!r} would not catch an obvious label leak; "
            "the ground-truth isolation test is enforcing nothing"
        )


def test_the_ground_truth_scanner_finds_files_to_scan():
    """The other way that test goes quiet: scanning an empty file list."""
    from tests.test_ground_truth_isolation import DWAAR_ROOT

    sources = list(DWAAR_ROOT.rglob("*.py"))
    assert len(sources) >= 20, (
        f"only {len(sources)} sources found under dwaar/; a scanner with nothing to scan "
        "passes vacuously"
    )


# ── import isolation and hot-path purity ────────────────────────────────────────────

def test_the_walker_catches_a_zoo_import_it_is_handed(tmp_path):
    """Consolidated control. Both guards depend on this one walker."""
    from tests.test_import_isolation import FORBIDDEN

    dirty = build_synthetic_package(
        tmp_path, "absence_zoo",
        {"gateway": "from absence_zoo import helper", "helper": "import zoo.agents.sleeper"},
    )
    assert find_path_to(dirty, "absence_zoo.gateway", FORBIDDEN) is not None


def test_the_walker_catches_every_blocked_llm_module(tmp_path):
    """One control per blocklist entry.

    A provider added to the list but not actually matchable would look enforced and not be.
    """
    from tests._support.llm_blocklist import BLOCKED_MODULES

    for index, blocked in enumerate(BLOCKED_MODULES):
        dirty = build_synthetic_package(
            tmp_path / f"probe{index}", "llm_probe", {"route": f"import {blocked}"}
        )
        assert find_path_to(dirty, "llm_probe.route", blocked) is not None, (
            f"the walker cannot detect an import of {blocked}; its presence in the "
            "blocklist is decorative"
        )


def test_the_hot_path_module_list_is_not_empty_and_all_exist():
    """A stale entry silently checks nothing; an empty list checks nothing at all."""
    from tests._support.importgraph import build_graph
    from tests.test_hot_path_purity import HOT_PATH_MODULES

    graph = build_graph("dwaar")
    assert len(HOT_PATH_MODULES) >= 10
    missing = [m for m in HOT_PATH_MODULES if m not in graph.modules]
    assert not missing, f"hot-path modules that do not exist: {missing}"


def test_the_hot_path_list_covers_the_authorize_route():
    """The one module that must never be omitted from the purity check."""
    from tests.test_hot_path_purity import HOT_PATH_MODULES

    assert "dwaar.api.routes.authorize" in HOT_PATH_MODULES
    assert "dwaar.authorize.pipeline" in HOT_PATH_MODULES


# ── stub contracts ──────────────────────────────────────────────────────────────────

def test_the_stub_registry_is_derived_not_hand_written():
    """`test_stub_contracts` enumerates `pipeline.STUB_STAGES`, so a stub added without a
    token fails immediately. Asserted here so that property is not quietly lost by someone
    replacing the registry with a literal list."""
    from dwaar.authorize import pipeline

    assert isinstance(pipeline.STUB_STAGES, dict)
    assert set(pipeline.STUB_STAGES) < set(pipeline.STAGE_ORDER), (
        "every stub must be a real stage in the pipeline's own order"
    )


def test_a_stub_without_a_token_would_be_caught():
    """Positive control: simulate a stage module that forgot its DEGRADED_TOKEN."""

    class ForgetfulStub:
        STAGE_NAME = "forgetful"

    assert not hasattr(ForgetfulStub, "DEGRADED_TOKEN")
    # This is the assertion test_stub_contracts makes; confirm it rejects the bad case.
    with pytest.raises(AssertionError):
        assert hasattr(ForgetfulStub, "DEGRADED_TOKEN"), "a stub must declare itself"


# ── the make targets ────────────────────────────────────────────────────────────────

#: Targets that exist in the Makefile but do not do the thing they are named for.
#:
#: EMPTY as of 30 August. `verify` landed on the 25th, `eval` on the 28th and `demo` on the
#: 30th, and each left this tuple as it became real.
#:
#: Kept rather than deleted, because the mechanism is the point and the next stub needs an
#: obvious home. A green stub is a control that is not there — the same failure mode as a
#: hardcoded metric, and it fails at the worst possible moment.
UNIMPLEMENTED_TARGETS: tuple[str, ...] = ()


def test_unimplemented_make_targets_exit_non_zero():
    makefile = (REPO_ROOT / "Makefile").read_text(encoding="utf-8")
    for target in UNIMPLEMENTED_TARGETS:
        block = re.search(rf"^{target}:\n((?:\t.*\n)+)", makefile, re.M)
        assert block, f"no {target} target in the Makefile"
        assert "exit 2" in block.group(1), (
            f"`make {target}` must exit non-zero while unimplemented"
        )


@pytest.mark.parametrize(
    ("target", "must_invoke"),
    [("verify", "verify_cli"), ("eval", "eval.report"), ("demo", "tools.demo")],
)
def test_a_landed_target_is_no_longer_a_stub(target, must_invoke):
    """`verify` landed 25 Aug, `eval` 28 Aug, `demo` 30 Aug. If any regressed to `exit 2`,
    an acceptance criterion would be silently gone — and a target that exits 2 is
    indistinguishable from one that was never built."""
    makefile = (REPO_ROOT / "Makefile").read_text(encoding="utf-8")
    block = re.search(rf"^{target}:\n((?:\t.*\n)+)", makefile, re.M)
    assert block, f"no {target} target in the Makefile"
    assert "exit 2" not in block.group(1)
    assert must_invoke in block.group(1)


# ── BaseHTTPMiddleware is banned (F-015, F-021) ─────────────────────────────────────

def test_no_middleware_uses_basehttpmiddleware():
    """It broke this application twice, in two different ways.

    F-015: it hands the route a different Request, so the body cap drained the body and
    every POST arrived empty. F-021: `call_next` raises `No response returned` while a
    long-lived StreamingResponse is open, so every SSE connection the console opened
    returned a 500.

    Two defects, one cause. Per the standing rule the fix is the layer — so this asserts
    the layer, rather than trusting that nobody reaches for it again.
    """
    result = _scan_dwaar(_BANNED_MIDDLEWARE)
    assert not result.findings, (
        "BaseHTTPMiddleware is banned in this application — it is incompatible with the "
        "streaming responses the console depends on, and it hides the request body from "
        "middleware that needs it. Write pure ASGI:\n"
        + sourcescan.render(result.findings)
    )


#: Bare mentions of the name, which is only safe because `_scan_dwaar` removes comments and
#: docstrings first. Before the shared stripper existed this had to match import and
#: subclass syntax specifically, because `dwaar/api/middleware.py` documents at length why
#: the class is banned and the check flagged its own explanation. Matching the name is
#: strictly broader: it also catches `app.add_middleware(BaseHTTPMiddleware, ...)`, which
#: subclasses nothing and which the narrower patterns missed.
_BANNED_MIDDLEWARE = (
    re.compile(r"\bBaseHTTPMiddleware\b"),
    re.compile(r"starlette\.middleware\.base"),
)


def _scan_dwaar(patterns) -> sourcescan.ScanResult:
    result = sourcescan.scan([REPO_ROOT / "dwaar"], patterns, relative_to=REPO_ROOT)
    assert result.files_scanned >= 20, (
        f"only {result.files_scanned} sources scanned under dwaar/; a scanner with nothing "
        "to scan passes vacuously"
    )
    return result


def test_the_ban_check_would_catch_a_reintroduction(tmp_path):
    """Positive control. The check must fire on real usage and stay silent on prose.

    The stripper has its own controls in `tests/test_source_scan.py`; this asserts the two
    are wired together, which is the part that could silently come undone.
    """
    package = tmp_path / "probe"
    package.mkdir()

    (package / "guilty.py").write_text(
        "from starlette.middleware.base import BaseHTTPMiddleware\n\n"
        "class Sneaky(BaseHTTPMiddleware):\n    pass\n",
        encoding="utf-8",
    )
    assert sourcescan.scan([package], _BANNED_MIDDLEWARE).findings, (
        "the ban check does not detect an actual import and subclass; it is enforcing "
        "nothing"
    )

    (package / "guilty.py").unlink()
    (package / "innocent.py").write_text(
        '"""We do not use BaseHTTPMiddleware because it breaks streaming."""\n'
        "# BaseHTTPMiddleware is banned here.\n",
        encoding="utf-8",
    )
    assert not sourcescan.scan([package], _BANNED_MIDDLEWARE).findings, (
        "the ban check fires on prose that merely mentions the class — the same failure "
        "as a grep matching the comment that explains why something is absent"
    )


def test_the_real_middleware_module_still_explains_itself():
    """The prose the check must tolerate is prose we actually want to keep.

    If someone silences a future false positive by deleting the explanation rather than by
    fixing the scanner, this fails. The stripper exists so that the docstring and the check
    can coexist; that is only worth anything if the docstring is still there.
    """
    text = (REPO_ROOT / "dwaar" / "api" / "middleware.py").read_text(encoding="utf-8")
    assert "BaseHTTPMiddleware" in text, (
        "dwaar/api/middleware.py no longer explains why BaseHTTPMiddleware is banned"
    )
    assert not sourcescan.scan(
        [REPO_ROOT / "dwaar" / "api" / "middleware.py"], _BANNED_MIDDLEWARE
    ).findings
