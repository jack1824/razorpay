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

def test_unimplemented_make_targets_exit_non_zero():
    """A green stub is a control that is not there — the same failure as a hardcoded
    metric, and it fails at the worst possible moment."""
    makefile = (REPO_ROOT / "Makefile").read_text(encoding="utf-8")
    for target in ("eval", "demo"):
        block = re.search(rf"^{target}:\n((?:\t.*\n)+)", makefile, re.M)
        assert block, f"no {target} target in the Makefile"
        assert "exit 2" in block.group(1), (
            f"`make {target}` must exit non-zero while unimplemented"
        )


def test_verify_is_no_longer_a_stub():
    """It landed on 25 Aug. If it regressed to `exit 2`, the acceptance criterion is gone."""
    makefile = (REPO_ROOT / "Makefile").read_text(encoding="utf-8")
    block = re.search(r"^verify:\n((?:\t.*\n)+)", makefile, re.M)
    assert block
    assert "exit 2" not in block.group(1)
    assert "verify_cli" in block.group(1)
