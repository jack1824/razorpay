"""Rule 3: `zoo/` must never be importable from `dwaar/`.

This is structural, not stylistic. `zoo/` contains adversarial agents — a card tester, an
injector, a compromised agent. If the gateway can import them it can also import whatever
they know, and the separation between the thing being attacked and the thing doing the
attacking stops being a property of the system and becomes a property of everyone's
self-discipline.

The reverse direction is fine and intended: `zoo/` imports `dwaar.crypto` so the agents
sign the way the gateway verifies.

The related concern — that shared signing code lets a wrong implementation agree with
itself and pass — is handled by known-answer vectors against RFC 8785 and RFC 9421, not by
forbidding the import.
"""

from __future__ import annotations

import pytest

from tests._support.importgraph import REPO_ROOT, build_graph, find_path_to

FORBIDDEN = "zoo"


@pytest.fixture(scope="module")
def graph():
    return build_graph("dwaar")


def test_graph_is_not_empty(graph):
    """Guard against the test passing because it found nothing to check.

    A walker that silently discovers zero modules would make every assertion below
    vacuously true, which is the failure mode that matters for a test whose job is to
    never fail.
    """
    assert len(graph.modules) >= 10, (
        f"expected the dwaar package to have modules to analyse, found {len(graph.modules)}"
    )
    assert "dwaar.api.app" in graph.modules
    assert "dwaar.db.repositories.budget_ledger" in graph.modules


def test_dwaar_never_imports_zoo(graph):
    """No module under dwaar.* may reach zoo.* by any chain of imports."""
    violations: list[str] = []
    for module in sorted(graph.modules):
        path = find_path_to(graph, module, FORBIDDEN)
        if path is not None:
            chain = "\n      ".join(str(edge) for edge in path)
            violations.append(f"  {module} reaches {FORBIDDEN}:\n      {chain}")

    assert not violations, (
        "dwaar must never import zoo — offence and defence are separated structurally, "
        "not by convention:\n" + "\n".join(violations)
    )


def test_zoo_is_not_inside_the_dwaar_package():
    """`zoo/` is a top-level sibling. Nesting it would make the rule unenforceable."""
    assert not (REPO_ROOT / "dwaar" / "zoo").exists(), (
        "zoo/ must be a sibling of dwaar/, not nested inside it"
    )
    assert (REPO_ROOT / "zoo").is_dir(), "zoo/ must exist as a top-level directory"


def test_zoo_readme_states_localhost_only():
    """Scope control: `zoo/` targets localhost only, stated in line 1.

    An offence-capable general-purpose tool is disqualifying. The constraint is asserted
    here so that the statement cannot quietly disappear from the README.
    """
    readme = REPO_ROOT / "zoo" / "README.md"
    assert readme.is_file(), "zoo/README.md must exist"
    text = readme.read_text(encoding="utf-8").lower()
    assert "localhost" in text, "zoo/README.md must state that it targets localhost only"


def test_the_walker_can_actually_find_a_zoo_import(tmp_path):
    """Positive control.

    This test's job is to never fail, which is exactly the kind of test that can quietly
    stop enforcing anything. Asserting against `dwaar/` cannot detect that, because
    `dwaar/` is supposed to be clean. A package built to be dirty can.

    It found a real defect the first time it ran: the walker recorded `from X import Y` as
    an edge to `X` only, so submodule imports were invisible to traversal. See F-014.
    """
    from tests._support.importgraph import build_synthetic_package

    dirty = build_synthetic_package(
        tmp_path,
        "isolation_probe",
        {
            "gateway": "from isolation_probe import helper",
            "helper": "import zoo.agents.compromised",
        },
    )
    found = find_path_to(dirty, "isolation_probe.gateway", FORBIDDEN)
    assert found is not None, (
        "the walker failed to find a zoo import two hops away; rule 3's only guard is "
        "therefore enforcing nothing"
    )


def test_exact_membership_would_not_have_caught_a_submodule_import(tmp_path):
    """The specific weakness the strategy package's version of this test had.

    `assert "zoo" not in transitive_imports(mod)` is exact-element membership, so
    `import zoo.agents.compromised` passes it clean. This asserts our matcher is a prefix
    match, not an equality check.
    """
    from tests._support.importgraph import build_synthetic_package, transitive_imports

    dirty = build_synthetic_package(
        tmp_path, "membership_probe", {"gateway": "import zoo.agents.compromised"}
    )
    imports = transitive_imports(dirty, "membership_probe.gateway")

    # The naive check passes — which is the point.
    assert "zoo" not in imports
    # Ours does not.
    assert find_path_to(dirty, "membership_probe.gateway", FORBIDDEN) is not None
