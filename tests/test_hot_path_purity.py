"""Rule 1, structurally: no LLM is *reachable* from the authorize path.

The strategy package enforces rule 1 with a runtime monkeypatch — patch the LLM client to
raise, send 1,000 authorize requests, assert nothing exploded. That test is real and it
stays (it lands with the authorize path on day 10). But it proves a narrower claim than it
appears to: *the LLM was not called on the requests we sent*.

This test proves the stronger one: **the LLM is not reachable at all.** It walks the
transitive import closure of every request-path module and fails if any chain arrives at an
LLM client or a provider SDK.

Neither test subsumes the other:

- Static closure catches reachability, including a path no sampled request happened to take.
- It cannot see ``httpx.post("https://api.anthropic.com/v1/messages")`` — no import, still
  an LLM in the hot path. The runtime test catches that.

Two independent enforcements of one claim, and the README says so.
"""

from __future__ import annotations

import pytest

from tests._support.importgraph import REPO_ROOT, build_graph, find_path_to

# Modules that serve requests. As the pipeline lands (day 3 onward) its stages are added
# here — that is the point: the list grows with the hot path and the check grows with it.
HOT_PATH_MODULES = [
    "dwaar.api.app",
    "dwaar.api.middleware",
    "dwaar.api.routes.health",
    "dwaar.db.repositories.budget_ledger",
    "dwaar.db.repositories.decision_records",
    "dwaar.db.repositories.mandates",
    "dwaar.db.repositories.policies",
]

# Anything whose presence in the closure means an LLM became reachable.
FORBIDDEN_MODULES = [
    "dwaar.llm",       # our own client wrapper — off-path by construction
    "dwaar.explain",   # async explainer, queue-driven, never synchronous
    "anthropic",
    "openai",
    "langchain",
    "langchain_core",
    "llama_index",
    "cohere",
    "google.generativeai",
    "mistralai",
    "ollama",
    "transformers",
]


@pytest.fixture(scope="module")
def graph():
    return build_graph("dwaar")


@pytest.mark.parametrize("module", HOT_PATH_MODULES)
def test_hot_path_module_exists(graph, module):
    """A typo in HOT_PATH_MODULES would silently check nothing."""
    assert module in graph.modules, (
        f"{module} is listed as a hot-path module but does not exist. Either the module "
        "moved and this list is stale, or the name is wrong — both make the purity check "
        "vacuous for that entry."
    )


@pytest.mark.parametrize("module", HOT_PATH_MODULES)
@pytest.mark.parametrize("forbidden", FORBIDDEN_MODULES)
def test_no_llm_reachable_from_hot_path(graph, module, forbidden):
    path = find_path_to(graph, module, forbidden)
    if path is None:
        return
    chain = "\n      ".join(str(edge) for edge in path)
    pytest.fail(
        f"LLM reachable from the request path: {module} -> {forbidden}\n"
        f"      {chain}\n\n"
        "Rule 1: no LLM call may occur in the /v1/authorize request path, ever. "
        "500-2000ms against a 25ms budget, non-deterministic on money, and it makes the "
        "decision-maker the injection target. If an explanation is needed, queue it."
    )


def test_llm_package_is_not_imported_by_the_api_package(graph):
    """Belt and braces: nothing under dwaar.api may reach an LLM, hot path or not.

    Stronger than the per-module check above, because it covers routes added later that
    nobody remembered to list in HOT_PATH_MODULES.
    """
    api_modules = [m for m in graph.modules if m.startswith("dwaar.api")]
    assert api_modules, "expected modules under dwaar.api"

    violations: list[str] = []
    for module in sorted(api_modules):
        for forbidden in FORBIDDEN_MODULES:
            path = find_path_to(graph, module, forbidden)
            if path is not None:
                chain = " | ".join(str(edge) for edge in path)
                violations.append(f"  {module} -> {forbidden}: {chain}")

    assert not violations, "no module under dwaar.api may reach an LLM:\n" + "\n".join(
        violations
    )


def test_runtime_counterpart_is_documented():
    """The runtime monkeypatch test is scheduled, not forgotten.

    This test exists so that the static check cannot quietly become the *only* enforcement.
    It asserts the README still claims both, which is the thing a reader will rely on.
    """
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    assert "test_no_llm_in_hot_path" in readme, (
        "README must document the runtime counterpart to this test. Static reachability "
        "cannot see a raw httpx call to a provider URL; the two tests make different "
        "claims and the README promises both."
    )
