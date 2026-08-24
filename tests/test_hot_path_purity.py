"""Rule 1, structurally: no LLM is REACHABLE from the authorize path.

The strategy package enforces rule 1 with a runtime monkeypatch — patch the client to
raise, send 1,000 requests, assert nothing exploded. That test is real and it is kept
(`tests/test_no_llm_in_hot_path.py`). But it proves a narrower claim than it appears to:
*the LLM was not called on the requests we sent.*

This proves the stronger one: **it cannot be called**, because nothing on the request path
can even see it. It walks the transitive import closure of every request-path module and
fails if any chain arrives at an LLM client or a provider SDK.

Neither test subsumes the other:

- Static closure catches reachability, including a path no sampled request happened to take.
- It cannot see ``httpx.post("https://generativelanguage.googleapis.com/...")`` — no import
  involved, still an LLM in the hot path. The runtime test catches that, and so does the
  source scan at the bottom of this file.

Two independent enforcements of one claim, and the README says so.
"""

from __future__ import annotations

import pytest

from tests._support import sourcescan
from tests._support.importgraph import REPO_ROOT, build_graph, find_path_to
from tests._support.llm_blocklist import BLOCKED_MODULES, PROVIDER_HOSTS

# Modules that serve requests. This list grows with the pipeline — that is the point.
HOT_PATH_MODULES = [
    "dwaar.api.app",
    "dwaar.api.middleware",
    "dwaar.api.routes.health",
    "dwaar.api.routes.authorize",
    "dwaar.authorize.pipeline",
    "dwaar.authorize.stages.signature",
    "dwaar.authorize.stages.mandate",
    "dwaar.authorize.stages.authority",
    "dwaar.authorize.stages.features",
    "dwaar.authorize.stages.risk",
    "dwaar.authorize.stages.policy",
    "dwaar.authorize.stages.ledger",
    "dwaar.authorize.stages.decision",
    "dwaar.authorize.stages.record",
    "dwaar.db.repositories.budget_ledger",
    "dwaar.db.repositories.decision_records",
    "dwaar.db.repositories.mandates",
    "dwaar.db.repositories.policies",
]


@pytest.fixture(scope="module")
def graph():
    return build_graph("dwaar")


@pytest.mark.parametrize("module", HOT_PATH_MODULES)
def test_hot_path_module_exists(graph, module):
    """A typo here would silently check nothing."""
    assert module in graph.modules, (
        f"{module} is listed as a hot-path module but does not exist. Either it moved and "
        "this list is stale, or the name is wrong — both make the purity check vacuous "
        "for that entry."
    )


@pytest.mark.parametrize("module", HOT_PATH_MODULES)
@pytest.mark.parametrize("forbidden", BLOCKED_MODULES)
def test_no_llm_reachable_from_hot_path(graph, module, forbidden):
    path = find_path_to(graph, module, forbidden)
    if path is None:
        return
    chain = "\n      ".join(str(edge) for edge in path)
    pytest.fail(
        f"LLM reachable from the request path: {module} -> {forbidden}\n"
        f"      {chain}\n\n"
        "Rule 1: no LLM call may occur in the /v1/authorize request path, ever. "
        "500-2000ms against a 25ms budget is the small problem. The real one is that it "
        "makes the decision-maker the injection target. If an explanation is needed, "
        "queue it."
    )


def test_nothing_under_the_api_package_can_reach_an_llm(graph):
    """Broader than the per-module list, so a route added later is covered automatically."""
    api_modules = [m for m in graph.modules if m.startswith("dwaar.api")]
    assert api_modules

    violations = []
    for module in sorted(api_modules):
        for forbidden in BLOCKED_MODULES:
            path = find_path_to(graph, module, forbidden)
            if path is not None:
                violations.append(f"  {module} -> {forbidden}: " + " | ".join(map(str, path)))
    assert not violations, "no module under dwaar.api may reach an LLM:\n" + "\n".join(violations)


def test_nothing_under_the_authorize_package_can_reach_an_llm(graph):
    authorize_modules = [m for m in graph.modules if m.startswith("dwaar.authorize")]
    assert authorize_modules

    violations = []
    for module in sorted(authorize_modules):
        for forbidden in BLOCKED_MODULES:
            path = find_path_to(graph, module, forbidden)
            if path is not None:
                violations.append(f"  {module} -> {forbidden}: " + " | ".join(map(str, path)))
    assert not violations, "no module under dwaar.authorize may reach an LLM:\n" + "\n".join(
        violations
    )


def test_the_walker_can_actually_find_a_violation(tmp_path):
    """Positive control, against a package built to be dirty.

    A walker that silently found nothing would make every assertion above vacuously true —
    the characteristic failure of a test whose job is to never fail. Asserting against the
    real codebase cannot detect that, because the real codebase is supposed to be clean.

    So this builds a two-hop chain that MUST be flagged. If the walker cannot see a
    violation it was handed deliberately, none of its silence above means anything.
    """
    from tests._support.importgraph import build_synthetic_package

    dirty = build_synthetic_package(
        tmp_path,
        "purity_probe",
        {
            "route": "from purity_probe import helper",
            "helper": "import google.generativeai",
        },
    )
    found = find_path_to(dirty, "purity_probe.route", "google.generativeai")
    assert found is not None, (
        "the import walker failed to find a violation two hops away; every purity "
        "assertion in this file is therefore meaningless"
    )
    assert len(found) == 2, "the walker must report the full chain, not just the endpoint"


def test_the_walker_matches_submodules_not_just_exact_names(tmp_path):
    """`import google.generativeai.types` must be caught by a `google.generativeai` rule.

    Exact-element membership is the subtle way this check goes quiet: `"zoo" in imports`
    is False for `import zoo.agents.compromised`.
    """
    from tests._support.importgraph import build_synthetic_package

    dirty = build_synthetic_package(
        tmp_path, "submodule_probe", {"route": "import google.generativeai.types"}
    )
    assert find_path_to(dirty, "submodule_probe.route", "google.generativeai") is not None


def test_the_walker_does_not_match_a_mere_prefix(tmp_path):
    """`openai_helper` is not `openai`. A false positive here would be a broken build with
    no defect behind it, which is how a good check gets deleted."""
    from tests._support.importgraph import build_synthetic_package

    clean = build_synthetic_package(
        tmp_path, "prefix_probe", {"route": "import openai_helper"}
    )
    assert find_path_to(clean, "prefix_probe.route", "openai") is None


def test_no_provider_host_appears_in_request_path_source():
    """What the import walker structurally cannot see.

    A raw `httpx.post("https://generativelanguage.googleapis.com/...")` involves no import
    and produces no edge in the graph. This is a source scan, which is blunt and cheap, and
    it closes the one gap the static analysis has.

    It goes through the shared stripper for the same reason the other three do: this file
    would otherwise be unable to name the host in the docstring that explains what it is
    looking for. It was one docstring away from being the fourth instance of that bug.
    """
    result = sourcescan.scan(
        [REPO_ROOT / "dwaar" / "api", REPO_ROOT / "dwaar" / "authorize"],
        PROVIDER_HOSTS,
        relative_to=REPO_ROOT,
    )
    assert result.files_scanned >= 8, (
        f"only {result.files_scanned} request-path sources scanned; a scanner with nothing "
        "to scan passes vacuously"
    )
    assert not result.findings, (
        "a provider endpoint appears in request-path source; the import walker cannot see "
        "a raw HTTP call:\n" + sourcescan.render(result.findings)
    )


def test_the_provider_host_scan_would_catch_a_raw_call(tmp_path):
    """Positive control. Every host in the list must be matchable.

    A host added to the list but not actually detectable would look enforced and not be —
    the same shape as F-014.
    """
    probe = tmp_path / "probe"
    probe.mkdir()
    for index, host in enumerate(PROVIDER_HOSTS):
        (probe / f"raw{index}.py").write_text(
            f'import httpx\nhttpx.post("https://{host}/v1/generate")\n', encoding="utf-8"
        )
    result = sourcescan.scan([probe], PROVIDER_HOSTS)
    assert result.files_scanned == len(PROVIDER_HOSTS)
    assert len({f.path for f in result.findings}) == len(PROVIDER_HOSTS), (
        "not every provider host in the blocklist is detectable by the source scan; the "
        "undetectable ones are decorative"
    )


def test_blocklist_covers_the_chosen_provider():
    """Gemini is the provider. If it ever left the blocklist the test would keep passing
    while enforcing nothing about the one SDK we actually have a reason to install."""
    assert "google.generativeai" in BLOCKED_MODULES
    assert "google.genai" in BLOCKED_MODULES
    # NVIDIA's endpoint speaks the OpenAI protocol through the OpenAI SDK, so importing
    # `openai` is a live route to a model even though we do not use OpenAI.
    assert "openai" in BLOCKED_MODULES


def test_runtime_counterpart_is_documented():
    """The static check must not quietly become the only enforcement."""
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    assert "test_no_llm_in_hot_path" in readme, (
        "README must document the runtime counterpart. Static reachability cannot see a "
        "raw httpx call to a provider URL; the two tests make different claims and the "
        "README promises both."
    )
