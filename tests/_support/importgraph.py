"""Static transitive-import analysis.

Used by the two structural tests. Deliberately **static**: it parses source with ``ast``
rather than importing modules and inspecting ``sys.modules``. Importing to find out what
imports would (a) execute module-level code, which is how you accidentally connect to a
database inside a unit test, and (b) miss anything behind a conditional the test run does
not take. Parsing sees every import statement whether or not it executes.

What it cannot see, stated plainly so nobody over-trusts it:

- ``importlib.import_module(name)`` where ``name`` is computed at runtime
- a raw ``httpx.post("https://api.anthropic.com/...")`` — no import involved

The second is exactly why the runtime monkeypatch test is kept alongside the static one.
Reachability and invocation are different claims and each test only makes one of them.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


@dataclass
class ImportEdge:
    """One import, with the file and line that made it — so failures name a location."""

    source_module: str
    target_module: str
    file: Path
    line: int

    def __str__(self) -> str:
        rel = self.file.relative_to(REPO_ROOT)
        return f"{rel}:{self.line}  {self.source_module} -> {self.target_module}"


@dataclass
class ImportGraph:
    edges: dict[str, list[ImportEdge]] = field(default_factory=dict)
    modules: dict[str, Path] = field(default_factory=dict)

    def direct(self, module: str) -> list[ImportEdge]:
        return self.edges.get(module, [])


def _module_name(path: Path, package_root: Path) -> str:
    rel = path.relative_to(package_root.parent).with_suffix("")
    parts = list(rel.parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _resolve_relative(module: str, node: ast.ImportFrom, is_package: bool) -> str:
    """Turn a relative ``from . import x`` into an absolute module name."""
    parts = module.split(".")
    # Inside a package's __init__, level 1 refers to the package itself; elsewhere it
    # refers to the containing package.
    base = parts if is_package else parts[:-1]
    up = node.level - 1
    if up > 0:
        base = base[:-up] if up <= len(base) else []
    return ".".join([*base, node.module]) if node.module else ".".join(base)


def build_graph(package: str, repo_root: Path = REPO_ROOT) -> ImportGraph:
    """Parse every module under ``package`` and record its import edges."""
    package_root = repo_root / package
    if not package_root.is_dir():
        raise FileNotFoundError(f"package directory not found: {package_root}")

    graph = ImportGraph()
    for path in sorted(package_root.rglob("*.py")):
        module = _module_name(path, package_root)
        graph.modules[module] = path
        is_package = path.name == "__init__.py"

        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        edges: list[ImportEdge] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    edges.append(ImportEdge(module, alias.name, path, node.lineno))
            elif isinstance(node, ast.ImportFrom):
                target = (
                    _resolve_relative(module, node, is_package)
                    if node.level
                    else (node.module or "")
                )
                if target:
                    edges.append(ImportEdge(module, target, path, node.lineno))
        graph.edges[module] = edges
    return graph


def _matches(target: str, forbidden: str) -> bool:
    """``dwaar.llm`` matches ``dwaar.llm`` and ``dwaar.llm.client``, not ``dwaar.llmx``."""
    return target == forbidden or target.startswith(forbidden + ".")


def find_path_to(
    graph: ImportGraph, start: str, forbidden: str, *, _seen: set[str] | None = None
) -> list[ImportEdge] | None:
    """Shortest import path from ``start`` to anything under ``forbidden``, or None.

    Returns the chain of edges so a failure can print the route rather than just the fact.
    """
    seen = _seen if _seen is not None else set()
    if start in seen:
        return None
    seen.add(start)

    for edge in graph.direct(start):
        if _matches(edge.target_module, forbidden):
            return [edge]
    for edge in graph.direct(start):
        if edge.target_module in graph.modules:
            deeper = find_path_to(graph, edge.target_module, forbidden, _seen=seen)
            if deeper is not None:
                return [edge, *deeper]
    return None


def transitive_imports(graph: ImportGraph, start: str) -> set[str]:
    """Every module reachable from ``start`` by following imports within the graph."""
    out: set[str] = set()
    stack = [start]
    while stack:
        current = stack.pop()
        for edge in graph.direct(current):
            if edge.target_module in out:
                continue
            out.add(edge.target_module)
            if edge.target_module in graph.modules:
                stack.append(edge.target_module)
    return out
