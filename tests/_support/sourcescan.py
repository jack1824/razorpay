"""Grep source without matching the prose that explains why the thing is absent.

Four checks in this suite scan source text for something that must not appear:

    pgcrypto                 migrations/*.sql        `CREATE EXTENSION pgcrypto`
    BaseHTTPMiddleware       dwaar/**/*.py           import or use of the class
    provider hostnames       dwaar/api, authorize    a raw HTTP call to a model
    ground_truth / archetype dwaar/**/*.py           the eval label reaching the gateway

Three of the four have already fired on their own documentation. The pgcrypto check matched
migration 0001's comment explaining that pgcrypto is *not* used. The BaseHTTPMiddleware check
matched the docstring in `dwaar/api/middleware.py` explaining that the class is banned. Each
was fixed locally — one by stripping SQL comments, one by matching import and subclass
syntax — and the third instance was still waiting for someone to write a docstring.

**The failure is structural, not incidental.** A control that forbids a term attracts prose
containing that term, because the absence has to be justified somewhere, and the natural
place to justify it is the file being scanned. Any check of this shape will eventually match
its own explanation. So the fix belongs at the layer where a fourth instance is impossible:
one stripper, four callers.

── What is stripped, and what deliberately is not ──────────────────────────────────────

Comments and docstrings are prose and are removed. **Other string literals are kept**, which
is the whole reason this is not a blanket "remove all strings":

    open("ground_truth.json")          <- a leak, and it lives in a string literal

Removing every string would silence the one check that most needs to see inside one. The
distinction is meaningful rather than convenient: a docstring or a comment cannot execute,
and a string literal that is not a bare expression statement can.

Line numbers survive stripping — blanked spans are replaced with spaces, and blanked lines
become empty — so a finding still reports the line a reader can open.
"""

from __future__ import annotations

import ast
import contextlib
import io
import re
import tokenize
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

__all__ = [
    "Finding",
    "ScanResult",
    "compile_patterns",
    "scan",
    "strip_prose",
    "strip_python",
    "strip_sql",
]


# ── stripping ───────────────────────────────────────────────────────────────────────

Span = tuple[int, int, int, int]  # (start_line, start_col, end_line, end_col), 1-indexed


def _byte_col_to_char_col(line: str, byte_col: int) -> int:
    """`ast` reports column offsets in UTF-8 BYTES; `str` slicing wants characters.

    On an ASCII line the two are identical, which is exactly why this is easy to omit and
    then be wrong about for the one file that contains a rupee sign in a docstring.
    """
    return len(line.encode("utf-8")[:byte_col].decode("utf-8", errors="ignore"))


def _blank(lines: Sequence[str], spans: Iterable[Span]) -> str:
    out = list(lines)
    for start_line, start_col, end_line, end_col in spans:
        if not (1 <= start_line <= len(out)) or not (1 <= end_line <= len(out)):
            continue
        if start_line == end_line:
            line = out[start_line - 1]
            stop = min(end_col, len(line))
            if stop > start_col:
                out[start_line - 1] = line[:start_col] + " " * (stop - start_col) + line[stop:]
            continue
        out[start_line - 1] = out[start_line - 1][:start_col]
        for index in range(start_line, end_line - 1):
            out[index] = ""
        tail = out[end_line - 1]
        stop = min(end_col, len(tail))
        out[end_line - 1] = " " * stop + tail[stop:]
    return "\n".join(out)


def strip_python(text: str) -> str:
    """Blank comments and bare string-expression statements. Line numbers preserved.

    A bare string expression is documentation by convention and has no effect at runtime —
    module, class and function docstrings, and the free-standing string used to annotate the
    constant above it.
    Every other string literal is left alone, because a forbidden token inside one is a
    finding rather than an explanation.

    Unparseable source is returned unchanged rather than skipped: a syntax error must not
    quietly exempt a file from a security check.
    """
    lines = text.splitlines()
    spans: list[Span] = []

    try:
        for token in tokenize.generate_tokens(io.StringIO(text).readline):
            if token.type == tokenize.COMMENT:
                spans.append((token.start[0], token.start[1], token.end[0], token.end[1]))
    except (tokenize.TokenError, IndentationError, SyntaxError):
        pass

    try:
        tree = ast.parse(text)
    except SyntaxError:
        return _blank(lines, spans)

    for node in ast.walk(tree):
        if not isinstance(node, ast.Expr):
            continue
        value = node.value
        if not (isinstance(value, ast.Constant) and isinstance(value.value, str)):
            continue
        if value.end_lineno is None or value.end_col_offset is None:
            continue
        start_line, end_line = value.lineno, value.end_lineno
        if not (1 <= start_line <= len(lines) and 1 <= end_line <= len(lines)):
            continue
        spans.append(
            (
                start_line,
                _byte_col_to_char_col(lines[start_line - 1], value.col_offset),
                end_line,
                _byte_col_to_char_col(lines[end_line - 1], value.end_col_offset),
            )
        )

    return _blank(lines, spans)


_SQL_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)


def strip_sql(text: str) -> str:
    """Blank `--` line comments and `/* */` blocks, preserving line count.

    Naive about `--` inside a string literal, which no migration in this repo contains. If
    one ever does, the symptom is an over-strip — a check going quiet — so
    `tests/test_source_scan.py` asserts the stripper still finds real SQL after stripping.
    """
    text = _SQL_BLOCK_COMMENT.sub(lambda m: re.sub(r"[^\n]", " ", m.group(0)), text)
    return "\n".join(re.sub(r"--.*$", "", line) for line in text.splitlines())


_STRIPPERS = {".py": strip_python, ".sql": strip_sql}


def strip_prose(text: str, suffix: str) -> str:
    """Dispatch on file suffix. An unknown suffix is returned unchanged, not silently
    stripped by the wrong grammar."""
    return _STRIPPERS.get(suffix, lambda t: t)(text)


# ── scanning ────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Finding:
    path: Path
    lineno: int
    line: str
    pattern: str

    def __str__(self) -> str:
        return f"  {self.path}:{self.lineno}: {self.line.strip()}   [{self.pattern}]"


@dataclass(frozen=True)
class ScanResult:
    findings: list[Finding]
    files_scanned: int
    """Exposed so callers can assert it is non-zero.

    A scanner with nothing to scan reports no violations, which is indistinguishable from a
    clean tree. That is F-014's failure mode and it is the caller's job to reject it, so the
    count is returned rather than being checked here where a caller could forget it exists.
    """

    def __bool__(self) -> bool:
        return bool(self.findings)


def compile_patterns(patterns: Iterable[str | re.Pattern[str]]) -> list[re.Pattern[str]]:
    """A plain string is a LITERAL substring, not a regex.

    `api.openai.com` as a regex would match `apixopenaixcom`. Escaping at the boundary means
    a caller passing a hostname list gets what it obviously meant.
    """
    return [p if isinstance(p, re.Pattern) else re.compile(re.escape(p)) for p in patterns]


def scan(
    roots: Iterable[Path],
    patterns: Iterable[str | re.Pattern[str]],
    *,
    suffixes: Sequence[str] = (".py",),
    relative_to: Path | None = None,
) -> ScanResult:
    """Scan every file under `roots` for `patterns`, ignoring comments and docstrings."""
    compiled = compile_patterns(patterns)
    findings: list[Finding] = []
    scanned = 0

    for root in roots:
        paths = [root] if root.is_file() else sorted(root.rglob("*"))
        for path in paths:
            if path.suffix not in suffixes or not path.is_file():
                continue
            scanned += 1
            source = strip_prose(path.read_text(encoding="utf-8"), path.suffix)
            lines = source.splitlines()
            label = path
            if relative_to is not None:
                with contextlib.suppress(ValueError):
                    label = path.relative_to(relative_to)
            # Matched against the WHOLE text rather than line by line, so a pattern may
            # legitimately span lines (`CREATE\s+EXTENSION\s+pgcrypto` wrapped by a
            # formatter) and so `re.M` anchors mean what their author intended.
            for pattern in compiled:
                for match in pattern.finditer(source):
                    lineno = source[: match.start()].count("\n") + 1
                    line = lines[lineno - 1] if lineno <= len(lines) else match.group(0)
                    findings.append(Finding(label, lineno, line, pattern.pattern))

    return ScanResult(findings, scanned)


def render(findings: Iterable[Finding]) -> str:
    return "\n".join(str(finding) for finding in findings)
