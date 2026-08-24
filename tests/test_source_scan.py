"""Positive control for the shared source scanner.

Four checks in this suite forbid a term from appearing in source. All four now route through
`tests/_support/sourcescan.py`, so this file is the control for all four at once: if the
stripper over-strips, every one of them goes quiet simultaneously, and nothing else in the
suite would notice.

Two failure directions, and both are tested here, because only testing one is how a check
gets weakened into uselessness:

    over-strip   a real violation is removed along with the prose  -> silent false negative
    under-strip  a docstring is read as code                        -> the original bug

The scanner is also asserted to preserve line numbers. A finding that reports the wrong line
is a finding nobody can act on, and the temptation is then to delete the check.
"""

from __future__ import annotations

import re

from tests._support.sourcescan import (
    compile_patterns,
    scan,
    strip_python,
    strip_sql,
)

FORBIDDEN = re.compile(r"\bpgcrypto\b")


# ── Python: what must be stripped ───────────────────────────────────────────────────


def test_module_docstring_is_stripped():
    source = '"""We never use pgcrypto; gen_random_uuid is core."""\nx = 1\n'
    assert "pgcrypto" not in strip_python(source)


def test_function_and_class_docstrings_are_stripped():
    source = (
        "class C:\n"
        '    """pgcrypto is not installed."""\n'
        "    def m(self):\n"
        '        """Nor here: pgcrypto."""\n'
        "        return 1\n"
    )
    assert "pgcrypto" not in strip_python(source)


def test_line_comments_are_stripped():
    assert "pgcrypto" not in strip_python("x = 1  # pgcrypto is deliberately absent\n")


def test_a_bare_string_expression_used_as_a_comment_is_stripped():
    """The `#:`-style attribute docstring, which is prose in every sense that matters."""
    source = "X = 1\n'''X exists because pgcrypto does not.'''\n"
    assert "pgcrypto" not in strip_python(source)


# ── Python: what must SURVIVE stripping ─────────────────────────────────────────────


def test_a_string_literal_that_is_not_a_docstring_survives():
    """The single most important assertion in this file.

    `open("ground_truth.json")` is a real leak and it lives inside a string. A stripper that
    removed every string literal would silence the label-isolation check completely while
    looking more thorough.
    """
    source = 'path = open("ground_truth.json")\n'
    assert "ground_truth.json" in strip_python(source)


def test_an_import_survives():
    source = "from starlette.middleware.base import BaseHTTPMiddleware\n"
    assert "BaseHTTPMiddleware" in strip_python(source)


def test_a_docstring_does_not_take_the_code_after_it():
    source = 'def f():\n    """doc"""\n    return "pgcrypto"\n'
    stripped = strip_python(source)
    assert "doc" not in stripped
    assert "pgcrypto" in stripped


def test_unparseable_source_is_not_silently_exempted():
    """A syntax error must not turn into a free pass on a security check."""
    source = "def broken(  \nreturn 'pgcrypto'\n"
    assert "pgcrypto" in strip_python(source)


# ── Line numbers ────────────────────────────────────────────────────────────────────


def test_line_numbers_survive_a_multiline_docstring():
    source = '"""line one\nline two\nline three\n"""\nimport pgcrypto_shim  # noqa\n'
    stripped = strip_python(source)
    assert stripped.splitlines()[4].startswith("import pgcrypto_shim")


def test_column_offsets_survive_so_two_spans_on_one_line_both_apply():
    source = 'x = "kept"  # pgcrypto\ny = 2\n'
    stripped = strip_python(source)
    assert '"kept"' in stripped
    assert "pgcrypto" not in stripped
    assert stripped.splitlines()[1] == "y = 2"


def test_non_ascii_in_a_docstring_does_not_shift_the_strip():
    """`ast` reports columns in UTF-8 bytes. A rupee sign in a docstring is enough to make a
    character-offset assumption wrong, and the symptom is a partially-stripped line."""
    source = 'def f():\n    """₹50,000 and pgcrypto."""\n    return "pgcrypto"\n'
    stripped = strip_python(source)
    assert stripped.count("pgcrypto") == 1, stripped


# ── SQL ─────────────────────────────────────────────────────────────────────────────


def test_sql_line_comments_are_stripped_and_statements_are_not():
    sql = "-- pgcrypto is not needed\nCREATE TABLE t (id uuid DEFAULT gen_random_uuid());\n"
    stripped = strip_sql(sql)
    assert "pgcrypto" not in stripped
    assert "CREATE TABLE t" in stripped


def test_sql_block_comments_are_stripped_without_losing_line_count():
    sql = "/* pgcrypto\n   is absent */\nSELECT 1;\n"
    stripped = strip_sql(sql)
    assert "pgcrypto" not in stripped
    assert stripped.splitlines()[2] == "SELECT 1;"


# ── The scanner ─────────────────────────────────────────────────────────────────────


def test_scan_finds_a_violation_and_ignores_the_prose_beside_it(tmp_path):
    (tmp_path / "guilty.py").write_text(
        '"""This module must never touch pgcrypto."""\n'
        "# pgcrypto stays out of here.\n"
        'QUERY = "CREATE EXTENSION pgcrypto"\n',
        encoding="utf-8",
    )
    result = scan([tmp_path], [FORBIDDEN], relative_to=tmp_path)
    assert result.files_scanned == 1
    assert len(result.findings) == 1, result.findings
    assert result.findings[0].lineno == 3


def test_scan_reports_zero_files_rather_than_a_clean_bill(tmp_path):
    """The vacuous pass, made visible.

    An empty tree yields no findings, which reads exactly like a clean tree. `files_scanned`
    is what lets a caller tell the two apart, and every caller asserts on it.
    """
    result = scan([tmp_path], [FORBIDDEN])
    assert not result.findings
    assert result.files_scanned == 0


def test_a_plain_string_pattern_is_a_literal_not_a_regex():
    """`api.openai.com` as a regex matches `apixopenaixcom`. A false positive with no defect
    behind it is how a good check gets deleted."""
    (compiled,) = compile_patterns(["api.openai.com"])
    assert compiled.search("api.openai.com")
    assert not compiled.search("apixopenaixcom")


def test_scan_only_reads_the_suffixes_it_was_given(tmp_path):
    (tmp_path / "a.py").write_text("X = 'pgcrypto'\n", encoding="utf-8")
    (tmp_path / "b.txt").write_text("pgcrypto\n", encoding="utf-8")
    result = scan([tmp_path], [FORBIDDEN], suffixes=(".py",))
    assert result.files_scanned == 1
    assert len(result.findings) == 1


# ── the four callers ────────────────────────────────────────────────────────────────

#: Every check in this suite that scans source text for a forbidden term. All four route
#: through the shared stripper. Listed here so that a fifth check written the old way is a
#: deliberate omission from this tuple rather than an oversight nobody sees.
SCANNING_CHECKS = (
    "tests/db/test_migrations.py",
    "tests/test_absence_controls.py",
    "tests/test_ground_truth_isolation.py",
    "tests/test_hot_path_purity.py",
)


def test_every_source_scanning_check_uses_the_shared_stripper():
    """The refactor's whole value is that there is exactly one stripper.

    Three of these fixed the same bug independently and the fourth had not hit it yet. If a
    local re-implementation reappears, the class of defect reappears with it — this is the
    assertion that says so out loud.
    """
    from tests._support.importgraph import REPO_ROOT

    for relative in SCANNING_CHECKS:
        text = (REPO_ROOT / relative).read_text(encoding="utf-8")
        assert "sourcescan" in text, (
            f"{relative} scans source without the shared stripper; it will eventually match "
            "the prose that explains what it forbids"
        )
