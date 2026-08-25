"""A test may not write a signed table's columns directly.  F-018 / F-042, as a check.

── Three instances, one shortcut ───────────────────────────────────────────────────────

    F-018  a fixture wrote `canonical_json = '{"test":true}'` with a random hash
    …      a mandate column set by UPDATE after the row was signed
    F-042  `UPDATE mandates SET scopes = ...`, five tampered rows, suite green at 926

Every time, the shortcut was identical: **writing a column instead of re-signing the row.**
And every time it was taken for the same reason — the shared builder could not express what
the test needed, so the test reached past it. F-042's missing parameter was `scopes`, which
`make_mandate` now takes.

`make verify` was the only thing that caught the third one. That is worth stating plainly: a
926-test suite was green over five rows that a verifier called forged, because nothing in
the suite compares a column to the bytes signed over it and the fixtures were producing rows
no verifier would accept.

── Fixing the affordance rather than the instance ──────────────────────────────────────

Fixing each instance leaves the shortcut in place for the next author at 2am. So:

    1. `make_mandate` takes every signed term as a parameter, `scopes` included, and signs.
    2. `write_record` derives the ledger columns and asserts the money invariant before it
       inserts, so it cannot build a record the database would refuse.
    3. `tests/db/test_mcp_proxy.py`'s second mandate builder is gone — it was a copy of
       `make_mandate`'s signing logic that existed only because of (1)'s missing parameter.
    4. This file, which fails if a raw INSERT or UPDATE against a signed table appears
       outside the small set of files whose PURPOSE is tampering.

── The allowlist is the interesting part ───────────────────────────────────────────────

Four files must write these tables directly, and each is named with its reason rather than
being skipped by a pattern. A wildcard exemption ("anything under tests/db/") would have
covered `test_mcp_proxy.py`, which is where F-042 happened.
"""

from __future__ import annotations

import re
from pathlib import Path

from tests._support.sourcescan import render, scan

REPO = Path(__file__).resolve().parents[1]
TESTS = REPO / "tests"

#: The tables carrying a signed serialisation AND columns extracted from it — the registry
#: in `dwaar/crypto/integrity.py`, named here rather than imported so that adding a table to
#: the registry without adding it here is visible as an omission.
SIGNED_TABLES = ("decision_records", "mandates", "policies")

WRITE = re.compile(
    r"\b(INSERT\s+INTO|UPDATE)\s+(" + "|".join(SIGNED_TABLES) + r")\b",
    re.IGNORECASE,
)

#: Files permitted to write these tables directly, each with the reason it must.
#:
#: Named individually. A directory-wide exemption would have covered the file F-042 actually
#: happened in.
ALLOWED: dict[str, str] = {
    "db/test_verify_cli.py": (
        "the verifier's own tests. Tampering every signed column on every signed table IS "
        "the test; a fixture cannot express 'a row that disagrees with its signature' "
        "because no fixture is allowed to produce one."
    ),
    "db/test_append_only_grant.py": (
        "proves UPDATE and DELETE raise InsufficientPrivilege as dwaar_app and SUCCEED as "
        "superuser. The superuser half is demo beat 6's precondition — if the tamper cannot "
        "happen, the detection has nothing to detect."
    ),
    "db/test_authorize_pipeline.py": (
        "demo beat 6 as a CI gate: UPDATE decision_records SET amount_paise, then assert "
        "the verifier names the seq."
    ),
    "db/test_amount_invariant_db.py": (
        "re-inserts an existing record with fields changed, to reach the money invariant's "
        "trigger and nothing else — a fixture that signs would refuse to build the very rows "
        "this asserts the database refuses. Also asserts a superuser UPDATE still succeeds, "
        "which is demo beat 6's precondition."
    ),
    "db/test_explainer_isolation.py": (
        "proves dwaar_explainer cannot write anything that decides. The statements are the "
        "test: each must raise InsufficientPrivilege, so none of them ever runs."
    ),
    "db/test_policy_lifecycle.py": (
        "inserts an UNSIGNED policy (signature NULL) to prove a reserved word is refused at "
        "load. The integrity registry skips NULL-signature rows deliberately — such a row "
        "claims nothing, so there is nothing for it to contradict."
    ),
}


#: This file. Excluded from its own scan, and the reason is not laziness.
#:
#: The shared stripper removes comments and docstrings but deliberately KEEPS other string
#: literals, because `open("ground_truth.json")` is a leak that lives inside one. A control
#: like this one cannot avoid real string literals containing the forbidden text: the
#: allowlist reasons name the statements they permit, and the positive controls have to
#: plant one to prove the scanner can fail.
#:
#: This is the fourth time a check of this shape has matched its own definition, and it
#: arrived on the first run — which is the argument for the shared stripper rather than
#: against it. The stripper made the other four files safe; the fifth needs a named
#: exclusion, and a named exclusion is a decision someone can review.
SELF = "test_fixture_discipline.py"


def _relative(path: Path) -> str:
    return str(path).replace("\\", "/")


def _findings():
    result = scan([TESTS], [WRITE], suffixes=(".py",), relative_to=TESTS)
    assert result.files_scanned > 0, (
        "no test files were scanned. A scan with nothing to scan reports no violations, "
        "which is indistinguishable from a clean tree — F-014."
    )
    return [f for f in result.findings if _relative(f.path) != SELF]


def test_no_test_writes_a_signed_table_outside_the_allowlist():
    offenders = [f for f in _findings() if _relative(f.path) not in ALLOWED]
    assert not offenders, (
        "a test writes a signed table directly:\n" + render(offenders) + "\n\n"
        "Route it through the builder that signs — `make_mandate` for mandates, "
        "`write_record` for decision records. If the builder cannot express what the test "
        "needs, ADD THE PARAMETER; that missing parameter is what F-042 was. If the test's "
        "purpose genuinely is to tamper, add it to ALLOWED with the reason."
    )


def test_every_allowlisted_file_still_exists_and_still_tampers():
    """An allowlist entry for a file that no longer tampers is an exemption nobody needs,
    and it will silently cover the next thing written into that file."""
    tampering = {_relative(f.path) for f in _findings()}
    for name in ALLOWED:
        assert (TESTS / name).exists(), f"ALLOWED names {name}, which does not exist"
        assert name in tampering, (
            f"{name} is allowlisted but writes no signed table any more. Remove the entry — "
            "a stale exemption covers whatever is written there next."
        )


def test_positive_control_the_scanner_can_fail(tmp_path):
    planted = tmp_path / "shortcut.py"
    planted.write_text(
        'async def test_scoped(conn):\n'
        '    await conn.execute("UPDATE mandates SET scopes = %s", (["read"],))\n',
        encoding="utf-8",
    )
    assert scan([planted], [WRITE], suffixes=(".py",)).findings


def test_prose_about_the_shortcut_is_not_a_finding(tmp_path):
    """This file, `tests/db/test_mcp_proxy.py` and `dwaar/verify_cli.py` all describe the
    shortcut in prose in order to warn about it. Three earlier checks of this shape matched
    their own documentation; that is why this one routes through the shared stripper."""
    sample = tmp_path / "documented.py"
    sample.write_text(
        '"""An earlier version did UPDATE mandates SET scopes = ... and make verify caught it."""\n'
        "# Never INSERT INTO decision_records from a test; use write_record.\n"
        "def test_ok():\n"
        "    assert True\n",
        encoding="utf-8",
    )
    assert not scan([sample], [WRITE], suffixes=(".py",)).findings
