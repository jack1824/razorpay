"""No wall clock outside `dwaar/clock.py`.  F-040's general form, as a check.

── The finding this generalises ────────────────────────────────────────────────────────

The zoo's diurnal cycle was inverted for a full day: busiest at 08:00 at sixty requests a
minute — twice the degraded-velocity threshold — and quietest at 20:00. The tests read the
same wall clock the bug did, so they agreed with it through every working hour and
disagreed only at 03:45.

    A time-dependent test does not fail. It waits.

Injecting the hour fixed that instance. The general rule is broader: any test whose outcome
depends on ambient state — clock, timezone, locale, filesystem ordering, network
availability, an unseeded RNG — is a coin flip with a slow period, and the period is usually
longer than the project.

The clock is the ambient input this system depends on for *correctness* rather than for
convenience. Mandate expiry, RFC 9421 skew and key-rotation overlap are all decided by
comparing an instant against a stored one. So the clock is the input that gets a seam, and
this is the check that the seam is not bypassed.

── Why this is a source scan and not an import check ───────────────────────────────────

`tests/test_hot_path_purity.py` walks the import graph, which is the right tool for "is this
module reachable". It is the wrong tool here: `datetime` is legitimately imported almost
everywhere for type annotations and arithmetic. The thing being forbidden is a *call*, and
the call sites are what a scan can see.

This is the fourth caller of `tests/_support/sourcescan.py`, which exists because a control
that forbids a term attracts prose containing that term — `dwaar/clock.py`'s own docstring
says `datetime.now(UTC)` three times explaining what it is for.

── What is deliberately NOT forbidden ──────────────────────────────────────────────────

`time.perf_counter()` and `time.monotonic()`. They measure durations, not instants: there is
no ambient state to substitute, no timezone to get wrong, and nothing a test could usefully
pin. `latency_us` is a duration and routing it through a seam would add indirection and buy
nothing. Permitted by NAME here rather than by omission, so the exemption is a decision
someone made rather than a gap someone left.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from tests._support.sourcescan import render, scan

REPO = Path(__file__).resolve().parents[1]

#: The one module allowed to read a wall clock. Everything else calls it.
SEAM = REPO / "dwaar" / "clock.py"

#: Scanned. `dwaar/` is the product; the other three write or read the evidence the product
#: produces, and a generator with a drifting clock produces traffic nobody can replay —
#: which is exactly how F-040 happened.
ROOTS = (REPO / "dwaar", REPO / "zoo", REPO / "tools", REPO / "eval", REPO / "scripts")

#: Instants. Every one of these is a question the seam answers.
FORBIDDEN = (
    re.compile(r"\bdatetime\.now\s*\("),
    re.compile(r"\bdatetime\.utcnow\s*\("),
    re.compile(r"\butcnow\s*\("),
    re.compile(r"\btime\.time\s*\("),
)

#: Pinning the clock in production code is production code with a stopped clock.
FREEZE = re.compile(r"\bclock\.frozen\s*\(")


def _scan(patterns, roots=ROOTS):
    result = scan(roots, patterns, suffixes=(".py",), relative_to=REPO)
    assert result.files_scanned > 0, (
        "the scanner found no files. A scan with nothing to scan reports no violations, "
        "which is indistinguishable from a clean tree — F-014's exact failure mode."
    )
    return result


def test_no_wall_clock_outside_the_seam():
    result = _scan(FORBIDDEN)
    offenders = [f for f in result.findings if (REPO / f.path).resolve() != SEAM]
    assert not offenders, (
        f"{len(offenders)} wall-clock call(s) outside dwaar/clock.py, across "
        f"{result.files_scanned} files:\n" + render(offenders) + "\n\n"
        "Call `dwaar.clock.now()` or `dwaar.clock.unix()`. If the caller can take an "
        "instant as a parameter, do that instead — injection is still preferred over the "
        "seam, and the seam exists for the boundaries that cannot carry one."
    )


def test_the_seam_itself_is_the_only_exemption():
    """The exemption is a path, so assert the path still holds a clock.

    If `dwaar/clock.py` were ever rewritten to call something else, the test above would
    keep passing while nothing in the system read a clock at all — a green check over an
    absent mechanism, which is F-014 wearing a different hat.
    """
    assert SEAM.exists(), "dwaar/clock.py is gone; the exemption points at nothing"
    result = scan([SEAM], FORBIDDEN, suffixes=(".py",), relative_to=REPO)
    assert result.findings, (
        "dwaar/clock.py contains no wall-clock call outside its prose. Either the seam no "
        "longer reads a clock, or the stripper is over-stripping and the check above is "
        "silently vacuous."
    )


def test_production_code_never_pins_the_clock():
    result = _scan([FREEZE])
    offenders = [f for f in result.findings if (REPO / f.path).resolve() != SEAM]
    assert not offenders, (
        "clock.frozen() is a test seam. Called from the product it is a stopped clock:\n"
        + render(offenders)
    )


def test_perf_counter_is_permitted(tmp_path):
    """The exemption is real and narrow. A positive control for the negative space."""
    sample = tmp_path / "duration.py"
    sample.write_text(
        "import time\n"
        "def measure(fn):\n"
        "    started = time.perf_counter()\n"
        "    fn()\n"
        "    return time.perf_counter() - started\n",
        encoding="utf-8",
    )
    assert not scan([sample], FORBIDDEN, suffixes=(".py",)).findings


@pytest.mark.parametrize(
    "source",
    [
        "from datetime import UTC, datetime\nstamp = datetime.now(UTC)\n",
        "import time\ncreated = int(time.time())\n",
        "from datetime import datetime\nstamp = datetime.utcnow()\n",
    ],
    ids=["datetime-now", "time-time", "utcnow"],
)
def test_positive_control_the_scanner_can_fail(tmp_path, source):
    """It has to be able to catch one. A guard nobody has seen fail is a guard nobody has
    seen work — the same reason `tests/test_absence_controls.py` exists."""
    planted = tmp_path / "violation.py"
    planted.write_text(source, encoding="utf-8")
    assert scan([planted], FORBIDDEN, suffixes=(".py",)).findings


def test_prose_about_the_clock_is_not_a_finding(tmp_path):
    """The reason this check routes through the shared stripper at all.

    Three earlier checks of this shape matched their own documentation. A module that
    forbids `datetime.now` will contain a docstring saying `datetime.now`, because the
    absence has to be justified somewhere and the natural place is the file being scanned.
    """
    sample = tmp_path / "documented.py"
    sample.write_text(
        '"""Never call datetime.now() here — use dwaar.clock.now()."""\n'
        "from dwaar import clock\n"
        "# time.time() is forbidden; the seam owns it.\n"
        "stamp = clock.now()\n",
        encoding="utf-8",
    )
    assert not scan([sample], FORBIDDEN, suffixes=(".py",)).findings
