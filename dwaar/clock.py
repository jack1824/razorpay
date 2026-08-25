"""The time seam. Every wall clock in `dwaar/` comes from here.

── Why a seam at all ───────────────────────────────────────────────────────────────────

F-040: the zoo's diurnal cycle was inverted — busiest at 8am, quietest at 8pm, and running
at twice the degraded-velocity threshold during working hours. It survived a full day of
green test runs because the tests read the same wall clock the bug did. They agreed with it
between 09:00 and 18:00 and disagreed only at 03:45, which is when it was finally caught.

    A time-dependent test does not fail. It waits.

That generalises past the clock. Any test whose outcome depends on ambient state — clock,
timezone, locale, filesystem ordering, network availability, an unseeded RNG — is not a
test. It is a coin flip with a slow period, and the period is usually longer than the
project. The clock is the ambient input this system actually depends on for correctness
(mandate expiry, signature skew, key rotation), so it is the one that gets a seam.

── What this module is, and what it is not ─────────────────────────────────────────────

It is a *seam*, not an abstraction. `now()` returns `datetime.now(UTC)` and nothing else.
The value is not in what it does; it is in there being exactly one place that does it, so
that:

    1. `tests/test_clock_seam.py` can assert nothing else in `dwaar/` reads a wall clock,
       which turns "we inject time" from a habit into a checked property;
    2. a test that cannot thread `now=` through a call can pin the clock instead of waiting
       for the right hour to come round.

**Injection is still the preferred mechanism.** `authorize(..., now=...)` exists and every
stage takes `now`. `freeze()` is for the cases where a caller sits behind a boundary that
does not carry one — an HTTP handler, a startup hook — not a licence to stop threading it.

── Monotonic time is deliberately NOT here ─────────────────────────────────────────────

`time.perf_counter()` and `time.monotonic()` stay where they are used. They measure
*durations*, not instants: there is no ambient state to substitute, no timezone to get
wrong, and nothing a test could usefully pin. Routing them through a seam would add
indirection to `latency_us` and buy nothing. `tests/test_clock_seam.py` permits them by
name for that reason, rather than by omission.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import UTC, datetime

__all__ = ["frozen", "is_frozen", "now", "unix"]

#: A ContextVar rather than a module global, so a pinned clock cannot leak out of the task
#: that set it. Under pytest-asyncio two tests share a process and a plain global set by one
#: would silently govern the next — which is the same class of defect this module exists to
#: close, reintroduced by the tool meant to close it.
_PINNED: ContextVar[datetime | None] = ContextVar("dwaar_clock_pinned", default=None)


def now() -> datetime:
    """The current instant, always timezone-aware and always UTC.

    Aware rather than naive without exception. A naive datetime compared against an aware
    one raises; compared against another naive one it silently compares wall clocks in two
    different zones, and mandate expiry is decided by exactly that comparison.
    """
    pinned = _PINNED.get()
    return pinned if pinned is not None else datetime.now(UTC)


def unix() -> int:
    """Seconds since the epoch, as an integer.

    RFC 9421's `created` parameter is integer seconds, and the skew window is compared in
    integer seconds. Deriving it from `now()` rather than from `time.time()` means a pinned
    clock governs signature skew as well — which is the F-035 lesson: the signature stage
    once held two clocks, and two rotation tests were passing on a request from the future
    stamped in the present.
    """
    return int(now().timestamp())


def is_frozen() -> bool:
    """Whether a clock is pinned in this context. For diagnostics, never for control flow."""
    return _PINNED.get() is not None


@contextmanager
def frozen(at: datetime) -> Iterator[datetime]:
    """Pin the clock for the duration of the block. TESTS ONLY.

    Refuses a naive datetime rather than assuming a zone for it. Assuming UTC would be
    right on this machine and wrong in CI, and the failure would be a test that passes
    everywhere except where it matters — which is the shape of defect this module exists
    to prevent, not one it should introduce.

    `tests/test_clock_seam.py` asserts this function is never *called* from `dwaar/`.
    Production code that pins the clock is production code with a stopped clock.
    """
    if at.tzinfo is None:
        raise ValueError(
            f"frozen() requires an aware datetime; got naive {at!r}. A naive instant is a "
            "wall clock without a zone, and pinning one would make the test that uses it "
            "pass in one timezone and fail in another."
        )
    token = _PINNED.set(at.astimezone(UTC))
    try:
        yield at
    finally:
        _PINNED.reset(token)
