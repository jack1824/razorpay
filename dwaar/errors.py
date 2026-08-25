"""Error types.

Reason codes are deliberately coarse on the way out and fine-grained on the way in
(threat 10, policy-boundary probing): telling an agent precisely which limit it hit lets
it binary-search the mandate. ``DwaarError`` therefore carries both, and only
``public_reason`` is ever serialised to an agent.
"""

from __future__ import annotations


class DwaarError(Exception):
    """Base error. Carries a coarse outward code and a precise internal one."""

    public_reason: str = "denied"
    status_code: int = 400

    def __init__(self, internal_reason: str, *, public_reason: str | None = None) -> None:
        super().__init__(internal_reason)
        self.internal_reason = internal_reason
        if public_reason is not None:
            self.public_reason = public_reason


class ConfigError(DwaarError):
    public_reason = "server_error"
    status_code = 500


class MigrationError(DwaarError):
    public_reason = "server_error"
    status_code = 500


class RepositoryError(DwaarError):
    public_reason = "server_error"
    status_code = 500


class LedgerError(RepositoryError):
    """Budget ledger failure. Authority — always fail-closed. See FAIL_MATRIX.md."""

    public_reason = "unavailable"
    status_code = 503


class InsufficientBudget(DwaarError):
    """Arithmetic, not a model score. ``amount > balance`` and nothing else."""

    public_reason = "denied"
    status_code = 200  # A deny is a rendered decision, not an HTTP error.


class AmountInvariantViolation(LedgerError):
    """What the ledger moved does not equal what the decision stated.

    Fail-closed, and a subclass of ``LedgerError`` rather than a peer because it is the same
    answer to the caller: we cannot tell you what just happened, so nothing happens. Stage 8
    raises it inside stage 6's transaction, so the reservation rolls back with it.

    Never a warning. This is the money invariant — it sits beside ``balance_after >= 0``,
    and a system that logs one of those and continues is a system that has stopped enforcing
    the other. See ``dwaar/invariants.py`` and FAILURES.md F-038.
    """


class ChainError(RepositoryError):
    """Decision chain integrity failure. Fail-closed: we do not write what we cannot chain."""

    public_reason = "unavailable"
    status_code = 503


class BodyTooLarge(DwaarError):
    public_reason = "request_too_large"
    status_code = 413
