"""Repository layer. Hand-written SQL over psycopg — no ORM, in or out of the hot path.

Import the modules, not their contents::

    from dwaar.db.repositories import budget_ledger, mandates

Each module owns one table (``mandates`` owns its genesis ledger entry too, because that
write must land in the same transaction). The bytes/hex conversion lives in ``base`` and
nowhere else.
"""

from dwaar.db.repositories import (  # noqa: F401
    agents,
    budget_ledger,
    decision_records,
    mandates,
    policies,
    principals,
)

__all__ = [
    "agents",
    "budget_ledger",
    "decision_records",
    "mandates",
    "policies",
    "principals",
]
