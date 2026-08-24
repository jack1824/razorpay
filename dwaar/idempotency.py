"""Idempotency key namespaces.

One module because the rules must not be restated anywhere. A key derived one way in
``mandates.create`` and another way in ``budget_ledger.release`` is a collision waiting for
production traffic.

── Why client keys are always prefixed ─────────────────────────────────────────────────

The agent supplies ``idempotency_key`` and the agent is untrusted (trust boundary 1). If
its string were stored verbatim alongside server-derived keys, an agent could submit::

    idempotency_key = "release:1234"

Later, when the system releases ledger entry 1234, its derived key collides with the
agent's row. The insert is absorbed as a duplicate, **the release silently no-ops, and that
reservation leaks permanently** — budget consumed forever against nothing.

Prefixing every client key with ``rsv:`` makes the namespaces disjoint by construction. No
validation of agent input is required, which matters: validation is a rule someone can
forget to apply at a new call site, whereas a namespace that cannot overlap is a property.

``release:<entry_id>`` also makes releases idempotent for free — a duplicate release derives
the same key, collides, and is absorbed rather than double-crediting the budget.

── Why uniqueness is scoped to the mandate ─────────────────────────────────────────────

A global ``UNIQUE (idempotency_key)`` lets agent A burn agent B's key: a cross-tenant denial
of service, and an oracle telling A that B is using that key. The ledger is per-mandate and
a mandate binds one agent to one principal, so the mandate is the correct scope. Two
mandates held by the same agent are separate budgets and separate authorities; the same
client key on both legitimately produces two entries.
"""

from __future__ import annotations

from typing import Final

GENESIS: Final[str] = "genesis"
RESERVE: Final[str] = "rsv"
RELEASE: Final[str] = "release"
SETTLE: Final[str] = "settle"

NAMESPACES: Final[tuple[str, ...]] = (GENESIS, RESERVE, RELEASE, SETTLE)


def genesis_key(mandate_id: str) -> str:
    """Opening balance. Doubles as the 'already initialised' guard."""
    return f"{GENESIS}:{mandate_id}"


def reserve_key(client_key: str) -> str:
    """A reservation, from the agent's key. ALWAYS prefixed — see the module docstring."""
    return f"{RESERVE}:{client_key}"


def release_key(reserve_entry_id: int) -> str:
    """A compensating release, derived from the entry it reverses.

    Derived rather than supplied, so releasing the same reservation twice is absorbed
    instead of double-crediting.
    """
    return f"{RELEASE}:{reserve_entry_id}"


def settle_key(reserve_entry_id: int) -> str:
    """Settlement of a held reservation. Same derivation logic as release."""
    return f"{SETTLE}:{reserve_entry_id}"


def namespace_of(key: str) -> str | None:
    """The namespace a stored key belongs to, or None if it carries no known prefix.

    Used by tests to assert that no stored key escaped namespacing.
    """
    prefix = key.split(":", 1)[0]
    return prefix if prefix in NAMESPACES else None
