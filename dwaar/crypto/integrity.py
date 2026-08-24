"""Signed-blob / column agreement, generalised.

── The recurring bug ───────────────────────────────────────────────────────────────────

Three tables carry a signed serialisation **and** columns extracted from it:

    decision_records   canonical_json  ↔  every signed column
    mandates           canonical_json  ↔  the ten mandate terms
    policies           compiled_rules  ↔  version, merchant_id, approval

The signature attests to the **blob**. The application, the console, the hot path and
every query read the **columns**. If the two can diverge undetected, the signature protects
a shadow copy nobody looks at.

That was found three times — F-013 (`mandates`, an app role could rewrite `expires_at` and
the principal's signature kept verifying), F-016 (`decision_records`, demo beat 6's
``UPDATE ... SET amount_paise`` produced a green PASS), and then `policies` by inspection.
Three instances is a bug class, not three bugs.

── The rule ────────────────────────────────────────────────────────────────────────────

**Any table carrying both a signed serialisation and extracted columns must be registered
in `REGISTRY` below.** The verifier iterates the registry, so registering a table is what
makes it checked — and forgetting to register one is caught by
`tests/crypto/test_integrity.py`, which asserts the registry covers every table that has a
canonical-form column.

Recorded as a standing requirement in `docs/adr/0001-phase-1-2-decisions.md`.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any


class IntegrityError(Exception):
    """Columns disagree with the bytes that were signed."""

    def __init__(self, table: str, identifier: Any, detail: str) -> None:
        super().__init__(f"{table} {identifier}: {detail}")
        self.table = table
        self.identifier = identifier
        self.detail = detail


@dataclass(frozen=True)
class IntegrityCheck:
    """How to re-derive one table's signed form from its columns."""

    table: str
    canonical_column: str
    identity_column: str
    rebuild: Callable[[Mapping[str, Any]], str]
    """Row → the canonical string those columns should produce."""
    signature_column: str | None = None
    """When set, a row with a NULL signature is skipped: it was never attested, which is a
    different thing from an attested row whose blob has gone missing."""
    merchant_predicate: str | None = None
    """SQL fragment restricting the table to one merchant, with a single %s placeholder.

    Without this, `--merchant` would scope the chain walk but not the column checks, so
    verifying one merchant would fail on another merchant's rows. `mandates` has no
    merchant_id of its own and reaches it through `principals`.
    """


def assert_columns_match_canonical(row: Mapping[str, Any], check: IntegrityCheck) -> None:
    """Raise unless ``row``'s columns re-derive exactly the stored canonical form.

    Deliberately raises rather than returning a bool: a caller that ignores a boolean is a
    caller that has silently disabled the control, and this is the control that catches an
    attacker with database access.
    """
    stored = row.get(check.canonical_column)
    identifier = row.get(check.identity_column)

    if check.signature_column is not None and row.get(check.signature_column) is None:
        return  # never signed; nothing is being claimed about it

    if stored is None:
        raise IntegrityError(
            check.table, identifier, f"{check.canonical_column} is NULL; nothing to verify against"
        )

    try:
        rebuilt = check.rebuild(row)
    except Exception as exc:  # noqa: BLE001
        raise IntegrityError(
            check.table, identifier, f"columns cannot be canonicalised: {exc}"
        ) from exc

    if rebuilt != stored:
        raise IntegrityError(
            check.table,
            identifier,
            f"columns do not match the signed {check.canonical_column}",
        )


def _rebuild_decision_record(row: Mapping[str, Any]) -> str:
    from dwaar.crypto import record

    return record.canonical_json(record.payload_from_row(row))


def _rebuild_mandate(row: Mapping[str, Any]) -> str:
    from dwaar.crypto import mandate

    return mandate.canonical_json(
        mandate.build_payload(
            mandate_id=row["mandate_id"],
            principal_id=row["principal_id"],
            agent_id=row["agent_id"],
            max_total_paise=row["max_total_paise"],
            max_per_txn_paise=row["max_per_txn_paise"],
            allow_categories=list(row["allow_categories"]),
            deny_categories=list(row["deny_categories"]),
            substitution_tolerance=row["substitution_tolerance"],
            expires_at=row["expires_at"],  # build_payload normalises to UTC
            nonce=row["nonce"],
        )
    )


def _rebuild_policy(row: Mapping[str, Any]) -> str:
    """Policies sign their compiled ruleset together with what identifies and approves it.

    Signing ``compiled_rules`` alone would leave `version`, `merchant_id` and `approved_by`
    free — so an approved v3 ruleset could be repointed at another merchant, or an
    unapproved version could inherit an approval, with the signature still valid.
    """
    from dwaar.crypto.jcs import canonicalize

    return canonicalize(
        {
            "policy_id": row["policy_id"],
            "merchant_id": row["merchant_id"],
            "version": row["version"],
            "compiled_rules": row["compiled_rules"],
            "approved_by": row["approved_by"],
        }
    )


DECISION_RECORDS = IntegrityCheck(
    table="decision_records",
    canonical_column="canonical_json",
    identity_column="seq",
    rebuild=_rebuild_decision_record,
    merchant_predicate="merchant_id = %s",
)

MANDATES = IntegrityCheck(
    table="mandates",
    canonical_column="canonical_json",
    identity_column="mandate_id",
    rebuild=_rebuild_mandate,
    merchant_predicate=(
        "principal_id IN (SELECT principal_id FROM principals WHERE merchant_id = %s)"
    ),
)

POLICIES = IntegrityCheck(
    table="policies",
    canonical_column="canonical_json",
    identity_column="policy_id",
    rebuild=_rebuild_policy,
    signature_column="signature",
    merchant_predicate="merchant_id = %s",
)

REGISTRY: tuple[IntegrityCheck, ...] = (DECISION_RECORDS, MANDATES, POLICIES)
