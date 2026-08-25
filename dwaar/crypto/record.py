"""The signed decision-record payload.

Same discipline as ``dwaar/crypto/mandate.py``: an explicit field list, defaults
materialised, JCS canonicalisation, and a golden vector pinning the bytes. Records are
append-only and chained, so this definition is permanent — a field added later cannot be
backfilled and re-canonicalising forks the chain.

What is signed, and why each exclusion is deliberate:

- ``seq`` and ``prev_hash`` are **in**. They are the chain. Signing them is what stops an
  attacker reordering records or splicing a valid record into a different position.
- ``signing_key_id`` is **in**. If it were outside, an attacker with database access could
  repoint a record at a key they control and the signature would still verify.
- ``created_at`` is **in**, and is supplied by the application rather than defaulted by the
  database, so a record's own timestamp is tamper-evident.
- ``latency_us`` is **in**. It is the number the pitch leans on hardest; leaving it unsigned
  would make it the one figure an attacker could rewrite freely.
- ``degraded_mode`` is **in**, sorted. Whether a decision was degraded is material to how it
  should be read. Sorting is load-bearing: array order changes the hash.
- ``payload_hash`` and ``signature`` are **out** — both are circular.
- ``record_id`` is **out**. It is a database-assigned UUID with no semantic content; ``seq``
  is the identity that everything else references.
- ``request_idempotency_key`` is **in**. It identifies *which* request this record answers.
  A record that could be repointed at a different request would be evidence of nothing.

── Two fields that are present or absent, and why that is not a hole ────────────────────

``bounded_amount_paise`` and ``tool`` (migration 0017) are included **if and only if the
column is not NULL**. That is omit-if-absent, which the paragraph above forbids, so it
needs the same justification ``dwaar/crypto/mandate.py`` gives for ``scopes`` rather than
an exemption.

The hazard the rule protects against is a signer and a verifier reasoning DIFFERENTLY
about a default. Nullness of a column is not that: both read the same row and see the
same NULL, so there is no case in which they can disagree about which form applies. The
discriminator is in the data, not in anybody's interpretation of a default.

The alternative was making them required, which would have re-canonicalised — and so
invalidated — every record signed before today. Those signatures are correct and what
they attest to has not changed.

``bounded_amount_paise`` is load-bearing rather than decorative: it is the amount the
decision STATED, and without it in the record the money invariant
(``dwaar/invariants.py``) has one of its two sides missing. That is the gap F-038 lived
in for four phases.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Any

from dwaar.crypto.jcs import canonicalize, canonicalize_bytes

SIGNED_FIELDS: tuple[str, ...] = (
    # chain position
    "seq",
    "merchant_id",
    "prev_hash",
    "signing_key_id",
    # who
    "agent_id",
    "principal_id",
    "mandate_hash",
    "request_digest",
    "request_idempotency_key",
    # what was decided
    "decision",
    "reason_code",
    "rule_fired",
    # what informed it
    "risk_score",
    "model_version",
    "injection_flag",
    "features",
    "policy_version",
    # money
    "amount_paise",
    "budget_before",
    "budget_after",
    # how it ran
    "degraded_mode",
    "stages_executed",
    "latency_us",
    "created_at",
)

#: Present in the payload IFF supplied and not None. Migration 0017. See the module
#: docstring — this is the single exception to "materialise every default", and it exists
#: so records signed before these fields existed keep verifying.
OPTIONAL_FIELDS: tuple[str, ...] = ("bounded_amount_paise", "tool")

# Fields that may legitimately be absent and get an explicit null rather than being omitted.
# Under JCS an absent key and an explicit null are different bytes, so "omit if None" would
# give one record two valid hashes.
NULLABLE_FIELDS: frozenset[str] = frozenset(
    {
        "request_idempotency_key",
        "rule_fired",
        # TRISTATE since migration 0014. NULL means no detector ran on this request, which
        # is the case for every gate-denied record — the gate short-circuits stages 3 to 6,
        # so `detect_injection` never happens. `false` would claim a check nobody performed.
        "injection_flag",
        "risk_score",
        "model_version",
        "policy_version",
        "amount_paise",
        "budget_before",
        "budget_after",
    }
)


def _hex(value: bytes | str) -> str:
    return value.hex() if isinstance(value, bytes) else value


def build_payload(**fields: Any) -> dict[str, Any]:
    """Assemble the exact object that gets signed.

    Bytes become lowercase hex and datetimes become ISO-8601, because JCS has no
    representation for either — that conversion is part of the format, not a detail.
    """
    payload: dict[str, Any] = {}
    for name in SIGNED_FIELDS:
        if name not in fields:
            if name in NULLABLE_FIELDS:
                payload[name] = None
                continue
            raise ValueError(f"decision record payload missing required field {name!r}")

        value = fields[name]
        if value is None and name not in NULLABLE_FIELDS:
            raise ValueError(f"decision record field {name!r} may not be null")

        if name in ("prev_hash", "mandate_hash", "request_digest") and value is not None:
            value = _hex(bytes(value))
        elif name == "created_at" and isinstance(value, datetime):
            # Always UTC. PostgreSQL returns TIMESTAMPTZ in the session timezone, so a
            # verifier connecting with a different TimeZone setting would otherwise
            # reconstruct different bytes and report a valid record as forged.
            value = value.astimezone(UTC).isoformat()
        elif name == "risk_score" and value is not None:
            # NUMERIC(5,4) round-trips as Decimal; JCS forbids floats, so it is carried as
            # its exact 4-decimal string rather than a lossy float.
            value = f"{float(value):.4f}"
        elif name in ("degraded_mode", "stages_executed"):
            value = list(value)
            if name == "degraded_mode":
                value = sorted(value)  # order is inside the hash

        payload[name] = value

    for name in OPTIONAL_FIELDS:
        value = fields.get(name)
        if value is not None:
            payload[name] = value

    extra = set(fields) - set(SIGNED_FIELDS) - set(OPTIONAL_FIELDS)
    if extra:
        raise ValueError(
            f"decision record payload has fields outside the signed set: {sorted(extra)}. "
            "Adding one changes what every signature covers and cannot be backfilled onto "
            "an append-only chained table."
        )
    return payload


def canonical_json(payload: dict[str, Any]) -> str:
    return canonicalize(payload)


def payload_hash(payload: dict[str, Any]) -> bytes:
    """sha256 over the canonical bytes. This is the chain link and the next row's prev_hash."""
    return hashlib.sha256(canonicalize_bytes(payload)).digest()


def payload_from_row(row: dict[str, Any]) -> dict[str, Any]:
    """Reconstruct the signed payload from a stored ``decision_records`` row.

    This is what makes column tampering detectable. The signature covers
    ``canonical_json``; the columns are what every reader, query and console actually
    looks at. If the two can diverge undetected then the signature protects a shadow copy
    nobody reads — and demo beat 6, which is literally
    ``UPDATE decision_records SET amount_paise = ...``, would verify clean.
    """
    fields = {name: row[name] for name in SIGNED_FIELDS}
    # `.get`, because a row read from a database that has not had migration 0017 applied
    # has no such key at all — and a verifier that raised KeyError there would report an
    # unmigrated database as a forged chain.
    fields.update({name: row.get(name) for name in OPTIONAL_FIELDS})
    return build_payload(**fields)
