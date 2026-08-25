"""The signed mandate payload: exactly ten keys, plus one that is present or absent.

ADR 0001 item 9. Under JCS an absent key and an empty array serialise differently, so
"omit if default" would give one mandate two valid ``mandate_hash`` values — and a
verifier that reconstructs the payload a different way than the signer did produces a
signature failure indistinguishable from a forgery.

The rule is therefore: **materialise every default before signing.** ``allow_categories``
and ``deny_categories`` become ``[]``, ``substitution_tolerance`` becomes ``"none"``. The
mandate schema in the strategy package marks only seven of the ten as required; this module
is the reason that does not matter.

Pinned by a golden vector in ``tests/crypto/test_mandate_vector.py``.

── The one exception, and why it does not undo the rule ────────────────────────────────

``scopes`` (migration 0015) is included **if and only if the column is not NULL**. That is
omit-if-absent, which the paragraph above forbids — so it needs its own justification rather
than an exemption.

The hazard the rule protects against is a signer and a verifier reasoning DIFFERENTLY about
a default. "Omit `allow_categories` when empty" is dangerous because emptiness is a property
of the value, and two implementations can disagree about whether `None`, `[]` and a missing
key are the same thing.

Nullness of a column is not that. Both the signer and the verifier read the same row and see
the same NULL, so there is no case in which they can disagree about which form applies. The
discriminator is in the data, not in anybody's interpretation of a default.

The alternative was making it a required eleventh field, which would have invalidated every
mandate signed before it existed. Those signatures are correct and the terms they cover have
not changed; breaking them to add a column would be rewriting history to fit a feature.

``tests/crypto/test_mandate_vector.py`` pins BOTH forms with golden vectors, because a
second canonical form that nothing pins is a second canonical form that will drift.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Any

from dwaar.crypto.jcs import canonicalize, canonicalize_bytes

# The signed field set, in no particular order — JCS sorts them. Listed explicitly rather
# than inferred, so adding a mandate column cannot silently change what a signature covers.
SIGNED_FIELDS: tuple[str, ...] = (
    "mandate_id",
    "principal_id",
    "agent_id",
    "max_total_paise",
    "max_per_txn_paise",
    "allow_categories",
    "deny_categories",
    "substitution_tolerance",
    "expires_at",
    "nonce",
)

DEFAULTS: dict[str, Any] = {
    "allow_categories": [],
    "deny_categories": [],
    "substitution_tolerance": "none",
}

#: Present in the payload IFF supplied and not None. See the module docstring — this is the
#: single exception to "materialise every default", and it exists so that mandates signed
#: before scopes existed keep verifying.
OPTIONAL_FIELDS: tuple[str, ...] = ("scopes",)


def build_payload(**fields: Any) -> dict[str, Any]:
    """Assemble the exact object that gets signed.

    Raises on a missing required field or an unexpected extra one. Both are errors worth
    failing on: a missing field means the signature covers less than it should, and an
    extra one means the verifier will not reconstruct the same bytes.
    """
    payload: dict[str, Any] = {}
    for name in SIGNED_FIELDS:
        if name in fields and fields[name] is not None:
            value = fields[name]
            if isinstance(value, datetime):
                # Always UTC. PostgreSQL returns TIMESTAMPTZ in the session timezone, so a
                # verifier connecting with a different TimeZone setting would otherwise
                # rebuild different bytes and report a valid mandate as tampered. The
                # verifier caught exactly that on its first run.
                value = value.astimezone(UTC).isoformat()
            payload[name] = value
        elif name in DEFAULTS:
            payload[name] = DEFAULTS[name]
        else:
            raise ValueError(f"mandate payload missing required field {name!r}")

    for name in OPTIONAL_FIELDS:
        value = fields.get(name)
        if value is not None:
            # Sorted, because a set of delegated scopes has no meaningful order and two
            # callers listing them differently must produce the same mandate. JCS sorts
            # object KEYS, never array elements, so this has to happen here.
            payload[name] = sorted(value) if isinstance(value, (list, tuple, set)) else value

    extra = set(fields) - set(SIGNED_FIELDS) - set(OPTIONAL_FIELDS)
    if extra:
        raise ValueError(
            f"mandate payload has fields outside the signed set: {sorted(extra)}. "
            "Adding a field changes what every signature covers — put it in SIGNED_FIELDS "
            "deliberately or leave it off the mandate."
        )
    return payload


def canonical_json(payload: dict[str, Any]) -> str:
    return canonicalize(payload)


def mandate_hash(payload: dict[str, Any]) -> bytes:
    """sha256 over the canonical bytes. This is what ``mandates.mandate_hash`` stores."""
    return hashlib.sha256(canonicalize_bytes(payload)).digest()
