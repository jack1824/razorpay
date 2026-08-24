"""The signed mandate payload: exactly ten keys, always.

ADR 0001 item 9. Under JCS an absent key and an empty array serialise differently, so
"omit if default" would give one mandate two valid ``mandate_hash`` values — and a
verifier that reconstructs the payload a different way than the signer did produces a
signature failure indistinguishable from a forgery.

The rule is therefore: **materialise every default before signing.** ``allow_categories``
and ``deny_categories`` become ``[]``, ``substitution_tolerance`` becomes ``"none"``. The
mandate schema in the strategy package marks only seven of the ten as required; this module
is the reason that does not matter.

Pinned by a golden vector in ``tests/crypto/test_mandate_vector.py``.
"""

from __future__ import annotations

import hashlib
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


def build_payload(**fields: Any) -> dict[str, Any]:
    """Assemble the exact object that gets signed.

    Raises on a missing required field or an unexpected extra one. Both are errors worth
    failing on: a missing field means the signature covers less than it should, and an
    extra one means the verifier will not reconstruct the same bytes.
    """
    payload: dict[str, Any] = {}
    for name in SIGNED_FIELDS:
        if name in fields and fields[name] is not None:
            payload[name] = fields[name]
        elif name in DEFAULTS:
            payload[name] = DEFAULTS[name]
        else:
            raise ValueError(f"mandate payload missing required field {name!r}")

    extra = set(fields) - set(SIGNED_FIELDS)
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
