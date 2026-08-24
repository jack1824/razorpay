"""Dwaar's own signing identity.

Derived from a seed by the same HKDF mechanism as every other keypair in the demo, so the
whole system is reproducible from one integer. Private half to a gitignored ``.keys/``,
public half into ``signing_keys`` with a real ``key_id``.

The ``key_id`` is derived from the public key rather than assigned, so it cannot drift from
the material it names — two different keys can never share an id, and the same key always
gets the same id no matter how many times it is bootstrapped.

**This is a demo key-management scheme.** A production signer belongs in a KMS and never
touches application memory. Deriving a reproducible demo identity from a published seed is
the right trade for a system whose whole point is that anyone can re-run it and get the
same answer; deriving a production signing key this way would be indefensible. Stated here
so the distinction cannot be lost by someone reading only this file.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from dwaar.crypto import keys as keymod

SIGNER_ROLE = "dwaar"


@dataclass(frozen=True)
class Signer:
    key_id: str
    private_key: Ed25519PrivateKey

    @property
    def public_key_bytes(self) -> bytes:
        return keymod.public_bytes(self.private_key)

    def sign(self, message: bytes) -> bytes:
        return self.private_key.sign(message)


def derive_key_id(public_key: bytes) -> str:
    """``key_`` plus the first 12 hex chars of sha256(public key).

    Derived, never assigned: an id that names its own material cannot drift from it.
    """
    return f"key_{hashlib.sha256(public_key).hexdigest()[:12]}"


def derive_signer(seed: int, *, keys_dir: Path | None = None) -> Signer:
    """Derive the signing identity for ``seed``, optionally persisting the private half."""
    private = keymod.derive_private_key(seed, SIGNER_ROLE, "chain-signer")
    key_id = derive_key_id(keymod.public_bytes(private))
    if keys_dir is not None:
        keymod.write_private_key(keys_dir, SIGNER_ROLE, key_id, private)
    return Signer(key_id=key_id, private_key=private)


async def ensure_registered(conn, signer: Signer) -> str:
    """Insert the public half into ``signing_keys`` if it is not already there.

    Idempotent on ``key_id``, and deliberately not an UPSERT: the app holds no UPDATE on
    ``signing_keys.public_key`` (migration 0010), because rewriting a key that has already
    signed records would invalidate every one of them — and invalidation is
    indistinguishable from forgery.
    """
    async with conn.cursor() as cur:
        await cur.execute(
            "INSERT INTO signing_keys (key_id, public_key) VALUES (%s, %s) "
            "ON CONFLICT (key_id) DO NOTHING",
            (signer.key_id, signer.public_key_bytes),
        )
    return signer.key_id
