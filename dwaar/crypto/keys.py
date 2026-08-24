"""Deterministic Ed25519 keypair derivation (FAILURES.md F-004, ADR item 14).

Every keypair in the demo is derived from one integer seed via HKDF-SHA256. Same seed,
same keys, byte for byte, on any machine.

**Public keys go to the database. Private keys go only to a gitignored ``.keys/``.** That
split is the whole point: the fixtures need signed mandates, signing needs principal
private keys, and the convenient thing to do at that moment — commit a keypair — puts a
private key in git for good. ``.keys/`` was in ``.gitignore`` before the directory existed.

This is a **demo key-management scheme and nothing more.** Deriving production signing keys
from a hardcoded integer would be indefensible; deriving reproducible demo identities from a
published seed is exactly right, because reproducibility is the property we want and there
is no secret to protect. Real deployment uses a KMS. Stated here so the distinction is never
accidentally lost.
"""

from __future__ import annotations

from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Fixed, published, and not a secret. HKDF's salt exists to domain-separate derivations,
# not to add entropy — the seed is the only input that varies and it is printed in SEED.txt.
_HKDF_SALT = b"dwaar/demo-seed/v1"


def derive_private_key(seed: int, role: str, identifier: str) -> Ed25519PrivateKey:
    """Derive one Ed25519 private key from ``(seed, role, identifier)``.

    ``role`` domain-separates agents from principals from Dwaar's own signing key, so an
    agent and a principal that happened to share an id could never share a key.
    """
    material = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_HKDF_SALT,
        info=f"{role}/{identifier}".encode(),
    ).derive(str(seed).encode())
    return Ed25519PrivateKey.from_private_bytes(material)


def public_bytes(key: Ed25519PrivateKey | Ed25519PublicKey) -> bytes:
    """Raw 32-byte public key — the form ``agents.public_key`` stores."""
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    pub = key.public_key() if isinstance(key, Ed25519PrivateKey) else key
    return pub.public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)


def private_bytes(key: Ed25519PrivateKey) -> bytes:
    """Raw 32-byte private key. Only ever written under ``.keys/``."""
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
    )

    return key.private_bytes(
        encoding=Encoding.Raw, format=PrivateFormat.Raw, encryption_algorithm=NoEncryption()
    )


def write_private_key(keys_dir: Path, role: str, identifier: str, key: Ed25519PrivateKey) -> Path:
    """Write a private key to ``.keys/<role>/<identifier>.key`` with 0600 permissions."""
    target = keys_dir / role
    target.mkdir(parents=True, exist_ok=True)
    path = target / f"{identifier}.key"
    path.write_bytes(private_bytes(key))
    path.chmod(0o600)
    return path


def load_private_key(keys_dir: Path, role: str, identifier: str) -> Ed25519PrivateKey:
    """Read a private key back. Used by ``zoo/`` to sign as an agent."""
    raw = (keys_dir / role / f"{identifier}.key").read_bytes()
    return Ed25519PrivateKey.from_private_bytes(raw)
