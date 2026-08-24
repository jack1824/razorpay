"""RFC 9421 HTTP Message Signatures, Ed25519.

A focused subset — one signature label, a fixed component set, the parameters we actually
need. Implementing all of RFC 9421 would be a week and most of it is structured-field
parsing for cases this API never produces.

── What is covered, and why each component is not optional ─────────────────────────────

    "@method"          POST. Without it a signed POST could be replayed as a DELETE.
    "@path"            /v1/authorize. Without it a signature is portable between endpoints.
    "content-digest"   RFC 9530 sha-256 of the body. This is what binds the signature to
                       the *content*: signing only headers authenticates the envelope and
                       leaves the amount free to change.

    created            a Unix timestamp. Bounds replay to the skew window.
    keyid              the agent_id. Says whose key to verify with.
    alg                "ed25519".
    nonce              per-request, single-use. `created` alone bounds replay to ±120s,
                       which is 120 seconds of free replays.

── Both directions live here ───────────────────────────────────────────────────────────

``sign_request`` and ``verify_request`` are in one module, and `zoo/` imports it so agents
sign the way the gateway verifies. That is the allowed direction (`dwaar/` never imports
`zoo/`), but it does mean a wrong implementation would agree with itself.

Which is exactly why `tests/crypto/test_http_sig.py` carries **known-answer vectors**: a
hand-constructed signature base, asserted byte for byte against the RFC's construction
rules. Agreement between our signer and our verifier proves nothing; agreement with the
specification does.
"""

from __future__ import annotations

import base64
import hashlib
import re
import time
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

SIG_LABEL = "sig1"
ALGORITHM = "ed25519"

COVERED_COMPONENTS: tuple[str, ...] = ("@method", "@path", "content-digest")

# ±120s, per FAIL_MATRIX.md's clock-skew row.
DEFAULT_SKEW_SECONDS = 120


class SignatureError(Exception):
    """Verification failed. Always fail-closed — identity is not optional."""


@dataclass(frozen=True)
class VerifiedSignature:
    params: SignatureParams
    key_index: int
    """Which entry of ``public_keys`` matched. 0 is the current key; >0 is a rotation
    overlap key. Reported rather than inferred, because the caller cannot otherwise tell
    and "which credential was actually used" is exactly what an audit trail needs."""


@dataclass(frozen=True)
class SignatureParams:
    keyid: str
    created: int
    nonce: str | None
    alg: str


def content_digest(body: bytes) -> str:
    """RFC 9530 Content-Digest: ``sha-256=:<base64>:``"""
    digest = base64.b64encode(hashlib.sha256(body).digest()).decode()
    return f"sha-256=:{digest}:"


def _params_string(params: SignatureParams) -> str:
    components = " ".join(f'"{c}"' for c in COVERED_COMPONENTS)
    out = f"({components});created={params.created};keyid=\"{params.keyid}\""
    if params.nonce is not None:
        out += f';nonce="{params.nonce}"'
    out += f';alg="{params.alg}"'
    return out


def build_signature_base(
    method: str, path: str, digest: str, params: SignatureParams
) -> bytes:
    """The exact bytes that get signed (RFC 9421 §2.5).

    One line per covered component, ``"name": value``, LF-separated, terminated by the
    ``"@signature-params"`` line **with no trailing newline**. That final detail is the one
    every independent implementation gets wrong first, so it is asserted by a known-answer
    vector rather than trusted.
    """
    lines = [
        f'"@method": {method.upper()}',
        f'"@path": {path}',
        f'"content-digest": {digest}',
        f'"@signature-params": {_params_string(params)}',
    ]
    return "\n".join(lines).encode("utf-8")


def sign_request(
    private_key: Ed25519PrivateKey,
    *,
    method: str,
    path: str,
    body: bytes,
    keyid: str,
    created: int | None = None,
    nonce: str | None = None,
) -> dict[str, str]:
    """Produce the three headers a signed request carries."""
    params = SignatureParams(
        keyid=keyid,
        created=created if created is not None else int(time.time()),
        nonce=nonce,
        alg=ALGORITHM,
    )
    digest = content_digest(body)
    signature = private_key.sign(build_signature_base(method, path, digest, params))
    return {
        "Content-Digest": digest,
        "Signature-Input": f"{SIG_LABEL}={_params_string(params)}",
        "Signature": f"{SIG_LABEL}=:{base64.b64encode(signature).decode()}:",
    }


_PARAMS_RE = re.compile(
    r'^\((?P<components>[^)]*)\)'
    r'(?P<params>(?:;[a-z]+=(?:"[^"]*"|\d+))*)$'
)
_PARAM_RE = re.compile(r';(?P<key>[a-z]+)=(?:"(?P<quoted>[^"]*)"|(?P<bare>\d+))')


def parse_signature_input(header: str) -> tuple[str, SignatureParams, tuple[str, ...]]:
    """Parse ``Signature-Input``. Raises ``SignatureError`` on anything malformed.

    Strict by design: this runs before authentication, on attacker-controlled input, so a
    permissive parser here is a permissive parser in the most exposed place in the system.
    """
    if "=" not in header:
        raise SignatureError("malformed Signature-Input: no label")
    label, _, rest = header.partition("=")
    label = label.strip()

    match = _PARAMS_RE.match(rest.strip())
    if match is None:
        raise SignatureError("malformed Signature-Input: unparseable parameters")

    components = tuple(c.strip('"') for c in match.group("components").split() if c)

    found: dict[str, str] = {}
    for param in _PARAM_RE.finditer(match.group("params")):
        found[param.group("key")] = (
            param.group("quoted") if param.group("quoted") is not None else param.group("bare")
        )

    for required in ("created", "keyid", "alg"):
        if required not in found:
            raise SignatureError(f"malformed Signature-Input: missing {required}")

    try:
        created = int(found["created"])
    except ValueError as exc:
        raise SignatureError("malformed Signature-Input: created is not an integer") from exc

    return label, SignatureParams(
        keyid=found["keyid"], created=created, nonce=found.get("nonce"), alg=found["alg"]
    ), components


def parse_signature(header: str, expected_label: str) -> bytes:
    """Parse ``Signature: sig1=:<base64>:``"""
    prefix = f"{expected_label}="
    if not header.startswith(prefix):
        raise SignatureError(f"Signature label does not match Signature-Input ({expected_label})")
    encoded = header[len(prefix):].strip()
    if not (encoded.startswith(":") and encoded.endswith(":")):
        raise SignatureError("malformed Signature: expected a byte-sequence in colons")
    try:
        raw = base64.b64decode(encoded[1:-1], validate=True)
    except Exception as exc:  # noqa: BLE001
        raise SignatureError("malformed Signature: not valid base64") from exc
    if len(raw) != 64:
        raise SignatureError(f"Ed25519 signatures are 64 bytes, got {len(raw)}")
    return raw


def verify_request(
    *,
    method: str,
    path: str,
    body: bytes,
    headers: dict[str, str],
    public_keys: list[bytes],
    now: int | None = None,
    skew_seconds: int = DEFAULT_SKEW_SECONDS,
) -> VerifiedSignature:
    """Verify, or raise ``SignatureError``. Never returns a boolean.

    ``public_keys`` is a LIST so key rotation works: during the overlap window the current
    and previous keys are both acceptable. Passing one key would mean every rotation
    rejects requests already in flight.

    Returns the parsed params and which key matched, so the caller can record the nonce for
    replay defence and note whether a rotation-overlap credential was used. Deliberately
    stateless: a signature checker that also does I/O is a signature checker you cannot test
    without a database.
    """
    lowered = {k.lower(): v for k, v in headers.items()}
    for required in ("signature-input", "signature", "content-digest"):
        if required not in lowered:
            raise SignatureError(f"missing required header: {required}")

    label, params, components = parse_signature_input(lowered["signature-input"])
    signature = parse_signature(lowered["signature"], label)

    if params.alg != ALGORITHM:
        raise SignatureError(f"unsupported algorithm {params.alg!r}; expected {ALGORITHM!r}")

    # The covered set is fixed, not merely checked for presence. An attacker who could
    # choose which components are covered would simply cover none of the ones that matter.
    if components != COVERED_COMPONENTS:
        raise SignatureError(
            f"covered components {list(components)} do not match the required set "
            f"{list(COVERED_COMPONENTS)}"
        )

    current = now if now is not None else int(time.time())
    age = current - params.created
    if age > skew_seconds:
        raise SignatureError(f"signature created {age}s ago, outside the {skew_seconds}s window")
    if age < -skew_seconds:
        raise SignatureError(f"signature created {-age}s in the future")

    # Recompute the digest from the body we actually received. Trusting the header would
    # let an attacker keep a valid signature and swap the body underneath it.
    expected_digest = content_digest(body)
    if lowered["content-digest"] != expected_digest:
        raise SignatureError("Content-Digest does not match the request body")

    base = build_signature_base(method, path, expected_digest, params)
    for index, key in enumerate(public_keys):
        try:
            Ed25519PublicKey.from_public_bytes(bytes(key)).verify(signature, base)
            return VerifiedSignature(params=params, key_index=index)
        except InvalidSignature:
            continue
    raise SignatureError("signature does not verify against any acceptable key")
