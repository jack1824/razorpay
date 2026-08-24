"""RFC 9421 — known-answer vectors and negative cases.

`sign_request` and `verify_request` live in one module and `zoo/` imports it, so agents
sign the way the gateway verifies. That is the allowed direction, but it means a wrong
implementation would agree with itself perfectly.

So the signature base is asserted **byte for byte against the RFC's construction rules**,
hand-written here rather than produced by the code under test. Agreement between our signer
and our verifier proves nothing; agreement with the specification does.
"""

from __future__ import annotations

import base64
import hashlib

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from dwaar.crypto import http_sig

# A fixed key. Not derived, so this file is self-contained and a change to the derivation
# scheme cannot silently change what these vectors assert.
SEED = bytes(range(32))
KEY = Ed25519PrivateKey.from_private_bytes(SEED)
PUBLIC = KEY.public_key().public_bytes_raw()

BODY = b'{"amount_paise":124000}'
CREATED = 1_767_225_600
NONCE = "0123456789abcdef"
KEYID = "agt_000000000001"

PARAMS = http_sig.SignatureParams(keyid=KEYID, created=CREATED, nonce=NONCE, alg="ed25519")


# ── known answers ───────────────────────────────────────────────────────────────────

def test_content_digest_is_rfc_9530():
    """``sha-256=:<base64>:`` — the colons are part of the structured-field syntax."""
    expected = base64.b64encode(hashlib.sha256(BODY).digest()).decode()
    assert http_sig.content_digest(BODY) == f"sha-256=:{expected}:"


def test_signature_base_is_pinned_byte_for_byte():
    """Hand-constructed from RFC 9421 §2.5, not from the code under test.

    The trailing detail — no newline after the ``@signature-params`` line — is the one
    every independent implementation gets wrong first, and it is asserted here rather than
    trusted.
    """
    digest = http_sig.content_digest(BODY)
    expected = (
        '"@method": POST\n'
        '"@path": /v1/authorize\n'
        f'"content-digest": {digest}\n'
        '"@signature-params": ("@method" "@path" "content-digest")'
        f';created={CREATED};keyid="{KEYID}";nonce="{NONCE}";alg="ed25519"'
    ).encode()

    assert http_sig.build_signature_base("POST", "/v1/authorize", digest, PARAMS) == expected
    assert not expected.endswith(b"\n"), "the signature base must not end with a newline"


def test_signature_base_covers_the_method():
    """Without ``@method`` a signed POST could be replayed as a DELETE."""
    digest = http_sig.content_digest(BODY)
    post = http_sig.build_signature_base("POST", "/v1/authorize", digest, PARAMS)
    delete = http_sig.build_signature_base("DELETE", "/v1/authorize", digest, PARAMS)
    assert post != delete


def test_signature_base_covers_the_path():
    """Without ``@path`` a signature is portable between endpoints."""
    digest = http_sig.content_digest(BODY)
    a = http_sig.build_signature_base("POST", "/v1/authorize", digest, PARAMS)
    b = http_sig.build_signature_base("POST", "/v1/refund", digest, PARAMS)
    assert a != b


def test_headers_round_trip_through_the_parser():
    headers = http_sig.sign_request(
        KEY, method="POST", path="/v1/authorize", body=BODY,
        keyid=KEYID, created=CREATED, nonce=NONCE,
    )
    label, params, components = http_sig.parse_signature_input(headers["Signature-Input"])
    assert label == http_sig.SIG_LABEL
    assert params == PARAMS
    assert components == http_sig.COVERED_COMPONENTS
    assert len(http_sig.parse_signature(headers["Signature"], label)) == 64


def _headers(**overrides):
    headers = http_sig.sign_request(
        KEY, method="POST", path="/v1/authorize", body=BODY,
        keyid=KEYID, created=CREATED, nonce=NONCE,
    )
    headers.update(overrides)
    return headers


def _verify(headers=None, body=BODY, method="POST", path="/v1/authorize", keys=None, now=CREATED):
    return http_sig.verify_request(
        method=method, path=path, body=body,
        headers=headers if headers is not None else _headers(),
        public_keys=keys if keys is not None else [PUBLIC],
        now=now,
    )


# ── the happy path ──────────────────────────────────────────────────────────────────

def test_a_valid_signature_verifies():
    verified = _verify()
    assert verified.params.keyid == KEYID
    assert verified.params.nonce == NONCE
    assert verified.key_index == 0


def test_the_matching_key_index_is_reported():
    """Rotation needs to know WHICH credential was used, and it cannot infer it."""
    other = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33))).public_key()
    verified = _verify(keys=[other.public_bytes_raw(), PUBLIC])
    assert verified.key_index == 1


# ── negative cases, one per thing the signature is supposed to bind ─────────────────

def test_a_changed_body_fails():
    """The whole reason Content-Digest is covered: signing headers alone authenticates the
    envelope and leaves the amount free to change."""
    with pytest.raises(http_sig.SignatureError, match="Content-Digest does not match"):
        _verify(body=b'{"amount_paise":99900000}')


def test_a_forged_digest_header_fails():
    """An attacker who rewrites both the body and the digest still fails, because the
    digest is inside the signature base."""
    hostile = b'{"amount_paise":99900000}'
    with pytest.raises(http_sig.SignatureError):
        _verify(headers=_headers(**{"Content-Digest": http_sig.content_digest(hostile)}),
                body=hostile)


def test_a_different_method_fails():
    with pytest.raises(http_sig.SignatureError, match="does not verify"):
        _verify(method="DELETE")


def test_a_different_path_fails():
    with pytest.raises(http_sig.SignatureError, match="does not verify"):
        _verify(path="/v1/refund")


def test_a_wrong_key_fails():
    other = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33))).public_key()
    with pytest.raises(http_sig.SignatureError, match="does not verify"):
        _verify(keys=[other.public_bytes_raw()])


def test_an_expired_signature_fails():
    with pytest.raises(http_sig.SignatureError, match="outside the"):
        _verify(now=CREATED + http_sig.DEFAULT_SKEW_SECONDS + 1)


def test_a_future_signature_fails():
    """Clock skew cuts both ways, and a far-future `created` would otherwise extend the
    replay window arbitrarily."""
    with pytest.raises(http_sig.SignatureError, match="in the future"):
        _verify(now=CREATED - http_sig.DEFAULT_SKEW_SECONDS - 1)


def test_the_skew_boundary_is_inclusive():
    _verify(now=CREATED + http_sig.DEFAULT_SKEW_SECONDS)
    _verify(now=CREATED - http_sig.DEFAULT_SKEW_SECONDS)


@pytest.mark.parametrize("missing", ["Signature-Input", "Signature", "Content-Digest"])
def test_a_missing_header_fails(missing):
    headers = _headers()
    del headers[missing]
    with pytest.raises(http_sig.SignatureError, match="missing required header"):
        _verify(headers=headers)


def test_a_reduced_covered_set_is_refused():
    """An attacker who could choose which components are covered would cover none of the
    ones that matter. The set is fixed, not merely checked for presence."""
    headers = _headers(**{
        "Signature-Input": f'sig1=("@method");created={CREATED};keyid="{KEYID}";alg="ed25519"'
    })
    with pytest.raises(http_sig.SignatureError, match="do not match the required set"):
        _verify(headers=headers)


def test_an_unsupported_algorithm_is_refused():
    headers = _headers(**{
        "Signature-Input": (
            f'sig1=("@method" "@path" "content-digest");created={CREATED}'
            f';keyid="{KEYID}";nonce="{NONCE}";alg="rsa-pss-sha512"'
        )
    })
    with pytest.raises(http_sig.SignatureError, match="unsupported algorithm"):
        _verify(headers=headers)


@pytest.mark.parametrize(
    "header",
    [
        "",
        "no-equals-sign",
        'sig1=not-parentheses;created=1',
        'sig1=("@method" "@path" "content-digest");keyid="x";alg="ed25519"',   # no created
        'sig1=("@method" "@path" "content-digest");created=x;keyid="y";alg="ed25519"',
    ],
)
def test_malformed_signature_input_is_refused(header):
    """This parser runs before authentication on attacker-controlled input, so it is strict
    rather than forgiving."""
    with pytest.raises(http_sig.SignatureError):
        http_sig.parse_signature_input(header)


@pytest.mark.parametrize("value", ["sig1=notcolons", "sig1=::", "sig2=:AAAA:", "sig1=:!!!!:"])
def test_malformed_signature_is_refused(value):
    with pytest.raises(http_sig.SignatureError):
        http_sig.parse_signature(value, "sig1")


def test_a_truncated_signature_is_refused():
    short = base64.b64encode(b"\x00" * 32).decode()
    with pytest.raises(http_sig.SignatureError, match="64 bytes"):
        http_sig.parse_signature(f"sig1=:{short}:", "sig1")
