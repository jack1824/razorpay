"""RFC 8785 JSON Canonicalization Scheme.

The signature over a mandate covers *bytes*, not a Python object, so signer and verifier
must agree on exactly one serialisation. JCS is that agreement: sorted keys by UTF-16 code
unit, no insignificant whitespace, and a specified number format.

This lands ahead of the day-4 crypto layer because ``tools/gen_seed.py`` cannot produce a
loadable mandate fixture without it — ``canonical_json``, ``signature`` and ``mandate_hash``
are all ``NOT NULL``. Day 4 builds RFC 9421 and the chain signer around this module rather
than beside it: two implementations of a canonicaliser that must agree is the same masking
problem that makes shared signing code between ``dwaar/`` and ``zoo/`` a bad idea.

Scope, stated so nobody assumes more: this implements the subset Dwaar actually signs —
objects, arrays, strings, integers, booleans, null. **Floats raise.** That is not a gap; no
value Dwaar signs is a float. Money is integer paise, and a float creeping into a signed
payload would be a bug worth failing on rather than canonicalising.
"""

from __future__ import annotations

import json
from typing import Any

# JSON string escapes required by RFC 8785 section 3.2.2.2. Everything else that needs
# escaping is a control character, handled by the \u fallback below.
_ESCAPES = {
    '"': '\\"',
    "\\": "\\\\",
    "\b": "\\b",
    "\f": "\\f",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
}


def _escape_string(value: str) -> str:
    out = ['"']
    for char in value:
        if char in _ESCAPES:
            out.append(_ESCAPES[char])
        elif ord(char) < 0x20:
            out.append(f"\\u{ord(char):04x}")
        else:
            out.append(char)
    out.append('"')
    return "".join(out)


def _canonical(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return _escape_string(value)
    if isinstance(value, int):
        # bool is a subclass of int, already handled above.
        return str(value)
    if isinstance(value, float):
        raise TypeError(
            "JCS: floats are not permitted in a signed Dwaar payload. Money is integer "
            f"paise and every other signed field is an int, string, bool, array or object. "
            f"Got {value!r}."
        )
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_canonical(item) for item in value) + "]"
    if isinstance(value, dict):
        # RFC 8785 sorts by the UTF-16 code units of the key. Python compares str by
        # code point, which differs only for keys containing astral-plane characters —
        # encoding to UTF-16BE makes the two agree for every input.
        items = sorted(value.items(), key=lambda kv: kv[0].encode("utf-16-be"))
        return "{" + ",".join(f"{_escape_string(k)}:{_canonical(v)}" for k, v in items) + "}"
    raise TypeError(f"JCS: unsupported type {type(value).__name__}")


def canonicalize(value: Any) -> str:
    """Return the RFC 8785 canonical JSON string for ``value``."""
    return _canonical(value)


def canonicalize_bytes(value: Any) -> bytes:
    """Canonical JSON as UTF-8 bytes — what actually gets hashed and signed."""
    return canonicalize(value).encode("utf-8")


def loads_and_canonicalize(raw: str) -> str:
    """Parse then re-canonicalise. Used when verifying a stored ``canonical_json``."""
    return canonicalize(json.loads(raw))
