"""Cryptographic primitives: canonicalisation, keys, mandate payloads.

Lands ahead of the day-4 crypto layer only as far as the seed generator needs it —
``tools/gen_seed.py`` cannot emit a loadable mandate fixture without JCS and a signing key,
because ``canonical_json``, ``signature`` and ``mandate_hash`` are all ``NOT NULL``.

Day 4 adds RFC 9421 request-signature verification, the decision-record signer, and the
standalone verifier CLI **around** these modules rather than beside them. One
canonicaliser, one place.

Nothing here is imported by the request path yet.
"""
