"""Agent archetypes that generate evaluation traffic against a LOCAL Dwaar instance.

Every agent here makes **real signed HTTP calls**. Nothing in this package fabricates a
trace, constructs a feature vector, or writes a decision record. The gateway sees requests
and produces its own features, its own score and its own chain — which is the only
arrangement in which the resulting numbers describe the system rather than the generator.

`dwaar/` must never import from here. Enforced by `tests/test_import_isolation.py`. The
reverse is permitted and used: the agents sign with `dwaar.crypto` so they sign the way the
gateway verifies, and correctness against RFC 9421 and RFC 8785 is pinned by known-answer
vectors in `tests/` rather than by the two sides agreeing with each other.

**Localhost only.** `zoo/base.py` refuses any non-loopback target, in the base class rather
than in a README.
"""
