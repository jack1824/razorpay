# zoo/ — agent archetypes for evaluation

**This code targets `localhost` only. It is not a general-purpose attack tool and it must
never be pointed at a host you do not own.** Every agent here refuses to run against a
non-loopback target; that check is in the agent base class, not in this README.

`zoo/` exists to generate evaluation traffic against a local Dwaar instance: six
archetypes making *real signed HTTP calls*, not replayed fixtures.

## Structural rule

`dwaar/` must never import from `zoo/`. Enforced by `tests/test_import_isolation.py`,
which walks the transitive import closure of every `dwaar.*` module and fails the build on
any path reaching `zoo`.

The reverse direction is permitted: `zoo/` imports `dwaar.crypto` so the agents sign the
way the gateway verifies. Correctness against RFC 9421 and RFC 8785 is pinned by
known-answer vectors in `tests/`, not by the two sides agreeing with each other — if both
used the same wrong implementation, shared code would hide it and the vectors would not.

## Status

Empty. Agents land on day 8 per `docs/strategy/BUILD_PLAN.md`. Two of the six
(`compromised`, `sleeper`) are written by a different author and held out from the model
until day 12.
