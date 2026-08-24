"""Loading the live policy: signed, versioned, hot-reloadable.

── What "live" means, enforced in code ─────────────────────────────────────────────────

`approved_by IS NULL` means **not live**, and that is a WHERE clause here, not a convention
somebody remembers. The database also refuses to set `approved_by` on a policy whose
generated tests have not passed (`policies_approved_implies_tested`), so the human gate
cannot be skipped by an application that forgets to check.

── Hot reload without a restart, and without a race ────────────────────────────────────

The cache holds one immutable `LivePolicy` per merchant and is replaced wholesale, never
mutated. A request either sees the old ruleset or the new one — never a half-swapped
ruleset, which under `--workers 4` is the kind of bug that reproduces once a week.

TTL-bounded rather than event-driven: a compiled policy is approved by a human, so seconds
of staleness is not a correctness problem. Redis pub/sub would be a second failure mode for
a component whose whole point is that it keeps working when Redis is gone.

── Failure behaviour ───────────────────────────────────────────────────────────────────

If the store is unreachable, the **last signed version continues serving** — from
`FAIL_MATRIX.md`, and it is safe for a reason worth stating: a policy can only *tighten*.
It cannot grant authority the mandate did not, because it runs after the arithmetic gate
and before the ledger, and neither consults it to permit anything. Serving a stale policy
therefore risks enforcing an out-of-date restriction, not permitting an unauthorised spend.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass

from psycopg import AsyncConnection

from dwaar.logging import get_logger
from dwaar.policy import dsl
from dwaar.policy.dsl import Ruleset

log = get_logger("dwaar.policy")

DEFAULT_TTL_SECONDS = 30.0

#: Reserved. NEVER a real version — `policies.version` starts at 1.
#:   NULL  the engine was never consulted (the arithmetic gate short-circuited)
#:   0     consulted; no approved policy exists for this merchant
#:   >0    the approved version that decided
NO_COMPILED_POLICY = 0


@dataclass(frozen=True)
class LivePolicy:
    version: int
    ruleset: Ruleset | None
    policy_id: str | None
    loaded_at: float

    @property
    def exists(self) -> bool:
        return self.ruleset is not None


EMPTY = LivePolicy(version=NO_COMPILED_POLICY, ruleset=None, policy_id=None, loaded_at=0.0)


class PolicyStore:
    """Per-merchant cache of the live ruleset."""

    def __init__(self, *, ttl_seconds: float = DEFAULT_TTL_SECONDS) -> None:
        self._ttl = ttl_seconds
        self._cache: dict[str, LivePolicy] = {}

    def invalidate(self, merchant_id: str | None = None) -> None:
        """Force a reload. Called by the compiler CLI after an approval."""
        if merchant_id is None:
            self._cache.clear()
        else:
            self._cache.pop(merchant_id, None)

    async def get(self, conn: AsyncConnection, merchant_id: str) -> LivePolicy:
        cached = self._cache.get(merchant_id)
        now = time.monotonic()
        if cached is not None and (now - cached.loaded_at) < self._ttl:
            return cached

        try:
            live = await self._load(conn, merchant_id, now)
        except Exception as exc:  # noqa: BLE001
            if cached is not None:
                # Last signed version continues serving. A policy can only tighten, so a
                # stale one risks an out-of-date restriction, never an unauthorised spend.
                log.warning(
                    "policy_load_failed_serving_cached",
                    merchant_id=merchant_id,
                    policy_version=cached.version,
                    error_type=type(exc).__name__,
                )
                return cached
            raise

        # Replaced wholesale, never mutated: a request sees the old ruleset or the new one,
        # never a half-swapped one.
        self._cache[merchant_id] = live
        return live

    async def _load(self, conn: AsyncConnection, merchant_id: str, now: float) -> LivePolicy:
        async with conn.cursor() as cur:
            await cur.execute(
                "SELECT policy_id, version, compiled_rules FROM policies "
                "WHERE merchant_id = %s AND approved_by IS NOT NULL "
                "ORDER BY version DESC LIMIT 1",
                (merchant_id,),
            )
            row = await cur.fetchone()

        if row is None:
            return LivePolicy(
                version=NO_COMPILED_POLICY, ruleset=None, policy_id=None, loaded_at=now
            )

        policy_id, version, compiled = row
        if version == NO_COMPILED_POLICY:
            # Would make "consulted, none exists" indistinguishable from "version 0 decided".
            raise dsl.PolicyError(
                f"policy {policy_id} has version 0, which is reserved for 'no compiled "
                "policy exists' and must never be a real version"
            )

        rules = compiled if isinstance(compiled, dict) else json.loads(compiled)
        return LivePolicy(
            version=version,
            ruleset=dsl.parse(rules),
            policy_id=policy_id,
            loaded_at=now,
        )
