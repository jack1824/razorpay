"""Per-request nonce store. Replay defence (threat 2, FAILURES.md F-005).

`created` alone bounds replay to the skew window — which is 120 seconds of *free replays*.
The nonce closes that: each is accepted exactly once.

── Why Redis and not PostgreSQL ────────────────────────────────────────────────────────

Nonces are behavioural state with a TTL, not authority. Losing them degrades replay defence
for one skew window; losing authority state would be a different class of problem. That is
the same split the architecture uses everywhere: Postgres holds what must be durable, Redis
holds what must be fast and may expire.

An in-process set was rejected. Under ``uvicorn --workers 4`` it is four disjoint sets, so a
replay simply lands on a different worker — a control that works only at concurrency 1,
which is precisely the configuration we do not run.

── Why the store fails CLOSED ──────────────────────────────────────────────────────────

Redis down means we cannot tell a first-use from a replay. Threat 2 is replay of a signed
request, so answering "probably fine" here would be fail-open on identity. The rest of the
Redis surface (rolling windows, rate limits) degrades open because it is judgment; this one
does not, because it is authentication.
"""

from __future__ import annotations

from typing import Protocol

from redis.asyncio import Redis

from dwaar.errors import DwaarError

# Twice the skew window: a nonce only needs to outlive the period in which its signature is
# still temporally valid. Longer wastes memory; shorter reopens the replay hole at the edge.
DEFAULT_TTL_SECONDS = 240

_PREFIX = "dwaar:nonce"


class NonceReplayed(DwaarError):
    public_reason = "denied"
    status_code = 401


class NonceStoreUnavailable(DwaarError):
    """Fail-closed: we cannot distinguish a first use from a replay."""

    public_reason = "unavailable"
    status_code = 503


class NonceStore(Protocol):
    async def claim(self, agent_id: str, nonce: str) -> bool:
        """True if this nonce is being used for the first time by this agent."""
        ...


class RedisNonceStore:
    """`SET key 1 NX EX ttl` — atomic claim-or-fail in one round trip.

    Keyed on ``(agent_id, nonce)`` rather than the nonce alone, so one agent cannot burn
    another agent's nonce space. Same reasoning as the mandate-scoped idempotency key.
    """

    def __init__(self, redis: Redis, *, ttl_seconds: int = DEFAULT_TTL_SECONDS) -> None:
        self._redis = redis
        self._ttl = ttl_seconds

    async def claim(self, agent_id: str, nonce: str) -> bool:
        key = f"{_PREFIX}:{agent_id}:{nonce}"
        try:
            return bool(await self._redis.set(key, b"1", nx=True, ex=self._ttl))
        except Exception as exc:  # noqa: BLE001
            raise NonceStoreUnavailable(
                f"nonce store unreachable: {type(exc).__name__}. Cannot distinguish a "
                "first use from a replay, so the request is refused."
            ) from exc


class InMemoryNonceStore:
    """Test double. NOT usable in production — see the module docstring.

    Named to make that obvious at every call site: under multiple workers this is several
    disjoint sets and the control silently stops working.
    """

    def __init__(self) -> None:
        self._seen: set[tuple[str, str]] = set()

    async def claim(self, agent_id: str, nonce: str) -> bool:
        key = (agent_id, nonce)
        if key in self._seen:
            return False
        self._seen.add(key)
        return True
