"""Rolling behavioural windows in Redis.

── The key, which is the load-bearing decision in this file ────────────────────────────

Windows are keyed on **(agent_id, principal_id)** and on nothing else. Never IP. Never
device fingerprint. Never user-agent, TLS fingerprint or any other network identity.

This is not a privacy gesture, it is an accuracy argument, and it is the concrete reason a
fraud engine's feature set does not transfer to this problem. A card-fraud model leans hard
on network identity because a human cardholder sits behind one device and one address, so a
sudden change is signal. An agent platform is the opposite shape: one platform serves
millions of unrelated principals from a handful of egress addresses. Key on IP and every
agent on that platform shares one window — the features average across strangers, the
variance collapses, and "unusual for this IP" stops meaning anything at all. The feature
does not merely get weaker; it degenerates to a constant.

The pair is the right grain because authority is granted per (agent, principal): a mandate
names both. Two principals delegating to the same agent platform are different actors with
different normal behaviour, and one principal using two agents likewise. Anything coarser
mixes actors; anything finer has no history.

── What is stored ──────────────────────────────────────────────────────────────────────

Numerics and truncated hashes only. Raw SKUs, free text and card BINs never enter Redis and
never reach the append-only record — `decision_records.features` is hash-chained and cannot
be purged, so a raw agent-supplied string landing there would be unrecoverable by design.
A BIN is hashed before it is stored: BIN *diversity* is the signal, and the digits
themselves are not needed to count distinct values.

── Failure ─────────────────────────────────────────────────────────────────────────────

Redis down means an empty window, a degradation token, and a decision made by the gate, the
policy and the ledger — all of which are in PostgreSQL. This store **degrades**, it does not
fail closed. That is the opposite of `dwaar/nonce.py`, which is also Redis and does fail
closed, and the difference is the whole taxonomy: the nonce store answers a question about
*authentication*, and this one answers a question about *judgment*.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from dwaar.logging import get_logger

log = get_logger("dwaar.risk.observations")

OBS_PREFIX = "dwaar:obs"
PAY_PREFIX = "dwaar:pay"

#: Entries kept per key. One hour of a busy agent at ~2 requests/minute, with headroom for
#: the burst the card tester creates. Bounded because this is a fixed-cost data structure:
#: an unbounded list keyed on an agent-supplied pair is a memory-exhaustion surface.
WINDOW_MAX = 256

#: Seconds before an idle window disappears. Longer than the longest feature window (1h) so
#: no feature can read a truncated history and report it as a quiet period.
WINDOW_TTL = 7200

#: Payment outcomes kept per key. Smaller than the observation window: a failure ratio over
#: 64 attempts is already a stable estimate, and card testing produces far more attempts
#: than a legitimate agent ever will.
OUTCOME_MAX = 64


@dataclass(frozen=True, slots=True)
class Observation:
    """One request attempt. Deliberately small, and deliberately not a request.

    `sku_hash`, `bin_hash` and `cart_hash` are truncated SHA-256, not values. Counting
    distinct things does not require knowing what they are, and this record is written to a
    store we cannot purge.
    """

    ts: float
    amount_paise: int
    category: str | None
    sku_hash: str | None
    bin_hash: str | None
    cart_hash: str | None

    def to_json(self) -> str:
        # A positional array rather than an object: 256 of these are read on every request,
        # and the key names would be two thirds of the bytes.
        return json.dumps(
            [self.ts, self.amount_paise, self.category, self.sku_hash, self.bin_hash,
             self.cart_hash],
            separators=(",", ":"),
        )

    @classmethod
    def from_json(cls, raw: str | bytes) -> Observation:
        ts, amount, category, sku, bin_, cart = json.loads(raw)
        return cls(float(ts), int(amount), category, sku, bin_, cart)


def short_hash(value: str | None, *, salt: str = "") -> str | None:
    """Truncated SHA-256, hex. `None` in, `None` out.

    Twelve hex characters. Long enough that a collision inside a 256-entry window is
    negligible, short enough that the window stays small. It is not a security boundary —
    a BIN has only a million possibilities and is trivially enumerable — it is a way of not
    carrying values we have no use for into a store that cannot forget them.
    """
    if value is None:
        return None
    return hashlib.sha256(f"{salt}{value}".encode()).hexdigest()[:12]


def observation_from_request(request: Any, *, now: float) -> Observation:
    """Build the observation for a request. The only place request fields are read.

    `amount_paise` is recorded and the mandate's caps are not, because this file has no
    access to a mandate and must not acquire one — see `dwaar/risk/features.py`.
    """
    return Observation(
        ts=now,
        amount_paise=int(request.amount_paise or 0),
        category=getattr(request, "category", None),
        sku_hash=short_hash(getattr(request, "sku", None), salt="sku:"),
        bin_hash=short_hash(getattr(request, "instrument_bin", None), salt="bin:"),
        cart_hash=short_hash(getattr(request, "cart_id", None), salt="cart:"),
    )


def _key(prefix: str, agent_id: str, principal_id: str) -> str:
    return f"{prefix}:{agent_id}:{principal_id}"


@dataclass(frozen=True)
class WindowSnapshot:
    """What the feature stage gets. `available=False` means Redis, not "no history"."""

    observations: tuple[Observation, ...]
    outcomes: tuple[bool, ...]
    available: bool = True

    @property
    def is_empty(self) -> bool:
        return not self.observations and not self.outcomes


EMPTY = WindowSnapshot((), (), available=False)


class RedisObservationStore:
    """Read the window and append to it in one round trip.

    The read happens **before** the append, so a request never contributes to its own
    history. Both are issued in a single pipeline: two round trips per authorize would be
    two chances to blow a 25ms budget on a network hiccup.
    """

    def __init__(self, redis: Any) -> None:
        self._redis = redis

    async def observe(
        self, *, agent_id: str, principal_id: str, observation: Observation
    ) -> WindowSnapshot:
        obs_key = _key(OBS_PREFIX, agent_id, principal_id)
        pay_key = _key(PAY_PREFIX, agent_id, principal_id)
        try:
            pipe = self._redis.pipeline(transaction=False)
            pipe.lrange(obs_key, 0, WINDOW_MAX - 1)
            pipe.lrange(pay_key, 0, OUTCOME_MAX - 1)
            pipe.lpush(obs_key, observation.to_json())
            pipe.ltrim(obs_key, 0, WINDOW_MAX - 1)
            pipe.expire(obs_key, WINDOW_TTL)
            raw_obs, raw_pay = (await pipe.execute())[:2]
        except Exception as exc:  # noqa: BLE001 — judgment degrades, it never denies
            log.warning(
                "observation_window_unavailable",
                error_type=type(exc).__name__,
                agent_id=agent_id,
            )
            return EMPTY

        return WindowSnapshot(
            observations=tuple(_decode(raw) for raw in raw_obs if _decode(raw) is not None),
            outcomes=tuple(bytes(raw) == b"1" for raw in raw_pay),
        )

    async def record_outcome(
        self, *, agent_id: str, principal_id: str, succeeded: bool
    ) -> bool:
        """A payment attempt's outcome, from the PSP.

        Kept in its own list rather than patched into the matching observation, which would
        need a read-modify-write against a list another request may be pushing to. The
        failure ratio is an aggregate; it does not need attempts and outcomes aligned.

        **This is never called with agent-supplied data.** A card tester reporting its own
        decline rate would be the model asking the adversary for the answer. The writer is
        the settlement webhook — Razorpay's in test mode, and the simulator's stand-in
        before that.
        """
        pay_key = _key(PAY_PREFIX, agent_id, principal_id)
        try:
            pipe = self._redis.pipeline(transaction=False)
            pipe.lpush(pay_key, b"1" if succeeded else b"0")
            pipe.ltrim(pay_key, 0, OUTCOME_MAX - 1)
            pipe.expire(pay_key, WINDOW_TTL)
            await pipe.execute()
            return True
        except Exception as exc:  # noqa: BLE001
            log.warning("outcome_record_failed", error_type=type(exc).__name__)
            return False


def _decode(raw: bytes | str) -> Observation | None:
    try:
        return Observation.from_json(raw)
    except Exception:  # noqa: BLE001
        # A malformed entry is a corrupt cache, not a reason to fail a payment.
        return None


class InMemoryObservationStore:
    """Test double, and the fallback when no Redis is configured.

    Named so that using it in production is a visible choice rather than a default. Under
    `uvicorn --workers 4` this is four disjoint windows, so every feature is computed from a
    quarter of the traffic — the same defect as an in-process nonce set, with a quieter
    symptom.
    """

    def __init__(self) -> None:
        self._obs: dict[str, list[Observation]] = {}
        self._pay: dict[str, list[bool]] = {}

    async def observe(
        self, *, agent_id: str, principal_id: str, observation: Observation
    ) -> WindowSnapshot:
        key = _key(OBS_PREFIX, agent_id, principal_id)
        prior = tuple(self._obs.get(key, ()))
        self._obs[key] = [observation, *prior][:WINDOW_MAX]
        return WindowSnapshot(
            observations=prior,
            outcomes=tuple(self._pay.get(_key(PAY_PREFIX, agent_id, principal_id), ())),
        )

    async def record_outcome(
        self, *, agent_id: str, principal_id: str, succeeded: bool
    ) -> bool:
        key = _key(PAY_PREFIX, agent_id, principal_id)
        self._pay[key] = [succeeded, *self._pay.get(key, ())][:OUTCOME_MAX]
        return True
