"""The agent base class: loopback enforcement, signing, and the request loop.

── Loopback only, and it is enforced here ──────────────────────────────────────────────

Every agent refuses to run against a non-loopback target. The check lives in this class
rather than in a README because a README is not a control. This package generates traffic
that is deliberately abusive — rapid small charges against many card BINs, instruction-shaped
payloads, repeated cap probing — and the only thing separating "evaluation harness" from
"attack tool" is where it points.

── Why real HTTP and real signatures ───────────────────────────────────────────────────

Every request is Ed25519-signed per RFC 9421, carries a Content-Digest per RFC 9530, and
travels over the wire to a running gateway. Nothing here builds a feature vector or a
decision record.

Fabricated traces would have made the evaluation measure the generator. Real requests mean
the gateway computes its own features from its own rolling windows, scores them with its own
model and writes its own chain, so a number in the eval table is a fact about the system.

It also means the adversarial agents have to *actually work*: an agent whose signature does
not verify gets a 401 and produces no behavioural evidence at all, which is a much harder
thing to fake accidentally than a plausible-looking CSV.

── Determinism ─────────────────────────────────────────────────────────────────────────

Every random draw comes from a seeded `random.Random` owned by the agent. Two runs with the
same seed issue the same requests in the same order with the same amounts, SKUs and gaps.
Wall-clock timing is the one thing that cannot be reproduced exactly, and it is the reason
the gateway's `now` is its own rather than anything an agent supplies.
"""

from __future__ import annotations

import json
import random
import uuid
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

import httpx

from dwaar import clock
from dwaar.crypto import http_sig
from dwaar.crypto import keys as keymod

LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1", "[::1]", "0.0.0.0"})

AUTHORIZE_PATH = "/v1/authorize"


class NonLoopbackTarget(RuntimeError):
    """Raised when an agent is pointed anywhere but the local machine."""


def assert_loopback(base_url: str) -> None:
    host = (urlparse(base_url).hostname or "").lower()
    if host not in LOOPBACK_HOSTS:
        raise NonLoopbackTarget(
            f"zoo agents target localhost only; refused {base_url!r} (host {host!r}).\n"
            "This package generates deliberately abusive traffic. Pointing it at a host "
            "you do not own is the difference between an evaluation harness and an attack."
        )


@dataclass
class Attempt:
    """One request and what came back. Written to the run manifest, never to the gateway."""

    agent_id: str
    sent_at: float
    amount_paise: int
    category: str | None
    sku: str | None
    idempotency_key: str
    status_code: int
    decision: str | None
    reason_code: str | None
    decision_id: str | None
    latency_us: int | None
    error: str | None = None

    #: Whether the simulated PSP accepted the card. Only meaningful when the gateway
    #: allowed the request; `None` means no payment was attempted.
    payment_succeeded: bool | None = None


@dataclass
class AgentIdentity:
    agent_id: str
    principal_id: str
    mandate_id: str
    seed: int
    """HKDF seed the private key is derived from — the same mechanism the gateway uses for
    every other keypair in this project, so the whole system is reproducible from integers."""


class Agent:
    """One archetype, one identity, one seeded RNG.

    Subclasses implement `next_request()` and `next_gap()`. Everything about signing,
    transport, retry policy (there is none) and bookkeeping is here, so an archetype is a
    statement about *behaviour* and nothing else — which is what keeps the archetypes
    comparable.
    """

    #: Overridden by each subclass. Used only in the run manifest, which the gateway never
    #: reads. `tests/test_ground_truth_isolation.py` asserts this string cannot appear
    #: anywhere under `dwaar/`.
    name: str = "base"

    #: Requests this archetype makes, relative to the run's `--requests`.
    #:
    #: A card tester arrives 20x faster than a shopper, so in the same wall clock it makes
    #: far more attempts. Forcing every archetype to the same COUNT would make the run as
    #: slow as its slowest agent while under-sampling its busiest — and it would flatten
    #: the very rate difference the cadence features exist to measure.
    request_multiplier: float = 1.0

    def __init__(
        self,
        identity: AgentIdentity,
        *,
        base_url: str,
        seed: int,
        catalogue: list[Any],
        requests: int,
    ) -> None:
        assert_loopback(base_url)
        self.identity = identity
        self.base_url = base_url.rstrip("/")
        self.rng = random.Random(seed)
        self.catalogue = catalogue
        self.requests = requests
        self.attempts: list[Attempt] = []
        self._private = keymod.derive_private_key(
            identity.seed, "agent", identity.agent_id
        )
        self._sequence = 0

    # ── to implement ────────────────────────────────────────────────────────────────

    def next_request(self) -> dict[str, Any]:
        """The body of the next request, minus `idempotency_key`."""
        raise NotImplementedError

    def next_gap(self) -> float:
        """Seconds to wait before the next request. Real seconds, not simulated ones.

        Cadences are chosen to be realistic **for an autonomous agent**, which is not a
        realistic cadence for a human. No time compression is applied anywhere: a feature
        window is wall-clock, so compressing the generator and not the demo would train the
        model on velocities it never sees again.
        """
        raise NotImplementedError

    def payment_would_succeed(self) -> bool:
        """Whether the simulated PSP accepts this attempt.

        Stands in for the settlement webhook until Razorpay test mode lands. The outcome is
        the agent's *card* failing, never its authorization failing — the gateway's own
        denials must never feed a feature, or the model would learn to predict the
        arithmetic gate.
        """
        return True

    # ── the loop ────────────────────────────────────────────────────────────────────

    def _sign(self, body: bytes) -> dict[str, str]:
        return http_sig.sign_request(
            self._private,
            method="POST",
            path=AUTHORIZE_PATH,
            body=body,
            keyid=self.identity.agent_id,
            created=clock.unix(),
            nonce=uuid.uuid4().hex,
        )

    def build_body(self) -> dict[str, Any]:
        self._sequence += 1
        payload = self.next_request()
        payload.setdefault("agent_id", self.identity.agent_id)
        payload.setdefault("mandate_id", self.identity.mandate_id)
        payload.setdefault("action", "purchase")
        # Unique per attempt: a repeated key is a replay, and the gateway would correctly
        # return the first decision verbatim. That is a property worth testing, and it is
        # tested elsewhere; here it would silently halve the traffic.
        payload["idempotency_key"] = f"{self.name[:4]}-{uuid.uuid4().hex[:20]}"
        return payload

    async def send(self, client: httpx.AsyncClient, payload: dict[str, Any]) -> Attempt:
        body = json.dumps(payload, separators=(",", ":")).encode()
        headers = self._sign(body)
        headers["Content-Type"] = "application/json"

        # An INSTANT, recorded in the manifest — so it comes from the seam. The
        # response's own `latency_us` is the duration; this is not measuring one.
        sent_at = clock.now().timestamp()
        try:
            response = await client.post(
                f"{self.base_url}{AUTHORIZE_PATH}", content=body, headers=headers
            )
        except Exception as exc:  # noqa: BLE001 — a transport failure is data, not a crash
            return Attempt(
                agent_id=self.identity.agent_id,
                sent_at=sent_at,
                amount_paise=payload["amount_paise"],
                category=payload.get("category"),
                sku=payload.get("sku"),
                idempotency_key=payload["idempotency_key"],
                status_code=0,
                decision=None,
                reason_code=None,
                decision_id=None,
                latency_us=None,
                error=f"{type(exc).__name__}: {exc}",
            )

        parsed: dict[str, Any] = {}
        try:
            parsed = response.json()
        except Exception:  # noqa: BLE001
            parsed = {}

        return Attempt(
            agent_id=self.identity.agent_id,
            sent_at=sent_at,
            amount_paise=payload["amount_paise"],
            category=payload.get("category"),
            sku=payload.get("sku"),
            idempotency_key=payload["idempotency_key"],
            status_code=response.status_code,
            decision=parsed.get("decision"),
            reason_code=parsed.get("reason_code"),
            decision_id=parsed.get("decision_id"),
            latency_us=parsed.get("latency_us"),
        )


@dataclass
class BinPool:
    """Card BINs an agent draws from.

    A legitimate agent has one or two — a principal's saved cards. A card tester has many,
    and that difference is the whole of `bin_diversity`. The values are the standard test
    prefixes; they are hashed by the gateway before they are stored anywhere.
    """

    bins: list[str] = field(default_factory=list)

    def draw(self, rng: random.Random) -> str:
        return rng.choice(self.bins)


#: Razorpay/major-network test prefixes. Real BINs are not used and are not needed: the
#: gateway hashes them and counts distinct values, so any six digits with the right
#: cardinality produce the same feature.
TEST_BINS = [
    "411111", "424242", "521234", "555555", "601111", "353011",
    "402400", "455673", "540123", "622018", "356001", "379100",
    "434256", "491652", "512345", "676770", "356789", "401288",
]
