"""Stage 1 — RFC 9421 request signature verification.  [REAL]

Budget 0.3ms. **Fail-closed**: identity is not optional.

Three things must hold, and each closes a hole the others leave open:

1. **The signature verifies** against a key registered for this agent. Proves who sent it.
2. **The Content-Digest matches the body we received.** Proves the bytes were not swapped
   under a valid signature. Signing headers alone authenticates the envelope and leaves the
   amount free to change.
3. **The nonce has not been seen.** `created` bounds replay to ±120s, which without a nonce
   is 120 seconds of free replays.

── Key rotation ────────────────────────────────────────────────────────────────────────

Both the current and previous keys are accepted while ``key_rotated_at`` is inside the
overlap window. Without that, every rotation rejects requests already in flight — and a
rotation is exactly what you do when you suspect a key is compromised, so making it disruptive
makes people delay it.

Outside the window the previous key is refused, so the overlap is a window and not a
permanent second credential.

── A suspended agent is refused here, not later ────────────────────────────────────────

`agents.status` had no enforcement point at all before this. A revoked agent could still
authorize, because nothing read the column. It is checked as part of identity, which is
where "this agent may not act" belongs.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from psycopg import AsyncConnection

from dwaar import clock
from dwaar.authorize.types import AuthorizeRequest, SignatureResult
from dwaar.config import Settings
from dwaar.crypto import http_sig
from dwaar.db.repositories import agents as agent_repo
from dwaar.nonce import NonceStore

STAGE_NAME = "verify_signature"

# How long the previous key stays acceptable after a rotation.
KEY_OVERLAP = timedelta(minutes=15)

REASON_UNKNOWN_AGENT = "agent_unknown"
REASON_AGENT_NOT_ACTIVE = "agent_not_active"
REASON_KEYID_MISMATCH = "keyid_does_not_match_agent"
REASON_REPLAYED = "nonce_replayed"
REASON_NO_NONCE = "nonce_missing"


async def verify_signature(
    request: AuthorizeRequest,
    headers: dict[str, str],
    *,
    settings: Settings,
    conn: AsyncConnection,
    body: bytes = b"",
    method: str = "POST",
    path: str = "/v1/authorize",
    nonce_store: NonceStore | None = None,
    now: datetime | None = None,
) -> SignatureResult:
    agent = await agent_repo.get(conn, request.agent_id)
    if agent is None:
        return SignatureResult(ok=False, internal_reason=REASON_UNKNOWN_AGENT)
    if agent["status"] != "active":
        return SignatureResult(
            ok=False, internal_reason=f"{REASON_AGENT_NOT_ACTIVE}:{agent['status']}"
        )

    # Index 0 is always the current key. The previous key is appended only while the
    # rotation overlap window is open, so it is a window and not a second permanent
    # credential.
    acceptable: list[bytes] = [bytes(agent["public_key"])]
    rotated_at = agent["key_rotated_at"]
    reference = now or clock.now()
    if (
        agent["previous_public_key"] is not None
        and rotated_at is not None
        and reference - rotated_at <= KEY_OVERLAP
    ):
        acceptable.append(bytes(agent["previous_public_key"]))

    try:
        verified = http_sig.verify_request(
            method=method,
            path=path,
            body=body,
            headers=headers,
            public_keys=acceptable,
            # The SAME clock the rotation-overlap check above uses.
            #
            # This previously defaulted to `time.time()` while `reference` came from the
            # caller, so one function held two notions of "now" — the rotation window moved
            # with the pipeline's clock and the skew window did not. Nothing had gone wrong
            # yet; a benchmark that advanced the pipeline's clock found it, because its
            # signatures were then rejected as 127 seconds in the future by a check reading a
            # different clock than the one that stamped them.
            #
            # It does not weaken the skew control. `now` originates in
            # `dwaar/authorize/pipeline.py` as `datetime.now(UTC)` for every request that
            # arrives over HTTP; only an in-process caller can supply another value, and an
            # in-process caller could call `verify_request` directly regardless.
            now=int(reference.timestamp()),
        )
    except http_sig.SignatureError as exc:
        return SignatureResult(ok=False, internal_reason=str(exc))

    params = verified.params

    # keyid must name the agent making the request. Without this an agent could present a
    # valid signature made by a *different* agent's key and have it accepted, because the
    # key list is built from the claimed agent_id.
    if params.keyid != request.agent_id:
        return SignatureResult(
            ok=False,
            internal_reason=f"{REASON_KEYID_MISMATCH}: {params.keyid} != {request.agent_id}",
        )

    if params.nonce is None:
        return SignatureResult(ok=False, internal_reason=REASON_NO_NONCE)

    # Raises NonceStoreUnavailable if Redis is unreachable: we cannot tell a first use
    # from a replay, and guessing would be fail-open on identity.
    if nonce_store is not None and not await nonce_store.claim(request.agent_id, params.nonce):
        return SignatureResult(ok=False, internal_reason=REASON_REPLAYED)

    return SignatureResult(
        ok=True,
        agent_id=request.agent_id,
        key_used="current" if verified.key_index == 0 else "previous",
    )
