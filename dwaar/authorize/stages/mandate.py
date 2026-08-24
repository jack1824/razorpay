"""Stage 2 — mandate resolution and validity.  [REAL]

Budget 2ms. **Fail-closed**: cannot verify authority → cannot authorize.

Uncached, deliberately. See FAIL_MATRIX.md: a warm cache cannot see a revocation, which is
the write that matters most, and serving cached authority while the store is unreachable is
fail-open on authority.

Resolving the mandate also resolves ``merchant_id``, which the chain is sharded on. A
request whose mandate does not resolve therefore has no chain to be written to — which is
why an unknown mandate is a 403 with no record rather than a chained deny.
"""

from __future__ import annotations

from datetime import datetime

from psycopg import AsyncConnection

from dwaar.authorize.types import AuthorizeRequest, MandateResult
from dwaar.db.repositories import mandates as mandate_repo
from dwaar.db.repositories import principals as principal_repo

STAGE_NAME = "resolve_mandate"

REASON_UNKNOWN = "mandate_unknown"
REASON_AGENT_MISMATCH = "mandate_agent_mismatch"
REASON_REVOKED = "mandate_revoked"
REASON_EXPIRED = "mandate_expired"


async def resolve_mandate(
    request: AuthorizeRequest, *, conn: AsyncConnection, now: datetime
) -> MandateResult:
    mandate = await mandate_repo.get(conn, request.mandate_id)
    if mandate is None:
        return MandateResult(ok=False, internal_reason=REASON_UNKNOWN)

    # The mandate binds one agent. A different agent presenting it is not a lookup miss —
    # it is an attempt to exercise someone else's authority, and it must not resolve.
    if mandate["agent_id"] != request.agent_id:
        return MandateResult(ok=False, internal_reason=REASON_AGENT_MISMATCH)

    principal = await principal_repo.get(conn, mandate["principal_id"])
    if principal is None:
        return MandateResult(ok=False, internal_reason="principal_unknown")

    common = {
        "mandate": mandate,
        "merchant_id": principal["merchant_id"],
        "principal_id": mandate["principal_id"],
        "mandate_hash": bytes(mandate["mandate_hash"]),
    }

    # Revoked and expired mandates DO resolve. We know exactly whose authority was
    # withdrawn, so these become chained deny records rather than bare 403s.
    if mandate["revoked_at"] is not None:
        return MandateResult(ok=False, internal_reason=REASON_REVOKED, **common)
    if mandate["expires_at"] <= now:
        return MandateResult(ok=False, internal_reason=REASON_EXPIRED, **common)

    return MandateResult(ok=True, **common)
