"""Stage 1 — RFC 9421 request signature verification.  [STUB — real on 25 Aug]

Budget 0.3ms. **Fail-closed**: identity is not optional.

STUB CONTRACT
    returns ok=True with agent_id taken from the request body
    degraded token: "signature_unverified"

**The stub refuses to run outside a local environment.** A stubbed authentication check
that silently passes is the worst possible stub: it is invisible, it is exactly what an
attacker wants, and nothing about a passing test suite would reveal it. Raising here means
the failure mode is a loud startup error rather than a silently unauthenticated gateway.
"""

from __future__ import annotations

from dwaar.authorize.types import AuthorizeRequest, SignatureResult
from dwaar.config import Settings

DEGRADED_TOKEN = "signature_unverified"
STAGE_NAME = "verify_signature"


async def verify_signature(
    request: AuthorizeRequest,
    headers: dict[str, str],
    *,
    settings: Settings,
    conn=None,
) -> SignatureResult:
    if settings.env != "local":
        raise RuntimeError(
            "verify_signature is still a stub and refuses to run with "
            f"DWAAR_ENV={settings.env!r}. A stubbed auth check that silently passes is not "
            "a degraded control, it is no control. Implement RFC 9421 verification before "
            "deploying anywhere but local."
        )

    return SignatureResult(
        ok=True,
        degraded=DEGRADED_TOKEN,
        agent_id=request.agent_id,
        key_used=None,
        internal_reason="signature_not_verified_stub",
    )
