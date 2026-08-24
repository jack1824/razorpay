"""GET /health and GET /metrics.

── Always 200, never 503 ───────────────────────────────────────────────────────────────

Health reports; it does not gate. Compose uses it to decide whether the container is up,
and conflating "the process is serving" with "Postgres is reachable" makes a database blip
restart the API — which is the opposite of what `FAIL_MATRIX.md` asks for. A Postgres outage
must produce fail-closed *denials from a running service*, not a crash loop. Demo beat 5
depends on the API staying up in order to deny.

It also has to distinguish degraded from dead for the console, and a 503 cannot.

── Severity is not invented here ───────────────────────────────────────────────────────

The mapping comes from `dwaar/components.py`, which is a transcription of the fail matrix:
fail-open down → amber, fail-closed down → red. Hand-writing it a second time in this file
would guarantee drift between the banner and the documented behaviour — and the place that
drift surfaces is on stage, with the console asserting DEGRADED while the records written
in that window say something else.
"""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Request
from fastapi.responses import Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from dwaar import __version__
from dwaar.components import BY_NAME, Severity, overall

router = APIRouter()


def _report(name: str, up: bool, reason: str | None, checked_at: str) -> dict:
    component = BY_NAME[name]
    return {
        "status": "up" if up else "down",
        # NOMINAL while healthy, whatever the component is: severity describes the impact
        # of it being DOWN, so a healthy fail-closed component is not "critical".
        "severity": (Severity.NOMINAL if up else component.severity_when_down).value,
        "fail_mode": component.fail_mode.value,
        "reason": reason,
        "rationale": component.rationale,
        "checked_at": checked_at,
    }


@router.get("/health")
async def health(request: Request) -> dict:
    app = request.app
    now = datetime.now(UTC).isoformat()
    components: dict[str, dict] = {}

    pool = getattr(app.state, "pool", None)
    if pool is None:
        components["postgres"] = _report("postgres", False, "not configured", now)
    else:
        try:
            async with pool.connection(timeout=2.0) as conn:
                await conn.execute("SELECT 1")
            components["postgres"] = _report("postgres", True, None, now)
        except Exception as exc:  # noqa: BLE001 — health never raises
            components["postgres"] = _report("postgres", False, type(exc).__name__, now)

    # The ledger, the mandate store and the chain are all Postgres. Reported separately
    # because the console and the fail matrix speak about them separately, and because a
    # future split should not change the shape the console binds to.
    for derived in ("ledger", "mandate_store"):
        components[derived] = _report(
            derived,
            components["postgres"]["status"] == "up",
            components["postgres"]["reason"],
            now,
        )

    redis = getattr(app.state, "redis", None)
    if redis is None:
        components["redis"] = _report("redis", False, "not configured", now)
        components["nonce_store"] = _report("nonce_store", False, "not configured", now)
    else:
        try:
            await redis.ping()
            components["redis"] = _report("redis", True, None, now)
            components["nonce_store"] = _report("nonce_store", True, None, now)
        except Exception as exc:  # noqa: BLE001
            components["redis"] = _report("redis", False, type(exc).__name__, now)
            components["nonce_store"] = _report("nonce_store", False, type(exc).__name__, now)

    # Signature verification and the policy engine are in-process and pure, so they are up
    # whenever the process is. Reported so the console's component list is complete rather
    # than silently omitting the controls that matter most.
    components["signature_verification"] = _report("signature_verification", True, None, now)
    components["policy_engine"] = _report("policy_engine", True, None, now)

    # The risk model reports what actually happened at startup, not what is in the
    # repository. `app.state.scorer` is None when no bundle loaded, which is a degraded
    # state the fail matrix calls fail-open — the service runs and the ledger still holds.
    scorer = getattr(app.state, "scorer", None)
    components["risk_model"] = _report(
        "risk_model",
        scorer is not None,
        None if scorer is not None else "no model bundle loaded",
        now,
    )
    if scorer is not None:
        components["risk_model"]["model_version"] = scorer.model_version

    # The injection detector is UP whenever the process is: its named rules need no
    # artifact, so there is no state in which it stops checking. What varies is whether the
    # fitted weights loaded — reported as a reason rather than as a status, because
    # "rules only" is a smaller check and not an absent one.
    detector = getattr(app.state, "detector", None)
    components["injection_detector"] = _report(
        "injection_detector",
        detector is not None,
        None if detector is None else detector.degraded,
        now,
    )
    if detector is not None:
        components["injection_detector"]["model_version"] = detector.model_version

    # Not built yet. Reported as down with its real fail mode, so the console shows the
    # truth rather than an empty space that reads as healthy.
    components["explainer"] = _report("explainer", False, "not implemented", now)

    status = overall([Severity(component["severity"]) for component in components.values()])

    return {
        "status": status.value,
        "version": __version__,
        "trace_id": getattr(request.state, "trace_id", None),
        "components": components,
    }


@router.get("/metrics", include_in_schema=True)
async def metrics() -> Response:
    """Prometheus exposition.

    Unauthenticated and excluded from the RFC 9421 requirement: it is an operational
    surface exposing no agent-identifiable data, and requiring a signed request to scrape
    metrics would mean the scraper needs an agent identity.
    """
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)
