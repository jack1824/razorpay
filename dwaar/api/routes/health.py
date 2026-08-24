"""GET /health.

Reports dependency reachability but **does not fail the endpoint on it**. Health is used
by Compose to decide whether the container is up; conflating "the process is serving" with
"Postgres is reachable" makes a database blip restart the API, which is the opposite of
what `FAIL_MATRIX.md` wants. A Postgres outage must produce fail-closed *denials from a
running service*, not a crash loop — the demo's beat 5 depends on the API staying up to
deny.

So: 200 whenever the process can serve, with per-dependency status in the body.
"""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from dwaar import __version__

router = APIRouter()


@router.get("/health")
async def health(request: Request) -> dict:
    pool = getattr(request.app.state, "pool", None)

    db_status = "not_configured"
    if pool is not None:
        try:
            async with pool.connection(timeout=2.0) as conn:
                await conn.execute("SELECT 1")
            db_status = "ok"
        except Exception as exc:  # noqa: BLE001 — health never raises
            db_status = f"unavailable: {type(exc).__name__}"

    return {
        "status": "ok",
        "version": __version__,
        "trace_id": getattr(request.state, "trace_id", None),
        "dependencies": {"postgres": db_status},
    }


@router.get("/metrics", include_in_schema=True)
async def metrics() -> Response:
    """Prometheus exposition.

    Unauthenticated and excluded from the RFC 9421 signature requirement: it is an
    operational surface, it exposes no agent-identifiable data, and requiring a signed
    request to scrape metrics would mean the scraper needs an agent identity.
    """
    return Response(
        content=generate_latest(),
        media_type=CONTENT_TYPE_LATEST,
    )
