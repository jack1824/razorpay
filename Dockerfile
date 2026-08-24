FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Dependencies first so a source edit does not reinstall the world.
COPY pyproject.toml ./
RUN pip install --upgrade pip && pip install -e ".[dev]" 2>/dev/null || \
    pip install fastapi "uvicorn[standard]" "psycopg[binary,pool]" redis structlog \
                pydantic pydantic-settings prometheus-client numpy onnxruntime

COPY dwaar/      ./dwaar/
# The trained risk model. Committed so a clean clone has a working gateway: `docker compose
# up` to a scoring pipeline needs no training step, and the bundle's feature ordering is
# checked against the code at load. Regenerate with `make traffic && make train`.
COPY models/     ./models/
COPY migrations/ ./migrations/
COPY scripts/    ./scripts/
COPY tests/      ./tests/
COPY pyproject.toml README.md ./

RUN pip install -e . --no-deps

EXPOSE 8080
ENTRYPOINT ["/app/scripts/entrypoint.sh"]
