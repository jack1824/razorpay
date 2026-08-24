FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Dependencies first so a source edit does not reinstall the world.
COPY pyproject.toml ./
RUN pip install --upgrade pip && pip install -e ".[dev]" 2>/dev/null || \
    pip install fastapi "uvicorn[standard]" "psycopg[binary,pool]" redis structlog \
                pydantic pydantic-settings prometheus-client

COPY dwaar/      ./dwaar/
COPY migrations/ ./migrations/
COPY scripts/    ./scripts/
COPY tests/      ./tests/
COPY pyproject.toml README.md ./

RUN pip install -e . --no-deps

EXPOSE 8080
ENTRYPOINT ["/app/scripts/entrypoint.sh"]
