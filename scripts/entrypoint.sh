#!/bin/sh
# API entrypoint: wait for Postgres, migrate as the OWNER, then serve as the APP role.
#
# Migrating here rather than in a separate one-shot service keeps `docker compose up` a
# single command from nothing, which is an acceptance criterion.
set -eu

echo "waiting for postgres..."
python -m scripts.wait_for "${DATABASE_URL_MIGRATE}" 60

echo "applying migrations as owner..."
python -m dwaar.db.migrate "${DATABASE_URL_MIGRATE}"

echo "starting api as dwaar_app..."
exec uvicorn dwaar.api.app:app --host 0.0.0.0 --port 8080 --workers "${UVICORN_WORKERS:-4}"
