#!/usr/bin/env bash
# Bootstrap a NON-Docker PostgreSQL for the test suite.
#
# scripts/init-db/01-roles.sh is the Docker path — it runs once, as superuser, on an empty
# data directory. This is the same setup for a cluster you already have (Homebrew, a
# system package, a remote dev database), so `make test` can run the DB suite without
# Docker.
#
# The two paths must stay in agreement about ONE thing above all: dwaar_app is not the
# owner of anything. If these ever diverge on that, the append-only test passes in one
# environment and the control is absent in the other.
#
# Idempotent: safe to re-run.
#
#   ./scripts/init-db/local-bootstrap.sh [superuser] [dbname]
set -euo pipefail

SUPERUSER="${1:-$(whoami)}"
DBNAME="${2:-dwaar}"
OWNER_PW="${DWAAR_OWNER_PASSWORD:-owner_pw}"
APP_PW="${DWAAR_APP_PASSWORD:-app_pw}"
POSTGRES_PW="${POSTGRES_PASSWORD:-postgres_pw}"

psql -v ON_ERROR_STOP=1 -U "$SUPERUSER" -d postgres <<SQL
DO \$\$
BEGIN
    -- A 'postgres' superuser role, for the tamper-demo DSN. On Homebrew the cluster
    -- superuser is the invoking user, so this may not exist yet.
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'postgres') THEN
        CREATE ROLE postgres LOGIN SUPERUSER PASSWORD '${POSTGRES_PW}';
    ELSE
        ALTER ROLE postgres WITH LOGIN SUPERUSER PASSWORD '${POSTGRES_PW}';
    END IF;

    -- Owner: owns every table, runs migrations. The API never connects as this.
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dwaar_owner') THEN
        CREATE ROLE dwaar_owner LOGIN PASSWORD '${OWNER_PW}';
    ELSE
        ALTER ROLE dwaar_owner WITH LOGIN PASSWORD '${OWNER_PW}';
    END IF;

    -- App: NOT an owner of anything, ever. This is the whole control.
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dwaar_app') THEN
        CREATE ROLE dwaar_app LOGIN PASSWORD '${APP_PW}';
    ELSE
        ALTER ROLE dwaar_app WITH LOGIN PASSWORD '${APP_PW}';
    END IF;
END
\$\$;
SQL

if ! psql -U "$SUPERUSER" -d postgres -tAc \
      "SELECT 1 FROM pg_database WHERE datname='${DBNAME}'" | grep -q 1; then
    createdb -U "$SUPERUSER" -O dwaar_owner "$DBNAME"
    echo "created database ${DBNAME} owned by dwaar_owner"
fi

psql -v ON_ERROR_STOP=1 -U "$SUPERUSER" -d "$DBNAME" <<SQL
ALTER DATABASE ${DBNAME} OWNER TO dwaar_owner;
ALTER SCHEMA public OWNER TO dwaar_owner;

GRANT CONNECT ON DATABASE ${DBNAME} TO dwaar_app;
GRANT USAGE   ON SCHEMA public TO dwaar_app;

-- dwaar_app may not create objects. If it could, it would own them, and an owner cannot
-- be restricted by GRANT.
REVOKE CREATE ON SCHEMA public FROM dwaar_app;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
SQL

echo "bootstrap complete: ${DBNAME} owned by dwaar_owner; dwaar_app owns nothing"
