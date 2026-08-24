#!/bin/bash
# Runs once, as superuser, at first Postgres start (docker-entrypoint-initdb.d).
#
# Creates the two roles the append-only control depends on. CREATE ROLE is cluster-level,
# so it cannot live in a migration — migrations run as dwaar_owner, which does not have it.
#
# The critical line is `ALTER DATABASE ... OWNER TO dwaar_owner` combined with dwaar_app
# NEVER owning anything. A REVOKE cannot strip a table owner, so non-ownership is the only
# thing that makes GRANT SELECT, INSERT meaningful on decision_records.
set -euo pipefail

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-SQL
    -- Owner: owns every table, runs migrations. The API never connects as this.
    CREATE ROLE dwaar_owner LOGIN PASSWORD '${DWAAR_OWNER_PASSWORD}';

    -- App: NOT an owner of anything, ever. This is the whole control.
    CREATE ROLE dwaar_app   LOGIN PASSWORD '${DWAAR_APP_PASSWORD}';

    ALTER DATABASE ${POSTGRES_DB} OWNER TO dwaar_owner;
    ALTER SCHEMA public OWNER TO dwaar_owner;

    GRANT CONNECT ON DATABASE ${POSTGRES_DB} TO dwaar_app;
    GRANT USAGE   ON SCHEMA public TO dwaar_app;

    -- dwaar_app may not create objects. If it could, it would own them, and an owner
    -- cannot be restricted by GRANT.
    REVOKE CREATE ON SCHEMA public FROM dwaar_app;
    REVOKE CREATE ON SCHEMA public FROM PUBLIC;
SQL

echo "roles dwaar_owner and dwaar_app created; ${POSTGRES_DB} owned by dwaar_owner"
