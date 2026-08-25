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

DWAAR_EXPLAINER_PASSWORD="${DWAAR_EXPLAINER_PASSWORD:-explainer_pw}"

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-SQL
    -- Owner: owns every table, runs migrations. The API never connects as this.
    CREATE ROLE dwaar_owner LOGIN PASSWORD '${DWAAR_OWNER_PASSWORD}';

    -- App: NOT an owner of anything, ever. This is the whole control.
    CREATE ROLE dwaar_app   LOGIN PASSWORD '${DWAAR_APP_PASSWORD}';

    -- Explainer: SELECT on decision_records, INSERT on explanations, nothing else.
    -- Also owns nothing. See migration 0018 — this role is what makes "the LLM cannot
    -- affect a decision" a property of the database rather than of the code.
    CREATE ROLE dwaar_explainer LOGIN PASSWORD '${DWAAR_EXPLAINER_PASSWORD}';

    ALTER DATABASE ${POSTGRES_DB} OWNER TO dwaar_owner;
    ALTER SCHEMA public OWNER TO dwaar_owner;

    GRANT CONNECT ON DATABASE ${POSTGRES_DB} TO dwaar_app;
    GRANT USAGE   ON SCHEMA public TO dwaar_app;
    GRANT CONNECT ON DATABASE ${POSTGRES_DB} TO dwaar_explainer;
    GRANT USAGE   ON SCHEMA public TO dwaar_explainer;

    -- dwaar_app may not create objects. If it could, it would own them, and an owner
    -- cannot be restricted by GRANT.
    REVOKE CREATE ON SCHEMA public FROM dwaar_app;
    REVOKE CREATE ON SCHEMA public FROM dwaar_explainer;
    REVOKE CREATE ON SCHEMA public FROM PUBLIC;
SQL

echo "roles dwaar_owner, dwaar_app and dwaar_explainer created; ${POSTGRES_DB} owned by dwaar_owner"
