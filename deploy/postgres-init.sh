#!/bin/sh
# Runs once, on first start of an empty Postgres volume (docker-entrypoint-initdb.d).
# Creates the least-privilege runtime role used by the server. Migrations run
# as the owner role (POSTGRES_USER); the server runs as cav_app, which cannot
# alter tables or update/delete the audit log.
set -eu
: "${CAV_APP_DB_PASSWORD:?CAV_APP_DB_PASSWORD must be set}"
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  -v app_pw="$CAV_APP_DB_PASSWORD" -v db="$POSTGRES_DB" <<'SQL'
CREATE ROLE cav_app LOGIN PASSWORD :'app_pw';
GRANT CONNECT ON DATABASE :"db" TO cav_app;
GRANT USAGE ON SCHEMA public TO cav_app;
SQL
