#!/bin/sh
# Runs once, on first start of an empty Postgres volume.
set -eu

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
     -v app_password="$APP_DB_PASSWORD" <<'EOSQL'
CREATE ROLE agentgate_app LOGIN PASSWORD :'app_password';
EOSQL

for f in /db/migrations/*.sql /db/seed/*.sql; do
  echo "applying $f"
  psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" -f "$f"
done
