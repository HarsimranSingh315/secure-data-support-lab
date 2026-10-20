#!/bin/bash
# Copy TLS material with the permissions PostgreSQL insists on, prepare the shared audit-log
# directory, then hand over to the official image entrypoint.
set -euo pipefail
CERT_DIR=/var/lib/postgresql/certs
mkdir -p "$CERT_DIR" /var/log/postgresql/lab
cp /lab-certs/server.crt /lab-certs/server.key /lab-certs/ca-chain.pem "$CERT_DIR/"
chown -R postgres:postgres "$CERT_DIR" /var/log/postgresql/lab
chmod 600 "$CERT_DIR/server.key"
# The schema script runs as the postgres user, which cannot read the owner-only secret mount.
if [[ -f /run/secrets/app-db-password ]]; then
  install -o postgres -g postgres -m 600 /run/secrets/app-db-password "$CERT_DIR/app-db-password"
  export APP_DB_PASSWORD_FILE="$CERT_DIR/app-db-password"
fi
exec docker-entrypoint.sh "$@"
