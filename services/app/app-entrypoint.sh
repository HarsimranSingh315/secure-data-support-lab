#!/bin/sh
# Copy certificates and secrets into a private directory owned by the app user, then drop root.
set -eu
mkdir -p /run/app
cp /lab-certs/server.crt /lab-certs/server.key /lab-certs/ca-chain.pem /run/app/
for f in app-db-password app-kms-token; do
  if [ -f "/run/secrets/$f" ]; then cp "/run/secrets/$f" /run/app/; fi
done
chown -R appuser:appuser /run/app
chmod 600 /run/app/server.key
export LAB_CA=/run/app/ca-chain.pem APP_TLS_CERT=/run/app/server.crt APP_TLS_KEY=/run/app/server.key \
       APP_DB_PASSWORD_FILE=/run/app/app-db-password KMS_TOKEN_FILE=/run/app/app-kms-token
# The KMS token appears after `make kms-init`, which restarts the app so it is copied in here.
export HOME=/run/app   # libpq looks for optional client certs under $HOME
exec setpriv --reuid=appuser --regid=appuser --init-groups python3 /srv/app.py
