#!/bin/bash
# First-start schema: roles mapped to directory users, a sensitive table, least-privilege grants.
set -euo pipefail
if [[ -n "${APP_DB_PASSWORD_FILE:-}" && -f "$APP_DB_PASSWORD_FILE" ]]; then
  APP_DB_PASSWORD="$(cat "$APP_DB_PASSWORD_FILE")"
fi
: "${APP_DB_PASSWORD:?set APP_DB_PASSWORD or APP_DB_PASSWORD_FILE}"

psql -v ON_ERROR_STOP=1 --username postgres -v app_pw="$APP_DB_PASSWORD" <<'SQL'
CREATE DATABASE appdb;
\connect appdb
CREATE EXTENSION IF NOT EXISTS pgaudit;

-- Directory users (passwords live in LDAP, not here)
CREATE ROLE ldap_users NOLOGIN;
CREATE ROLE dba NOLOGIN;
CREATE ROLE analyst NOLOGIN;
CREATE ROLE alice LOGIN IN ROLE ldap_users, dba;
CREATE ROLE bob   LOGIN IN ROLE ldap_users, analyst;
CREATE ROLE carol LOGIN IN ROLE ldap_users, analyst;

-- Application service account
CREATE ROLE svc_app LOGIN PASSWORD :'app_pw';

REVOKE ALL ON DATABASE appdb FROM PUBLIC;
GRANT CONNECT ON DATABASE appdb TO svc_app, ldap_users;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;

-- Card numbers are never stored in clear: only the last 4 digits and KMS ciphertext.
CREATE TABLE cardholders (
  id              serial PRIMARY KEY,
  full_name       text        NOT NULL,
  email           text        NOT NULL,
  card_last4      char(4)     NOT NULL,
  card_ciphertext text        NOT NULL,
  created_at      timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE orders (
  id            serial PRIMARY KEY,
  cardholder_id int         NOT NULL REFERENCES cardholders(id),
  amount_cents  int         NOT NULL CHECK (amount_cents > 0),
  created_at    timestamptz NOT NULL DEFAULT now()
);

GRANT SELECT, INSERT ON cardholders, orders TO svc_app;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO svc_app;
GRANT SELECT ON orders TO analyst;
-- Deliberately too broad (a common real-world finding): analysts can read cardholders.
-- The DAM watcher is what catches misuse of it. See docs/runbooks/data-exfiltration.md
GRANT SELECT ON cardholders TO analyst;
GRANT ALL ON ALL TABLES IN SCHEMA public TO dba;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO dba;
GRANT USAGE, CREATE ON SCHEMA public TO dba;
SQL
echo "db-init: appdb created with roles, tables and grants"
