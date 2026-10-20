# Runbook: app cannot reach the database after a hardening change

**Ticket:** after a database hardening change, the app health check fails.

## Triage
1. Health shows the database check failing with
   `FATAL: pg_hba.conf rejects connection for host "10.20.20.30", user "svc_app", database "appdb", SSL encryption`
2. Database log names every rejected connection and why:
   `docker compose exec db tail -n 20 /var/log/postgresql/lab/postgresql.log`
3. Read the rules: `docker compose exec db cat /etc/postgresql/pg_hba.conf`. The `svc_app` line is
   commented out; the connection falls through to `host all all 0.0.0.0/0 reject`.

## Root cause
pg_hba.conf is evaluated top to bottom; the first matching line decides. Removing the
application's line made it fall through to the final reject rule.

## Fix
Restore the line and reload (`pg_ctl reload`; no restart needed): `make fix S=hba-change`.

## Interview angle
Reading pg_hba.conf, first-match logic, reload vs restart, and using the server log rather than
guessing from the client error.
