# Day 4 fixtures: real directory, database and audit data

Recorded 2026-10-21 (UTC) from the namespace replica of the lab, running this repo's own service
files: OpenLDAP from services/ldap/slapd.conf and seed.ldif, and PostgreSQL 16 with
services/db/postgresql.conf (pgAudit, csvlog), pg_hba.conf and 01-init.sh. PostgreSQL authenticates
directory users against OpenLDAP over StartTLS, as in the lab.

Activity in `postgresql.csv` came from real logins from the Site A toolbox: alice reading one
cardholder, bob running `select * from cardholders` and `copy cardholders to stdout`, bob denied a
DELETE on orders, alice granting SELECT on orders over the network, carol failing to log in 7 times,
plus the workbench's own login tests and catalog reads (tagged application_name=datashield-workbench).
`alerts.jsonl` is the output of the real services/dam/dam.py run over that log.

`session_<state>.json` holds every command the workbench ran (directory, login tests, catalog
queries) with its real output:

| Session | State |
| --- | --- |
| baseline | as initialised by 01-init.sh |
| after_revoke | `REVOKE SELECT ON cardholders FROM analyst` (the data-exfiltration fix) |
| hba_change | the svc_app line commented out of pg_hba.conf and reloaded (the hba-change scenario) |

The directory's password hashes were replaced with `{SSHA}REDACTED` in the recorded slapcat output.
