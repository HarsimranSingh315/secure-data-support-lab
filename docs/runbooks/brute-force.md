# Runbook: repeated failed logins against one account

**Ticket:** Carol says her account feels locked and she did not try to log in.

## Triage
1. `make alerts`: `HIGH brute-force-login ... 7 failed logins for user:carol within 60s` and the
   same for the source IP.
2. Database log: `docker compose exec db grep 'authentication failed' /var/log/postgresql/lab/postgresql.log | tail`
   Same source (10.10.10.10, the toolbox), seconds apart: automated guessing, not a person.

## Root cause
Password guessing from a host in Site A.

## Remediation options
Lockout policy in the directory (OpenLDAP ppolicy), restrict which hosts may log in
(pg_hba.conf), MFA for interactive access, and keep alerting (already working).
