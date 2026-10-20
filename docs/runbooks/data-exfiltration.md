# Runbook: suspicious export of the cardholder table

**Ticket:** monitoring raised alerts on the cardholder table. Who did what, from where, and what
should change?

## Triage
1. `make alerts`: `HIGH bulk-read-sensitive bob 10.10.10.10 ... select * from cardholders` and
   `... copy cardholders to stdout`.
2. Confirm in the audit trail:
   `docker compose exec db grep 'AUDIT' /var/log/postgresql/lab/postgresql.log | grep cardholders | tail`
3. Who is bob and how did he get access? `ldapsearch` shows he is an analyst. In the database:
   `\dp cardholders` shows `analyst=r/postgres`: analysts were granted SELECT on the whole table.
4. What data actually left? Only names, emails, last 4 digits and KMS ciphertext. Full card
   numbers were never in the database and cannot be decrypted without the KMS policy.

## Root cause
An over-broad grant (`GRANT SELECT ON cardholders TO analyst`) let analysts read every row.
Encryption through the KMS limited the impact.

## Fix / remediation
`REVOKE SELECT ON cardholders FROM analyst;` (`make fix S=data-exfiltration`), give analysts a
view without personal data if they need statistics, and follow the incident process.

## Interview angle
Database activity monitoring, least privilege, and why application-level encryption with keys in a
KMS limits a breach. This is exactly the problem Thales/Imperva data-security products address.
