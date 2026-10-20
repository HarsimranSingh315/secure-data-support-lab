# Runbook: TLS failures after a certificate renewal

**Ticket:** the database certificate was renewed this morning; since then the app returns 503 and
`psql` from Site A refuses to connect.

## Triage
1. Exact client error (toolbox): `psql "host=db.site-b.lab dbname=appdb user=bob"`
   `server certificate for "db01.site-b.lab" does not match host name "db.site-b.lab"`
2. App side: `curl -s --cacert /lab-certs/ca-chain.pem https://app.site-b.lab:8443/health`
   shows `db: error ... does not match host name`.
3. Inspect what the server presents:
   `openssl s_client -connect db.site-b.lab:5432 -starttls postgres -CAfile /lab-certs/ca-chain.pem </dev/null | openssl x509 -noout -subject -ext subjectAltName -dates`
   The chain is valid (issued by our CA) but the names are `DNS:db01.site-b.lab` only.

## Root cause
The renewed certificate used a new naming standard and dropped the name clients connect with
(and the IP SAN). Clients using `sslmode=verify-full` correctly refuse it. Nothing is wrong with
the network or the database itself.

## Fix
Re-issue with the correct SANs (`DNS:db.site-b.lab, IP:10.20.20.10`) and restart or reload the
service (`make fix S=cert-renewal`). Never "fix" it by lowering clients to `sslmode=require`:
that turns off server identity checks.

## Prevention
Renewal checklist that compares old and new SANs; a post-renewal check with `openssl s_client`.

## Interview angle
Certificate chain vs hostname verification, why verify-full matters, how to read SANs.
