# Runbook: directory logins fail after the LDAP server was rebuilt

**Ticket:** nobody can log in to the database with their directory password; the app still works.

## Triage
1. Reproduce from the toolbox: `PGPASSWORD='Lab-bob-2026!' psql "host=db.site-b.lab dbname=appdb user=bob" -c 'select 1'`
   `FATAL: LDAP authentication failed for user "bob"`
2. Why does the app still work? It uses SCRAM (a database password), not LDAP. So the problem is
   on the LDAP path only.
3. The database log says more than the client:
   `docker compose exec db grep -i ldap /var/log/postgresql/lab/postgresql.log | tail`
   `could not start LDAP TLS session: Connect error` (verified wording, PostgreSQL 16)
4. Check the directory's certificate from the toolbox:
   `openssl s_client -connect ldap.site-a.lab:389 -starttls ldap -CAfile /lab-certs/ca-chain.pem </dev/null | grep -E "subject=|issuer=|Verify return"`
   `Verify return code: 18 (self-signed certificate)`

## Root cause
The rebuilt directory server came up with a self-signed certificate instead of one from the
company CA. PostgreSQL uses StartTLS with `LDAPTLS_REQCERT=demand`, so it refuses to send
passwords to a server it cannot verify. Security working as designed.

## Fix
Install a CA-issued certificate on the directory (`make fix S=ldap-cert-untrusted`). Do not set
`LDAPTLS_REQCERT=never` on the database.

## Interview angle
LDAP vs LDAPS vs StartTLS, trust stores, and why "the app works" narrowed it to one auth path.
