# Runbook: KMS sealed after a restart

**Ticket:** after the KMS host was patched and rebooted, creating new cardholders fails with 503.

## Triage
1. `curl -s --cacert /lab-certs/ca-chain.pem https://app.site-b.lab:8443/health` (toolbox):
   `{"db": "ok", "kms": "sealed"}`
2. App log: `docker compose logs app | tail`: `"error": "KMS HTTP 503: ... sealed"`
3. `docker compose exec kms bao status`: `Sealed  true`

## Root cause
A key manager keeps its master key only in memory. After any restart it starts sealed and cannot
encrypt or decrypt until it is unsealed with the unseal key shares. Reads of existing rows still
work because they do not need the KMS; creating cardholders (encrypt) and showing cards (decrypt)
do not.

## Fix
`make kms-unseal`. In production: several key holders each provide a share (Shamir), or the KMS
auto-unseals with an HSM or a cloud KMS.

## Prevention
Include "unseal and verify" in the patching runbook; monitor `/v1/sys/health`.

## Interview angle
Sealed vs unsealed, why that is a feature, and how HSM auto-unseal works.
