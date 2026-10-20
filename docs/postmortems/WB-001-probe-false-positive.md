# WB-001: Health probe set off the brute-force alert

| | |
| --- | --- |
| Date | 2026-10-20 |
| Severity | P3 (false positives; no data or access impact) |
| Detected by | Workbench Overview: activity monitor showed 268 alerts, latest `brute-force-login` |
| Status | Resolved |

## Summary
Right after the workbench went live, the database activity monitor (DAM) began raising a HIGH
`brute-force-login` alert roughly every minute. Nobody was attacking the database: the
workbench's own health check was causing them.

## Timeline
- Workbench Day 1 deployed. Its database card runs `pg_isready` from the toolbox every 10 s
  (auto-refresh).
- DAM alert count climbs from a handful to 268, all `brute-force-login`, user `root`, source
  10.10.10.10 (the toolbox).
- Investigation, root cause and fix the same morning.

## Investigation
1. Alerts named one user (`root`) and one source (the toolbox), at a steady rate of about one
   per minute. A steady rate from one machine points at automation, not a person.
2. `pg_isready` connects as the operating-system user when no `-U` is given. In the toolbox
   that is `root`.
3. Reproduced on PostgreSQL 16 with the lab's `pg_hba.conf` pattern: each probe as `root` matched
   no rule, hit the final `reject` line and logged
   `FATAL 28000 pg_hba.conf rejects connection ... user "root"`.
4. DAM treats FATAL 28000/28P01 as failed logins; 6 per minute crosses its threshold of 5 in 60 s.
   Running the real DAM over that log produced the same `brute-force-login` alerts.

## Root cause
The health probe used an identity the database rejects, so every probe was recorded as a failed
login. The detection worked as designed; the probe was badly designed.

## Fix
- Probe as `wb_probe`, a dedicated identity: allowed by a `hostssl` rule from the toolbox's address
  with `scram-sha-256`, but the role has no password and cannot log in.
- The probe hangs up when asked to authenticate. PostgreSQL does not log a client that disconnects
  before sending a password, so the probe leaves only a neutral `connection received` line.
- Force TLS on the probe (`PGSSLMODE=require`): without it, the probe would miss the `hostssl`
  rule and be rejected and logged again.
- Verified on PostgreSQL 16: probes over TLS as `wb_probe` produced no FATAL lines and no DAM alerts.

## Prevention
- Regression tests: the workbench asserts the probe identity, TLS and rule order in
  `pg_hba.conf`; the DAM tests replay the real log and confirm `root` probes alert while
  `wb_probe` probes leave no trace.
- Rule for future checks: a monitoring probe must never generate security events. Give probes
  their own identity and confirm what they write to audit logs before turning them on.

## Cleanup
The false alerts were cleared from `/dam/alerts.jsonl` after the fix. Real alerts from earlier
scenario runs were lost with them; in production you would mark them as false positives rather than
delete the file.

## What I would say about it
"My own monitoring set off my own intrusion alert. The alert was correct to fire: it saw real
failed logins. The bug was in the probe. I found it from the pattern (one user, one source, a
fixed rate), reproduced it, and fixed it so the probe can't authenticate and leaves nothing
in the audit log."
