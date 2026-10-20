# What was tested before release (20 Oct 2026)

| Area | How it was tested | Result |
| --- | --- | --- |
| OSPF between r1, r2, r3 | Real FRR with these exact configs, in Linux network namespaces and in Docker containers on Docker bridges | Full adjacencies; Site A -> Site B via r2 (cost 30) |
| OSPF MTU incident | MTU 1400 on r2 -> r3 | Neighbour stuck in ExStart, log names the MTU, traffic moves to the cost-100 link; fix restores |
| Core link failure | r1 -> r2 link down | Re-route over the backup link, back after the fix |
| RIP exercise | Same three routers switched to RIP v2 | RIP picks the 1-hop slow link (metric 2), unlike OSPF |
| nftables firewall | Real ruleset on r3 | 5432 allowed, port 22 dropped (timeout), ping/traceroute work, drop counter increments |
| Firewall incident | Injected drop rule with a change-ticket comment | Hang reproduced, rule visible by handle and counter, fix restores |
| Docker networking | Routers forwarding between Docker bridges | Found and fixed: Docker 28+ drops traffic to containers from other bridges unless the network uses `gateway_mode_ipv4=nat-unprotected` |
| OpenLDAP | slapd with this config, seed data and lab certificates | Plain-text bind refused ("confidentiality required"), StartTLS and LDAPS work, chain verifies |
| PostgreSQL + pgAudit | PostgreSQL 16 with this config, schema and pg_hba.conf, LDAP through the routed network | LDAP login over TLS works; wrong password, non-TLS and wrong-network attempts are refused; reads and DDL audited |
| Certificate renewal incident | Re-issued cert with the wrong name | `sslmode=verify-full` refuses it with the expected message |
| LDAP certificate incident | Self-signed directory certificate | DB log: `could not start LDAP TLS session: Connect error` |
| DAM watcher | 9 unit tests against a real pgAudit csvlog, plus live-follow mode | Bulk reads, brute force, permission errors detected; init activity ignored |
| App | End to end against PostgreSQL with an API-compatible mock KMS, plus 4 unit tests (Luhn, encrypt/decrypt over TLS, sealed KMS, wrong token) | Encrypt on create, decrypt on read, only last 4 + ciphertext stored, 503 + clear log when the KMS is sealed |
| HSM demo | SoftHSM 2 + pkcs11-tool | Sign inside the token, verify with OpenSSL, tamper detected, private key not exportable |
| PKI | Script run end to end | Two-tier chain verifies; re-issue with wrong SAN works for the incident |

**Not run before release:** the OpenBao container itself and the complete `docker compose` stack
(container registries were not reachable from the build environment). The CI integration job
(`.github/workflows/ci.yml`) is the first full end-to-end run; if anything fails there, the
support bundle is attached to the run.
