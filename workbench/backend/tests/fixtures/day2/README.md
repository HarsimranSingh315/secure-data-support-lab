# Day 2 fixtures: real output from a replica of the lab

Captured 2026-10-20 from a Linux network-namespace copy of the lab topology: three FRR routers
started from this repo's `services/router/*/frr.conf.tmpl` via `router-init.sh`, r3 loading
`services/router/r3/nftables.nft`, PostgreSQL 16 with TLS behind r3, OpenSSL TLS servers for the
app and KMS ports, and certificates from `scripts/pki.sh`. Nothing here is hand-written.

`session_<state>.json` holds every command the network map, the guided diagnosis and a few
router/firewall diagnostics ran, in order, with exit code and output:

| Session | How the fault was made (same as the lab's scenario.sh) |
| --- | --- |
| healthy | nothing |
| firewall_drop | `nft insert rule ... tcp dport 5432 counter drop comment "CHG-1042 temporary block"` on r3 |
| core_link_down | `ip link set <r2 r1-facing interface> down` |
| ospf_mtu | r2's r3-facing interface set to MTU 1400, then `clear ip ospf process` on r2 and r3 |

Single captures: `tls_db_wrongname.txt` (db cert re-issued as db01.site-b.lab),
`tls_kms_untrusted.txt` (self-signed cert), `tls_app_expired.txt` (CA-issued cert valid only
2025-01-01..02), `tls_refused.txt` (nothing listening), `tcp_refused.txt` (LDAPS on the
directory: nothing listening), `tcp_timeout.txt` (port 5432 behind the drop rule), plus ping,
traceroute, getent, route, OSPF and nft listings. FRR in the replica is 8.4.4; the lab runs 10.2.1.
Commands repeated within a session (traceroute retries) are stored in order.
