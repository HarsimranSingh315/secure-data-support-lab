# Day 3 fixtures: real packet captures from a replica of the lab

Captured 2026-10-20 with the workbench's own capture code (tcpdump on the capture point, decoded by
tshark) against a Linux network-namespace replica of the lab (this repo's router templates and
firewall rules, PostgreSQL 16 with TLS, certificates from scripts/pki.sh). Nothing is hand-written.

`cap_<name>.pcap` is the captured file; `cap_<name>.json` holds the capture arguments and the exact
output of every tshark (and `ip -j addr`) command run to analyse it, which the tests replay.

| Capture | Point · filter · test traffic | State of the lab |
| --- | --- | --- |
| healthy_db | r3 · tcp 5432 · TCP+TLS to db | healthy |
| firewall_drop_r3 / _toolbox | r3 or toolbox · tcp 5432 · TCP+TLS to db | `CHG-1042` drop rule inserted on r3 |
| refused | toolbox · LDAP ports · connect to ldap:636 | healthy (nothing listens on 636) |
| ping | toolbox · ICMP · ping db | healthy |
| unreachable | toolbox · ICMP · ping db | both of r1's core links down |
| tls_wrongname | toolbox · tcp 5432 · TCP+TLS to db | db certificate re-issued as db01.site-b.lab |
| ospf_mtu_r3 / _r2 | r3 or r2 · OSPF | r2's r3-facing interface at MTU 1400 |
| ospf_ok_r3 | r3 · OSPF | healthy |

`detail_tls_alert.txt` is `tshark -V -x` for the TLS alert packet in tls_wrongname.
tshark in the replica is 4.2.2; the lab's Rocky 9 toolbox ships 3.4, so the analysis only uses
fields and display filters both versions support (retransmissions are found with a filter pass
rather than by reading the field value).
