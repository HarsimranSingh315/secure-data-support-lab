# Runbook: OSPF neighbour stuck in ExStart (MTU mismatch)

**Ticket:** after maintenance, Site A to Site B is slow and one OSPF neighbour never comes up.

## Triage
1. Where does traffic go now? From the toolbox: `traceroute -n db.site-b.lab`
   - Healthy: `10.10.10.2 -> 10.0.12.12 -> 10.0.23.23 -> 10.20.20.10` (via r2)
   - Now: `10.10.10.2 -> 10.0.13.13 -> ...` (the slow backup link, cost 100)
2. Neighbour state on both ends:
   `docker compose exec r2 vtysh -c "show ip ospf neighbor"` and the same on r3.
   One neighbour sits in **ExStart** or **Exchange** and never reaches **Full**.
3. Read the router log: `docker compose exec r2 grep -i mtu /var/log/frr/frr.log`
   `Neighbor 3.3.3.3 MTU 1500 is larger than [eth2]'s MTU 1400`
4. Confirm: `docker compose exec r2 ip link` and `docker compose exec r3 ip link` on the r2-r3 link.

## Root cause
OSPF neighbours compare interface MTU in their Database Description packets. With different MTUs
they cannot exchange databases, so the adjacency stalls in ExStart/Exchange and OSPF routes around
the link. Here the maintenance change set MTU 1400 on one side only.

## Fix
Set matching MTUs on both ends (`make fix S=ospf-mtu`). `ip ospf mtu-ignore` would hide the symptom
but can cause packet loss for large packets; fix the MTU instead.

## Prevention
Change checklists that verify both ends of a link; alert on OSPF neighbours not in Full.

## Interview angle
"Neighbour stuck in ExStart is almost always an MTU mismatch. I confirm it in the OSPF log, then
fix the MTU on both ends rather than using mtu-ignore."
