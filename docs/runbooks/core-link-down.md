# Runbook: core link failure and OSPF re-route

**Ticket:** latency between the sites jumped; nothing appears down.

## Triage
1. `traceroute -n db.site-b.lab` from the toolbox: the second hop changed from `10.0.12.12` (r2)
   to `10.0.13.13` (r3 over the slow link).
2. On r1: `vtysh -c "show ip route 10.20.20.0/24"`: metric changed from 30 to 110.
3. On r2: `vtysh -c "show ip ospf neighbor"`: the neighbour to r1 is gone. `ip -br link`
   shows the interface DOWN.

## Root cause
The r1-r2 link went down. OSPF noticed within the dead interval (8 s in this lab) and
recalculated the shortest path: the only remaining path is the high-cost backup link. Nothing is
"down" for users, it is just slower.

## Fix
Bring the link back (`make fix S=core-link-down`) and watch the route return to cost 30.

## Interview angle
Explains convergence: hello/dead timers, SPF recalculation, why a cost of 100 makes a link a backup.
