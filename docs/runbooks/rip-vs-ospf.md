# Exercise: RIP vs OSPF on the same network

Goal: see with your own eyes why OSPF picks the fast path and RIP does not.

1. Baseline (OSPF): `traceroute -n db.site-b.lab` from the toolbox goes via r2
   (`10.0.12.12`), cost 10 + 10 + 10 = 30, instead of the direct slow link (cost 100).
2. Switch every router to RIP (run on r1, r2 and r3):
   ```
   docker compose exec r1 vtysh -c "conf t" -c "no router ospf" -c "router rip" -c "version 2" -c "network 10.0.0.0/8" -c "end"
   ```
3. Wait about 30-60 seconds (RIP sends updates every 30 s), then:
   - `docker compose exec r1 vtysh -c "show ip route 10.20.20.0/24"` shows `Known via "rip", distance 120, metric 2`
   - `traceroute` now goes **r1 -> r3 directly**, over the slow link: RIP only counts hops (1 hop beats 2).
4. Put OSPF back: `docker compose restart r1 r2 r3` (the startup config is OSPF).

| | RIP v2 | OSPF |
| --- | --- | --- |
| Type | Distance vector | Link state |
| Metric | Hop count (max 15) | Cost from bandwidth |
| Administrative distance | 120 | 110 |
| Updates | Full table every 30 s | Hellos; changes flooded immediately |
| In this lab | Took the slow 1-hop link | Took the fast 2-hop path |
