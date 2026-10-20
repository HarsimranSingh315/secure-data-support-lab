# Runbook: database unreachable from Site A (firewall change)

**Ticket:** analysts in Site A cannot connect to the database; `psql` just hangs; the app in Site B is fine.

## Triage
1. Hang or refuse? From the toolbox: `nc -zv -w3 db.site-b.lab 5432`
   - **timed out** = something dropped the packets (firewall, routing)
   - **refused** = the host answered, nothing listening (service down)
2. Is the path fine? `ping db.site-b.lab` and `traceroute -n db.site-b.lab` work, so routing is OK.
3. Capture where it dies: `make capture R=r3 F='port 5432' D=15` while retrying `nc`.
   You see SYNs arriving at r3 and no SYN-ACK: dropped on r3.
4. Read the firewall: `docker compose exec r3 nft -a list ruleset`
   A rule above the allow-list: `ip daddr 10.20.20.10 tcp dport 5432 drop comment "CHG-1042 temporary block"`.
   Its counter is increasing; `dropped_to_site_b` is not, because this rule matched first.

## Root cause
A change ticket added a "temporary" drop rule at the top of the chain and it was never removed.
nftables evaluates rules in order; the first match wins.

## Fix
Remove the rule by handle (`nft delete rule inet labfw to_site_b handle <n>`) or reload the
approved ruleset (`make fix S=firewall-drop`).

## Prevention
Firewall rules in Git, reviewed and deployed from there; expiry dates on temporary rules.

## Interview angle
"A timeout means a drop, a refusal means nothing is listening. I proved where the packet died with
a capture on the firewall and found the rule by its hit counter and change-ticket comment."
