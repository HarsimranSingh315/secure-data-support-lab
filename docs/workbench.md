# DataShield Support Workbench

A web console over the lab at **https://localhost:9443**. Every card on the Overview runs a
real, fixed command inside a lab container and shows the evidence: the exact command, where it
ran, exit code, duration and output, plus a plain-English meaning and the same command ready to
paste into your terminal.

> Independent educational project. It is not a Thales product and does not reproduce any vendor
> software. It is a local lab with synthetic data, not a production monitoring system.

## Open it

```bash
make up            # first time, or after pulling changes: builds and starts everything
make workbench     # after changing only the workbench code
```

Then open **https://localhost:9443**. The certificate is issued by the lab CA for `localhost`;
if you trusted the lab root CA for the KMS UI (docs/visual-tools.md) the browser accepts it,
otherwise click through the warning once.

## What the Overview checks (status: implemented, tested)

| Card | Runs in | Command | Healthy when |
| --- | --- | --- | --- |
| Router r1 / r2 / r3 | each router | `vtysh -c "show ip ospf neighbor json"` | 2 neighbours in state Full |
| Firewall | r3 | `nft list table inet labfw` | policy table loaded (shows allow and drop counters) |
| Directory | toolbox | `ldapwhoami -x -ZZ -H ldap://ldap.site-a.lab` | StartTLS succeeds and the cert is trusted |
| Database | toolbox | `pg_isready -h db.site-b.lab -U wb_probe -t 3` over TLS | accepting connections across the routed path |
| Cardholder app | toolbox | `curl --cacert … https://app.site-b.lab:8443/health` | HTTP 200 (503 = a dependency failed) |
| Key manager | kms | `bao status -format=json` | initialised and unsealed |
| Activity monitor | dam | counts lines in `/dam/alerts.jsonl` | running (alerts are findings, not failures) |

Status meanings:
- **Healthy**: the command ran and its output proved the component works.
- **Degraded**: working but impaired (one OSPF neighbour missing, app up but a dependency down).
- **Down**: the component failed its check, or did not answer before the timeout.
- **Unknown**: the check itself could not run (for example the toolbox is stopped, so checks
  that start from Site A cannot judge the target). Unknown is never shown as healthy.

The **request path** strip colours each hop from the same live checks (worst status wins).
**Status changes** lists every transition the workbench has seen since it started (kept in memory).

## Network map (status: implemented, tested)

The designed topology (from docker-compose.yml) overlaid with what the routers report right now:

- **Routers**: green when both OSPF neighbours are Full. Click one for its interfaces (address,
  state, MTU, OSPF cost, adjacent neighbours), OSPF neighbour table and routing table.
- **Links**: coloured from both ends: interface state on each router plus the OSPF adjacency
  between them. Down = an interface is down; amber dashed = interfaces up but the adjacency is not
  Full. Click a link to compare both ends side by side (the map shows the values, such as MTU, but
  does not name the cause for you).
- **Current path**: a traceroute from the Site A toolbox to the database, drawn as the animated
  line. The banner warns when traffic is on the r1-r3 backup link. Path links are worked out from
  the order of routers, not from reply addresses, so asymmetric routing (a router answering from
  another interface) does not mislead it.
- **Servers** take their colour from the Overview checks.

Sources: `ip -j addr show`, `vtysh -c "show ip ospf neighbor json"`, `"show ip ospf interface json"`,
`"show ip route json"` on each router, and `traceroute -n` from the toolbox.

## Diagnostics (status: implemented, tested)

**Guided diagnosis** answers "a user in Site A cannot reach service X" by walking up the stack:
name resolution → ping → traceroute → TCP connect → TLS, then names the layer that fails:

| What the tests show | Conclusion |
| --- | --- |
| Name does not resolve | Name resolution |
| Ping works, port times out | Firewall (port filtered) |
| Port refused | Service (nothing listening) |
| Ping and path fail, router has no route | Routing |
| Port works, TLS fails | TLS (wrong name, untrusted CA, expired) |
| Everything works, path uses r1-r3 | Network path warning (backup link) |

**Individual tests**: name resolution, ping, traceroute, TCP port check, TLS certificate (with
STARTTLS for PostgreSQL and LDAP), route lookup on a router, OSPF neighbours, OSPF interfaces
(MTU, cost, timers), firewall rules with counters and handles, RIP routes (when the RIP exercise is
on). Each result shows a verdict, plain-English meaning, the facts parsed from the output, the
exact command and its output, and the same command ready for your terminal.

Teaching ports: `db:22` (not allowed by the firewall: shows a **timeout**) and `ldap:636` (same
site, nothing listening: shows **refused**). Run both and compare.

Traceroute retries once when the destination stays silent: Linux rate-limits ICMP error replies,
so a final `*` does not always mean the host is unreachable.

## Incidents (status: implemented, tested)

The nine scenarios, each with **Start incident**, **Show a hint** and **Fix and close**. The buttons
run the lab's own `scripts/scenario.sh` (the same as `make break S=...`), so the terminal and the
workbench always do exactly the same thing.

- Before you start: a neutral title (the symptom), never the cause.
- Started: the customer's ticket (ID, priority, their words), a timer, links to the tools for that
  area, a notes box (kept in your browser) and the hint.
- Fixed: what was actually broken, time to resolve (a lab metric), your notes next to the runbook.
- Every Break/Hint/Fix is recorded in `.workbench/actions.jsonl` and shown in the action log.
- Only one action runs at a time; breaking an incident that is already active is refused.

## Packet captures (status: implemented, tested)

Capture on r1, r2, r3 or the toolbox with a fixed filter (PostgreSQL, app, KMS, LDAP, ICMP, OSPF,
traceroute) for 3-30 s, optionally generating test traffic from the toolbox at the same time. Or
upload a `.pcap` (max 10 MB). The workbench decodes it with tshark in the toolbox and shows:

- **Findings**: unanswered SYNs (dropped), SYN→RST (refused), completed handshakes,
  retransmissions, TLS alerts (with who sent them), ICMP unreachable, and for OSPF the MTU each
  neighbour advertises in its Database Description packets next to the capturing interface's MTU.
- **TCP conversations** with state, and a **ladder diagram** of the selected one.
- **Packets**: filterable table (address, port, protocol, text), flagged rows, and full
  `tshark -V -x` decode with hex for any packet.
- **Download .pcap** to open in Wireshark.

Routers capture with `-Q in` so a forwarded packet is counted once, not on both interfaces.
Snap length is 256 bytes: headers and handshakes, not bulk data.

## How it works

```
browser ──HTTPS──> workbench (FastAPI + React, 127.0.0.1:9443)
                      │  Docker Engine API (mounted socket)
                      ▼
          docker exec <fixed command> in r1 | r2 | r3 | toolbox | kms | dam
```

The workbench is not attached to the lab networks. Checks that need the network path (LDAP, DB,
app) run from the toolbox in Site A, so they cross r1, r2, r3 and the firewall exactly like a user.

## Threat model and controls

Mounting the Docker socket gives a container root-equivalent control of Docker, and since Day 3
the workbench also has the repository mounted (read-write) and the Docker CLI, so that Break/Fix
can run `scripts/scenario.sh`. That is accepted only because this is a local, single-user lab, and
it is contained by:

- **Lab changes need a same-origin request.** The five POST endpoints (incident actions, start a
  capture, upload a capture) require an `X-Workbench-Action: 1` header, which another website cannot
  send without a CORS preflight this server never approves, and are refused when `Origin` or
  `Sec-Fetch-Site` show a cross-site request. This stops a malicious page in the same browser from
  breaking the lab (CSRF). Tested.
- **Fixed actions only.** Incident IDs, actions, capture points, filters, durations and traffic
  options are checked against allow-lists before anything runs; values are passed as separate
  arguments. Uploaded files are size- and magic-byte-checked and decoded by tshark inside the
  toolbox container, never by the workbench process.

- **No command input.** Apart from the guarded actions above, every endpoint is a read-only GET. Commands are fixed argument lists in
  `backend/app/checks.py`, `diagnostics.py` and `topology.py`. Diagnostics take only names from
  allow-lists (a target, a port that target defines, a router); anything else gets HTTP 400 before
  a command is built. Values reach `bash -c` scripts as separate arguments (`$0`, `$1`), never as
  script text. Tests cover injection-shaped input and assert there are no write methods.
- **Bounded load.** At most 3 diagnostics run at once (more get HTTP 429); the map is cached for 3 s.
- **Probes stay out of the audit trail.** TCP and TLS checks to the database open and close
  connections without logging in, so PostgreSQL records only "connection received" lines (verified).
- **Only lab containers.** Targets are looked up by compose labels and must be one of the nine
  lab services (`LAB_SERVICES`); anything else is refused.
- **Bounded execution.** Every command runs under `timeout -s KILL 5`; output is capped at 8 KB.
  Results are reused for 2 seconds so repeated refreshes cannot flood the lab.
- **Local only.** Published on 127.0.0.1, served over TLS, `Content-Security-Policy` and
  `nosniff` headers, structured request logs with request IDs.
- **Hardened container.** Read-only root filesystem, all Linux capabilities dropped,
  `no-new-privileges`. It runs as root only because the Docker socket requires it.
- **Probes do not pollute the audit trail.** The database probe uses `wb_probe`, an identity that
  pg_hba.conf allows over TLS but that cannot log in; the probe hangs up before authenticating,
  which PostgreSQL does not log. (Day 1 first probed as `root`, which wrote a failed login every
  10 s and set off the brute-force alert: see docs/postmortems/WB-001-probe-false-positive.md.)
- **No secrets shown.** Checks read status, never keys or passwords. The KMS card shows seal
  state and version, never the unseal key or tokens.

Not yet in place (planned): sign-in for the UI (today, anyone who can reach 127.0.0.1:9443 on the
Mac can use it), and persistent status history (the Overview timeline resets when the workbench
restarts; incident state, actions and captures are kept in `.workbench/`).

## Tests (actually run)

Day 3 (`tests/test_day3.py`, 29 tests): the incident tests run the repository's **real**
`scripts/scenario.sh` with only `docker compose` replaced by a stub that records each call, and
check the ticket parsing, hints, refusals, reveal-after-fix, failure handling and the action log.
The capture tests replay **real captures** from the namespace replica (healthy, firewall drop at
r3 and at the client, refused, ping, unreachable, wrong-name TLS, OSPF MTU mismatch from both
sides, healthy OSPF) and the exact tshark output for them. The API tests cover the CSRF guard.
Before packaging, the whole flow ran in a browser against the replica: Start incident → ticket →
capture on r3 (SYNs retransmitted, no SYN-ACK) → hint → Fix → cause revealed and runbook shown.
Frontend: 10 tests including the runbook renderer (built from React elements, never raw HTML).

Day 2 (`tests/test_day2.py`, 38 tests): the network map and the guided diagnosis replay **real
recorded sessions** from a network-namespace replica of the lab (the repo's own router templates,
firewall rules and PKI; PostgreSQL 16 with TLS; OpenSSL servers) in four states: healthy, firewall
drop, core link down and OSPF MTU mismatch. Single captures cover refused vs timed-out TCP and
wrong-name, self-signed, expired and refused TLS. The replica was also used live: the guided
diagnosis named the right layer for firewall drop, link down, MTU mismatch, wrong-name and
untrusted certificates, a stopped database and an isolated router. See `tests/fixtures/day2/README.md`.

Day 1:

- `workbench/backend/tests` (26 tests): every check against **real command output** captured from
  FRR, nftables, OpenBao 2.4.4, pg_isready, ldapwhoami and curl (see
  `tests/fixtures/README.md`), covering healthy, failed, timed-out, stopped-container,
  missing-toolbox and Docker-unreachable cases, plus the API, caching and status-change timeline.
- `workbench/frontend/src/status.test.ts` (6 tests): status roll-up and labels; the TypeScript
  build is type-checked.
- The Docker runner was also run against real containers (live `docker exec`, a real timeout,
  a stopped and a missing container).
- CI starts the whole lab, requires the workbench to report everything healthy, seals the KMS and
  requires the KMS card to go down, then unseals and requires it to recover.

Run them with `make test`.

## Practice with it

1. Open the workbench with the lab healthy. Click each card and read **What this means**.
2. `make break S=kms-sealed`. Watch the Key manager card go **Down**, the app go **Degraded**
   (it names the failing dependency), and the timeline record both. `make fix S=kms-sealed`.
3. Stop `toolbox` in Docker Desktop. The LDAP, database and app cards become **Unknown**, not Down:
   the vantage point is gone, so the workbench cannot judge them. Start it again.
4. `make break S=core-link-down`, then open r1 and r2. Which neighbour disappeared?
   `make fix S=core-link-down`.
5. For each card, copy the **Try it yourself** command into the terminal and compare the output.
