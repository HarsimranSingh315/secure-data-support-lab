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
| Database | toolbox | `pg_isready -h db.site-b.lab -t 3` | accepting connections across the routed path |
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

Mounting the Docker socket gives a container root-equivalent control of Docker. That is accepted
here only because this is a local, single-user lab, and it is contained by:

- **No command input.** The API has three read-only GET endpoints (`/api/health`,
  `/api/overview`, `/api/events`). Commands are fixed argument lists in `backend/app/checks.py`;
  nothing from the browser is ever placed into a command. A test asserts there are no
  POST/PUT/PATCH/DELETE routes.
- **Only lab containers.** Targets are looked up by compose labels and must be one of the nine
  lab services (`LAB_SERVICES`); anything else is refused.
- **Bounded execution.** Every command runs under `timeout -s KILL 5`; output is capped at 8 KB.
  Results are reused for 2 seconds so repeated refreshes cannot flood the lab.
- **Local only.** Published on 127.0.0.1, served over TLS, `Content-Security-Policy` and
  `nosniff` headers, structured request logs with request IDs.
- **Hardened container.** Read-only root filesystem, all Linux capabilities dropped,
  `no-new-privileges`. It runs as root only because the Docker socket requires it.
- **No secrets shown.** Checks read status, never keys or passwords. The KMS card shows seal
  state and version, never the unseal key or tokens.

Not yet in place (planned): sign-in for the UI, persistent history (events reset when the
workbench restarts), and actions such as Break/Fix, which will need their own validation.

## Tests (actually run)

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
