"""The allow-list of live lab checks shown on the Overview screen.

Each check runs one fixed command in one lab container and turns the raw output into:
  status   ok | degraded | down | unknown   (unknown = the check itself could not run)
  summary  one line for the card
  facts    label/value pairs taken from the output
  meaning  what the result tells a support engineer
  evidence the exact command, where it ran, exit code, duration and (capped) output

A check never reports "ok" unless the command ran and its output proved it.
"""
from __future__ import annotations

import json
import re
import shlex
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone

from .models import Check, Evidence, Fact
from .runner import ExecResult, Runner

CA = "/lab-certs/ca-chain.pem"
TOOLBOX_ENV = {"LDAPTLS_CACERT": CA}

ERROR_TEXT = {
    "docker_unavailable": "The workbench cannot reach Docker, so this check could not run.",
    "container_missing": "The {svc} container does not exist. Has the lab been started (make up)?",
    "container_not_running": "The {svc} container is stopped, so this check could not run.",
    "timeout": "The command did not finish in time and was stopped.",
}


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def evidence(r: ExecResult) -> Evidence:
    cmd = shlex.join(r.command)
    if r.env:
        cmd = " ".join(f"{k}={shlex.quote(v)}" for k, v in r.env.items()) + " " + cmd
    envs = "".join(f"-e {k}={shlex.quote(v)} " for k, v in r.env.items())
    repro = f"docker compose exec {envs}{r.service} {shlex.join(r.command)}"
    return Evidence(service=r.service, command=cmd, repro=repro, exit_code=r.exit_code, output=r.output,
                    duration_ms=r.duration_ms, error=r.error, truncated=r.truncated)


@dataclass(frozen=True)
class Spec:
    id: str
    title: str
    group: str
    fn: Callable[[Runner, "Spec"], Check]
    target: str = ""        # the component being checked (used by the network map later)


def result(spec: Spec, status: str, summary: str, meaning: str, runs: list[ExecResult],
           facts: list[tuple[str, str]] | None = None) -> Check:
    return Check(id=spec.id, title=spec.title, group=spec.group, target=spec.target or spec.id,
                 status=status, summary=summary, meaning=meaning,
                 facts=[Fact(label=k, value=v) for k, v in (facts or [])],
                 evidence=[evidence(r) for r in runs], checked_at=now(), source="live")


def could_not_run(spec: Spec, r: ExecResult, vantage: str | None = None) -> Check:
    """The command never produced a usable answer. Toolbox down = we cannot judge the target."""
    text = ERROR_TEXT.get(r.error or "", "The check could not run.").format(svc=r.service)
    if r.error == "timeout":
        # A hang is itself evidence (e.g. a firewall silently dropping) - report it as down.
        return result(spec, "down", "No answer before the timeout", text, [r])
    if vantage and r.service == vantage:
        return result(spec, "unknown", f"Cannot test: {vantage} is not running",
                      f"This check runs from the {vantage} container. " + text, [r])
    return result(spec, "down" if r.error != "docker_unavailable" else "unknown",
                  "Container not running" if r.error != "docker_unavailable" else "Docker unreachable",
                  text, [r])


# ---------------------------------------------------------------- routing (OSPF)

def parse_ospf_neighbors(output: str) -> list[dict]:
    """FRR `show ip ospf neighbor json`. Newer FRR uses converged/role, older nbrState."""
    data = json.loads(output or "{}")
    out = []
    for rid, entries in (data.get("neighbors") or {}).items():
        for e in entries if isinstance(entries, list) else [entries]:
            state = e.get("converged") or str(e.get("nbrState", "")).split("/")[0] or "?"
            iface = str(e.get("ifaceName", "")).split(":")[0]
            out.append({"router_id": rid, "state": state, "iface": iface,
                        "address": e.get("ifaceAddress", "")})
    return out


def ospf_check(expected: int) -> Callable[[Runner, Spec], Check]:
    def run(runner: Runner, spec: Spec) -> Check:
        r = runner.exec(spec.target, ["vtysh", "-c", "show ip ospf neighbor json"])
        if not r.ran:
            return could_not_run(spec, r)
        try:
            nbrs = parse_ospf_neighbors(r.output)
        except ValueError:
            return result(spec, "unknown", "Unreadable OSPF output",
                          "FRR answered, but not with the JSON this check expects.", [r])
        full = [n for n in nbrs if n["state"].startswith("Full")]
        facts = [(f'{n["router_id"]} via {n["iface"] or "?"}', n["state"]) for n in nbrs]
        summary = f"{len(full)}/{expected} OSPF neighbours Full"
        if len(full) >= expected:
            return result(spec, "ok", summary,
                          "All expected OSPF adjacencies are up, so this router has a complete "
                          "map of the network and can use the best path.", [r], facts)
        stuck = [n for n in nbrs if not n["state"].startswith("Full")]
        if stuck:
            summary += f"; {len(stuck)} stuck in {stuck[0]['state']}"
        status = "degraded" if full else "down"
        return result(spec, status, summary,
                      "At least one expected adjacency is missing or not Full. Routes learned "
                      "through that neighbour are gone, so traffic may take a slower path or "
                      "fail. Next: 'show ip ospf neighbor' on both ends and compare interface "
                      "settings (MTU, timers, area, network type).", [r], facts)
    return run


# ---------------------------------------------------------------- firewall (r3 nftables)

def parse_nft(output: str) -> dict:
    accepts = [(m.group(3), int(m.group(1))) for m in re.finditer(
        r"counter packets (\d+) bytes (\d+) accept comment \"([^\"]+)\"", output)]
    dropped = re.search(r"counter dropped_to_site_b \{[^}]*?packets (\d+) bytes (\d+)", output, re.S)
    rules = 0
    chain = re.search(r"chain to_site_b \{(.*?)\n\t\}", output, re.S)
    if chain:
        rules = sum(1 for line in chain.group(1).splitlines() if line.strip() and not line.strip().startswith("#"))
    return {"accepts": accepts, "dropped": int(dropped.group(1)) if dropped else None, "rules": rules}


def firewall_check(runner: Runner, spec: Spec) -> Check:
    r = runner.exec("r3", ["nft", "list", "table", "inet", "labfw"])
    if not r.ran:
        return could_not_run(spec, r)
    if r.exit_code != 0:
        return result(spec, "degraded", "No firewall policy loaded",
                      "The labfw table is missing. The forward chain then accepts everything, "
                      "so Site B is reachable without any filtering. Reload it: "
                      "nft -f /etc/lab/nftables.nft on r3.", [r])
    p = parse_nft(r.output)
    facts = [(f"allowed: {c}", f"{n} packets") for c, n in p["accepts"]]
    if p["dropped"] is not None:
        facts.append(("default-deny drops", f'{p["dropped"]} packets'))
    return result(spec, "ok", f'Policy loaded · {p["rules"]} rules · {p["dropped"] or 0} packets dropped',
                  "The Site B firewall is in place. Counters go up each time a rule matches: "
                  "an allow rule stuck at 0 while users report failures means their traffic is "
                  "being stopped before it reaches that rule.", [r], facts)


# ---------------------------------------------------------------- directory (LDAP)

def ldap_check(runner: Runner, spec: Spec) -> Check:
    r = runner.exec("toolbox", ["ldapwhoami", "-x", "-ZZ", "-o", "nettimeout=3",
                                "-H", "ldap://ldap.site-a.lab"], env=TOOLBOX_ENV)
    if not r.ran:
        return could_not_run(spec, r, vantage="toolbox")
    out = r.output.lower()
    if r.exit_code == 0:
        return result(spec, "ok", "Reachable · StartTLS OK · certificate trusted",
                      "The directory answered over an encrypted StartTLS session and its "
                      "certificate chains to the lab CA. Database logins that use LDAP can work.",
                      [r], [("server", "ldap.site-a.lab:389"), ("bind", "anonymous (whoami)")])
    if "can't contact" in out or "connect" in out and "tls" not in out:
        summary, meaning = "Cannot reach the directory", (
            "No connection to ldap.site-a.lab:389. This is a network or service problem "
            "(routing, firewall, slapd down), not a password or certificate problem.")
    elif "certificate" in out or "tls" in out or "ssl" in out:
        summary, meaning = "TLS failure (certificate not trusted or wrong name)", (
            "The server was reached but the StartTLS handshake failed. Check which certificate "
            "the server presents: openssl s_client -connect ldap.site-a.lab:389 -starttls ldap.")
    else:
        summary, meaning = "Directory check failed", "See the output for the exact error."
    return result(spec, "down", summary, meaning, [r])


# ---------------------------------------------------------------- database

def db_check(runner: Runner, spec: Spec) -> Check:
    r = runner.exec("toolbox", ["pg_isready", "-h", "db.site-b.lab", "-p", "5432", "-d", "appdb", "-t", "3"])
    if not r.ran:
        return could_not_run(spec, r, vantage="toolbox")
    facts = [("from", "toolbox (Site A) through r1 → r2 → r3"), ("server", "db.site-b.lab:5432")]
    if r.exit_code == 0:
        return result(spec, "ok", "Accepting connections from Site A",
                      "The database answered across the routed network and the firewall. "
                      "(This probe does not log in; TLS and passwords are tested separately.)",
                      [r], facts)
    if r.exit_code == 1:
        return result(spec, "degraded", "Reachable but rejecting connections",
                      "PostgreSQL answered but is not accepting connections yet, usually while "
                      "starting up or shutting down.", [r], facts)
    return result(spec, "down", "No response from the database",
                  "Nothing answered on db.site-b.lab:5432 within 3 seconds. A silent timeout "
                  "points at routing or a firewall drop; 'connection refused' would point at "
                  "the database service itself.", [r], facts)


# ---------------------------------------------------------------- key management

def kms_check(runner: Runner, spec: Spec) -> Check:
    r = runner.exec("kms", ["bao", "status", "-format=json"])
    if not r.ran:
        return could_not_run(spec, r)
    try:
        st = json.loads(r.output)
    except ValueError:
        return result(spec, "down", "KMS not answering",
                      "The OpenBao server did not return a status. Is the server process up? "
                      "Check: docker compose logs kms.", [r])
    facts = [("initialized", str(st.get("initialized")).lower()),
             ("sealed", str(st.get("sealed")).lower()),
             ("version", str(st.get("version", "?"))),
             ("unseal threshold", f'{st.get("t", "?")} of {st.get("n", "?")} key shares')]
    if not st.get("initialized"):
        return result(spec, "degraded", "Not initialised",
                      "The KMS has never been set up. Run: make kms-init.", [r], facts)
    if st.get("sealed"):
        return result(spec, "down", "Sealed - encryption unavailable",
                      "A sealed KMS keeps its keys locked and refuses all encrypt/decrypt "
                      "requests. This is normal after every restart, by design. Unseal with the "
                      "key holders' shares (lab: make kms-unseal).", [r], facts)
    return result(spec, "ok", f'Unsealed · OpenBao {st.get("version", "")}',
                  "The key manager is unlocked and can serve encrypt/decrypt requests.", [r], facts)


# ---------------------------------------------------------------- cardholder app

CURL_ERRORS = {
    6: "Name did not resolve (DNS / hosts problem).",
    7: "Connection refused: reached the host but nothing is listening on the port.",
    28: "Timed out: no answer at all, typical of a firewall drop or routing problem.",
    35: "TLS handshake failed.",
    60: "The server's certificate is not trusted or does not match the name.",
}


def app_check(runner: Runner, spec: Spec) -> Check:
    r = runner.exec("toolbox", ["curl", "-s", "-S", "-m", "4", "-w", "\\n%{http_code}",
                                "--cacert", CA, "https://app.site-b.lab:8443/health"])
    if not r.ran:
        return could_not_run(spec, r, vantage="toolbox")
    if r.exit_code != 0:
        why = CURL_ERRORS.get(r.exit_code or -1, "See the output for the exact error.")
        return result(spec, "down", f"Request failed (curl exit {r.exit_code})", why, [r])
    body, _, code = r.output.rstrip().rpartition("\n")
    try:
        deps = json.loads(body)
    except ValueError:
        deps = {}
    facts = [("HTTP status", code)] + [(f"dependency: {k}", str(v)) for k, v in deps.items()]
    if code == "200":
        return result(spec, "ok", "Healthy · database and KMS reachable",
                      "The app answered over HTTPS and both of its dependencies are working.", [r], facts)
    bad = ", ".join(f"{k}: {v}" for k, v in deps.items() if v != "ok") or f"HTTP {code}"
    return result(spec, "degraded", f"Running, but a dependency failed ({bad})",
                  "The app itself is up, but it cannot do its job: it reports which dependency is "
                  "failing. Investigate that component next.", [r], facts)


# ---------------------------------------------------------------- activity monitor

def dam_check(runner: Runner, spec: Spec) -> Check:
    r = runner.exec("dam", ["sh", "-c",
                            "cat /dam/alerts.jsonl 2>/dev/null | wc -l; tail -n 1 /dam/alerts.jsonl 2>/dev/null; true"])
    if not r.ran:
        return could_not_run(spec, r)
    lines = r.output.strip().splitlines()
    try:
        count = int(lines[0].strip()) if lines else 0
    except ValueError:
        count = 0
    facts = [("alerts recorded", str(count))]
    latest = ""
    if len(lines) > 1:
        try:
            a = json.loads(lines[-1])
            latest = a.get("rule", "")
            facts += [("latest rule", latest), ("latest severity", str(a.get("severity", ""))),
                      ("latest time", str(a.get("time", "")))]
        except ValueError:
            pass
    summary = f"Watching audit log · {count} alert{'s' if count != 1 else ''}"
    if latest:
        summary += f" · latest: {latest}"
    return result(spec, "ok", summary,
                  "The activity monitor is running and reading the database audit log. Alerts "
                  "are findings to investigate, not service failures.", [r], facts)


SPECS: list[Spec] = [
    Spec("r1", "Router r1 · Site A edge", "Network", ospf_check(2), "r1"),
    Spec("r2", "Router r2 · core", "Network", ospf_check(2), "r2"),
    Spec("r3", "Router r3 · Site B edge", "Network", ospf_check(2), "r3"),
    Spec("firewall", "Firewall · r3 nftables", "Network", firewall_check, "r3"),
    Spec("ldap", "Directory · OpenLDAP", "Identity", ldap_check, "ldap"),
    Spec("db", "Database · PostgreSQL 16", "Data", db_check, "db"),
    Spec("app", "Cardholder app · HTTPS", "Data", app_check, "app"),
    Spec("kms", "Key manager · OpenBao", "Crypto", kms_check, "kms"),
    Spec("dam", "Activity monitor · DAM", "Monitoring", dam_check, "dam"),
]


def run_check(runner: Runner, spec: Spec) -> Check:
    try:
        return spec.fn(runner, spec)
    except Exception as exc:  # a broken check must never take down the overview
        return Check(id=spec.id, title=spec.title, group=spec.group, target=spec.target,
                     status="unknown", summary="Check error",
                     meaning=f"The check itself failed: {type(exc).__name__}", facts=[],
                     evidence=[], checked_at=now(), source="live")
