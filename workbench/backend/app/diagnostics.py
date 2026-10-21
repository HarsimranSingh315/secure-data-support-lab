"""Network diagnostics workbench: allow-listed operations with validated parameters.

Inputs are never free text. A request names an operation, a target from TARGETS, a port that
target defines, or a router from ROUTERS; anything else is rejected before a command is built.
Values reach commands only as separate argv items (for `bash -c` they arrive as $0/$1, never
pasted into the script), so there is no injection path.
"""
from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone

from .checks import CA, evidence, now
from .models import DiagResult, Fact, WizardResult, WizardStep
from .runner import ExecResult, Runner


@dataclass(frozen=True)
class Port:
    number: int
    label: str
    tls: str | None = None        # None = no TLS test; "" = TLS from the start; "postgres"/"ldap" = STARTTLS
    note: str = ""                # what a learner should expect


@dataclass(frozen=True)
class Target:
    id: str
    host: str
    ip: str
    label: str
    ports: tuple[Port, ...] = ()


TARGETS: dict[str, Target] = {t.id: t for t in [
    Target("db", "db.site-b.lab", "10.20.20.10", "Database (Site B)", (
        Port(5432, "PostgreSQL", tls="postgres"),
        Port(22, "SSH", note="Not allowed through the firewall: expect a timeout"))),
    Target("app", "app.site-b.lab", "10.20.20.30", "Cardholder app (Site B)", (
        Port(8443, "HTTPS", tls=""),)),
    Target("kms", "kms.site-b.lab", "10.20.20.20", "Key manager (Site B)", (
        Port(8200, "OpenBao API", tls=""),)),
    Target("ldap", "ldap.site-a.lab", "10.10.10.20", "Directory (Site A)", (
        Port(389, "LDAP", tls="ldap"),
        Port(636, "LDAPS", note="Same site, no firewall, nothing listening: expect refused"))),
    Target("r1", "10.10.10.2", "10.10.10.2", "Router r1 (Site A gateway)"),
    Target("r2", "10.0.12.12", "10.0.12.12", "Router r2 (core)"),
    Target("r3", "10.20.20.2", "10.20.20.2", "Router r3 (Site B gateway)"),
]}
ROUTERS = ("r1", "r2", "r3")

# Which device owns which address (to turn traceroute hops into names)
ADDRESS_OWNER = {
    "10.10.10.2": "r1", "10.0.12.11": "r1", "10.0.13.11": "r1",
    "10.0.12.12": "r2", "10.0.23.22": "r2",
    "10.0.23.23": "r3", "10.0.13.13": "r3", "10.20.20.2": "r3",
    "10.20.20.10": "db", "10.20.20.20": "kms", "10.20.20.30": "app",
    "10.10.10.20": "ldap", "10.10.10.10": "toolbox",
}

TCP_SCRIPT = 'exec 3<>"/dev/tcp/$0/$1" && echo "connected to $0 port $1"'
TLS_SCRIPT = (
    'openssl s_client -brief -connect "$0:$1" -servername "$0" -verify_hostname "$0" '
    '-verify_return_error -CAfile ' + CA + ' $2 </dev/null 2>&1; echo "s_client_exit=$?"; '
    'echo "--- certificate presented"; '
    'openssl s_client -connect "$0:$1" -servername "$0" $2 </dev/null 2>/dev/null '
    '| openssl x509 -noout -subject -issuer -startdate -enddate -ext subjectAltName 2>&1'
)


class InvalidRequest(ValueError):
    """Raised for anything outside the allow-list; the API turns it into HTTP 400."""


def get_target(tid: str | None) -> Target:
    if not tid or tid not in TARGETS:
        raise InvalidRequest(f"unknown target; choose one of: {', '.join(TARGETS)}")
    return TARGETS[tid]


def get_port(t: Target, port: int | None) -> Port:
    for p in t.ports:
        if p.number == port:
            return p
    allowed = ", ".join(str(p.number) for p in t.ports) or "none"
    raise InvalidRequest(f"port not allowed for {t.id}; allowed: {allowed}")


def get_router(r: str | None) -> str:
    if r not in ROUTERS:
        raise InvalidRequest(f"unknown router; choose one of: {', '.join(ROUTERS)}")
    return r


def name(ip: str) -> str:
    return ADDRESS_OWNER.get(ip, ip)


def result(op: str, title: str, status: str, summary: str, meaning: str, runs: list[ExecResult],
           facts: list[tuple[str, str]] | None = None) -> DiagResult:
    return DiagResult(op=op, title=title, status=status, summary=summary, meaning=meaning,
                      facts=[Fact(label=k, value=v) for k, v in (facts or [])],
                      evidence=[evidence(r) for r in runs], ran_at=now())


def not_run(op: str, title: str, r: ExecResult) -> DiagResult | None:
    if r.ran or r.error == "timeout":
        return None
    why = {"container_not_running": f"The {r.service} container is stopped.",
           "container_missing": f"The {r.service} container does not exist (is the lab up?).",
           "docker_unavailable": "The workbench cannot reach Docker."}.get(r.error or "", "Could not run.")
    return result(op, title, "error", "Could not run this test", why, [r])


# ------------------------------------------------------------------ ping

def parse_ping(out: str) -> dict:
    d: dict = {}
    m = re.search(r"(\d+) packets transmitted, (\d+) received.*?(\d+(?:\.\d+)?)% packet loss", out)
    if m:
        d["sent"], d["received"], d["loss"] = int(m.group(1)), int(m.group(2)), float(m.group(3))
    m = re.search(r"rtt min/avg/max/mdev = [\d.]+/([\d.]+)/", out)
    if m:
        d["avg_ms"] = float(m.group(1))
    m = re.search(r"ttl=(\d+)", out)
    if m:
        d["ttl"] = int(m.group(1))
    return d


def op_ping(runner: Runner, target: Target, **_) -> DiagResult:
    title = f"Ping {target.host}"
    r = runner.exec("toolbox", ["ping", "-c", "3", "-W", "1", "-i", "0.3", target.host], timeout=8)
    if (n := not_run("ping", title, r)):
        return n
    p = parse_ping(r.output)
    facts = []
    if "sent" in p:
        facts.append(("replies", f'{p["received"]} of {p["sent"]} ({p["loss"]:g}% loss)'))
    if "avg_ms" in p:
        facts.append(("average round trip", f'{p["avg_ms"]} ms'))
    if "ttl" in p:
        hops = 64 - p["ttl"]
        facts.append(("TTL on replies", f'{p["ttl"]} (Linux starts at 64, so {hops} router{"s" if hops != 1 else ""} on the way back)'))
    if p.get("received", 0) == 0:
        why = ("No ICMP echo replies. Either the host is down, there is no route, or something "
               "filters ICMP. A failed ping alone does not prove the service is down: many "
               "networks block ICMP. Check traceroute and a TCP connection next.")
        if "unknown host" in r.output.lower() or "name or service not known" in r.output.lower():
            why = "The name did not resolve, so no packet was sent. Check name resolution first."
        return result("ping", title, "fail", "No replies", why, [r], facts)
    status = "warn" if p.get("loss", 0) > 0 else "pass"
    return result("ping", title, status, f'{p["received"]}/{p["sent"]} replies · avg {p.get("avg_ms", "?")} ms',
                  "The host is reachable at the IP level (layer 3) in both directions. This says "
                  "nothing yet about whether a service port is open: ICMP and TCP are treated "
                  "separately by firewalls.", [r], facts)


# ------------------------------------------------------------------ traceroute

def parse_trace(out: str) -> list[str | None]:
    hops: list[str | None] = []
    for line in out.splitlines()[1:]:
        m = re.match(r"\s*\d+\s+(\S+)", line)
        if m:
            hops.append(None if m.group(1) == "*" else m.group(1))
    return hops


def describe_path(hops: list[str | None]) -> str:
    return " → ".join(name(h) if h else "*" for h in hops)


TRACE_ARGV = ["traceroute", "-n", "-w", "1", "-q", "1", "-m", "8"]


def trace(runner: Runner, host: str, ip: str) -> list[ExecResult]:
    """Run traceroute; if the destination stayed silent, wait and try once more.

    Linux rate-limits ICMP error replies (about one per second per destination), so the last
    hop of a traceroute can show '*' even when the host is reachable, especially when several
    traces run at once. One retry after a pause separates that from a real failure.
    """
    import time
    first = runner.exec("toolbox", TRACE_ARGV + [host], timeout=15)
    if not first.ran or (h := parse_trace(first.output)) and h[-1] == ip:
        return [first]
    time.sleep(1.2)
    return [first, runner.exec("toolbox", TRACE_ARGV + [host], timeout=15)]


def hop_names(hops: list[str | None]) -> list[str]:
    return [name(h) for h in hops if h]


def uses_backup(hops: list[str | None]) -> bool:
    """r1 directly followed by r3 = the r1-r3 backup link. Judged by router order, not by the
    address a router answers from: with asymmetric routing r3 can reply from its backup-link
    address even though the probe arrived through r2."""
    names = hop_names(hops)
    return any(a == "r1" and b == "r3" for a, b in zip(names, names[1:]))


def asymmetric_hops(hops: list[str | None]) -> list[str]:
    """Hops that answered from an address on a link the probe did not come in on."""
    names = [name(h) if h else None for h in hops]
    notes = []
    for i, h in enumerate(hops):
        if h == "10.0.13.13" and i > 0 and names[i - 1] == "r2":
            notes.append("r3 answered from its r1-r3 link address (10.0.13.13) although the probe came in "
                         "from r2: its reply took a different path back (asymmetric routing)")
        if h == "10.0.23.23" and i > 0 and names[i - 1] == "r1":
            notes.append("r3 answered from its r2-r3 link address although the probe came in on the backup link")
    return notes


def op_traceroute(runner: Runner, target: Target, **_) -> DiagResult:
    title = f"Traceroute to {target.host}"
    runs = trace(runner, target.host, target.ip)
    r = runs[-1]
    if (n := not_run("traceroute", title, r)):
        return n
    hops = parse_trace(r.output)
    facts = [(f"hop {i}", f"{h}  ({name(h)})" if h else "* (no reply)") for i, h in enumerate(hops, 1)]
    if len(runs) > 1:
        facts.append(("note", "first attempt ended in silent hops, so the trace was repeated once"))
    facts += [("asymmetric", n) for n in asymmetric_hops(hops)]
    reached = bool(hops) and hops[-1] == target.ip
    answered = [h for h in hops if h]
    path = describe_path([h for h in hops if h] if not reached else hops)
    backup_note = (" This path uses the r1 → r3 link (OSPF cost 100), the slow backup; the normal path is "
                   "through r2 (cost 10 + 10). Ask why the cheaper path is not in use.") if uses_backup(hops) else ""
    if not reached:
        last = answered[-1] if answered else None
        return result("traceroute", title, "fail",
                      f"Did not reach {target.host}" + (f"; last reply from {name(last)}" if last else ""),
                      "The trace stops part-way. Either the problem is at or just after the last hop that "
                      "answered (missing route, link down, filter), or the remaining devices do not send "
                      "ICMP replies. Confirm with a TCP test to the service." + backup_note, runs, facts)
    meaning = ("Each line is one router that answered as the packet's TTL ran out. This is the "
               "real path packets take right now, chosen by the routing table (OSPF).") + backup_note
    if backup_note:
        return result("traceroute", title, "warn", f"{len(hops)} hops: {path} (backup link)", meaning, runs, facts)
    return result("traceroute", title, "pass", f"{len(hops)} hops: {path}", meaning, runs, facts)


# ------------------------------------------------------------------ name resolution

def op_resolve(runner: Runner, target: Target, **_) -> DiagResult:
    title = f"Resolve {target.host}"
    r = runner.exec("toolbox", ["getent", "hosts", target.host])
    if (n := not_run("resolve", title, r)):
        return n
    if r.exit_code == 0 and r.output.strip():
        ip = r.output.split()[0]
        status = "pass" if ip == target.ip else "fail"
        summary = f"{target.host} → {ip}" + ("" if status == "pass" else f" (expected {target.ip})")
        meaning = ("getent asks the system resolver in the order set in /etc/nsswitch.conf. In this "
                   "lab the names come from /etc/hosts entries that Docker writes (extra_hosts); "
                   "in a company network they would come from DNS.")
        if status == "fail":
            meaning = "The name resolves, but to the wrong address. Every connection will go to the wrong host. " + meaning
        return result("resolve", title, status, summary, meaning, [r], [("address", ip), ("source", "/etc/hosts via nsswitch")])
    return result("resolve", title, "fail", "Name does not resolve",
                  "No address for this name, so nothing can connect to it. Check the hosts file or "
                  "DNS server, and the spelling of the name.", [r])


# ------------------------------------------------------------------ TCP port

def op_tcp(runner: Runner, target: Target, port: int | None = None, **_) -> DiagResult:
    p = get_port(target, port)
    title = f"TCP connect {target.host}:{p.number} ({p.label})"
    r = runner.exec("toolbox", ["timeout", "3", "bash", "-c", TCP_SCRIPT, target.host, str(p.number)], timeout=6)
    if (n := not_run("tcp", title, r)):
        return n
    facts = [("port", f"{p.number} ({p.label})")] + ([("expected", p.note)] if p.note else [])
    out = r.output.lower()
    if r.exit_code == 0:
        return result("tcp", title, "pass", "Connected (3-way handshake completed)",
                      "SYN → SYN-ACK → ACK succeeded: the route works in both directions, the "
                      "firewall allows this port and a process is listening. Problems from here up "
                      "are TLS, authentication or the application.", [r], facts)
    if "connection refused" in out:
        return result("tcp", title, "fail", "Connection refused (got a reset)",
                      "The host answered immediately with a TCP reset: the network path works, but "
                      "nothing is listening on this port (service stopped, wrong port, or bound to "
                      "another address). Firewalls that drop do not send resets.", [r], facts)
    if r.exit_code in (124, 137) or r.error == "timeout":
        return result("tcp", title, "fail", "Timed out (no answer at all)",
                      "The SYN got no reply of any kind within 3 s. That silence is typical of a "
                      "firewall that drops packets, or of a routing problem. If ping to the same host "
                      "works, suspect a firewall rule for this port: compare the rule counters on r3.",
                      [r], facts)
    if "no route to host" in out:
        return result("tcp", title, "fail", "No route to host",
                      "The kernel or a router reported the destination unreachable. Check the routing "
                      "table along the path.", [r], facts)
    return result("tcp", title, "fail", f"Failed (exit {r.exit_code})", "See the output for the exact error.", [r], facts)


# ------------------------------------------------------------------ TLS certificate

VERIFY_HELP = {
    "hostname mismatch": ("The certificate is valid and trusted, but it was issued for a different "
                          "name than the one the client connected to. Re-issue it with the right "
                          "name in Subject Alternative Name."),
    "self-signed certificate": ("The server presents a certificate it signed itself, not one from the "
                                "company CA, so clients cannot trust it. Install a CA-issued certificate."),
    "unable to get local issuer certificate": ("The certificate chain does not lead to a CA the client "
                                               "trusts. Either the server is missing its intermediate "
                                               "certificate or it was issued by a different CA."),
    "certificate has expired": "The certificate's validity period has ended. Renew and reinstall it.",
    "certificate is not yet valid": "The certificate's start date is in the future: check clocks (NTP).",
}


def parse_tls(out: str) -> dict:
    d: dict = {"ok": "Verification: OK" in out}
    m = re.search(r"s_client_exit=(\d+)", out)
    d["exit"] = int(m.group(1)) if m else None
    m = re.search(r"verify error:num=\d+:(.+)", out)
    d["verify_error"] = m.group(1).strip() if m else None
    for key, pat in (("protocol", r"Protocol version: (\S+)"), ("subject", r"^subject=(.+)$"),
                     ("issuer", r"^issuer=(.+)$"), ("not_after", r"^notAfter=(.+)$"),
                     ("not_before", r"^notBefore=(.+)$")):
        m = re.search(pat, out, re.M)
        d[key] = m.group(1).strip() if m else None
    m = re.search(r"Subject Alternative Name:\s*\n\s*(.+)", out)
    d["san"] = m.group(1).strip() if m else None
    d["refused"] = "connection refused" in out.lower() or "errno=111" in out
    return d


def days_left(not_after: str | None, today: datetime | None = None) -> int | None:
    if not not_after:
        return None
    try:
        exp = datetime.strptime(" ".join(not_after.split()), "%b %d %H:%M:%S %Y GMT").replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    return (exp - (today or datetime.now(timezone.utc))).days


def op_tls(runner: Runner, target: Target, port: int | None = None, **_) -> DiagResult:
    p = get_port(target, port)
    if p.tls is None:
        raise InvalidRequest(f"port {p.number} on {target.id} does not use TLS")
    starttls = f"-starttls {p.tls}" if p.tls else ""
    title = f"TLS certificate {target.host}:{p.number}" + (f" (STARTTLS {p.tls})" if p.tls else "")
    r = runner.exec("toolbox", ["bash", "-c", TLS_SCRIPT, target.host, str(p.number), starttls], timeout=10)
    if (n := not_run("tls", title, r)):
        return n
    t = parse_tls(r.output)
    left = days_left(t["not_after"])
    facts = [(k, v) for k, v in [
        ("presented subject", t["subject"]), ("issuer", t["issuer"]), ("names (SAN)", t["san"]),
        ("valid until", t["not_after"] + (f" ({left} days left)" if left is not None else "") if t["not_after"] else None),
        ("protocol", t["protocol"]), ("trusted CA file", CA)] if v]
    if t["refused"] or (t["exit"] and not t["subject"] and not t["verify_error"]):
        return result("tls", title, "fail", "Could not connect to start TLS",
                      "The TCP connection itself failed, so no certificate was exchanged. Test the "
                      "port first (TCP connect).", [r], facts)
    if t["ok"]:
        status = "warn" if left is not None and left < 30 else "pass"
        summary = f"Trusted · name matches · {left} days left" if left is not None else "Trusted · name matches"
        return result("tls", title, status, summary,
                      "The certificate chains to the lab CA, includes the name the client used, and is "
                      "within its validity dates. The encrypted connection can be trusted."
                      + (" It expires within 30 days: renew it." if status == "warn" else ""), [r], facts)
    err = t["verify_error"] or "certificate verification failed"
    return result("tls", title, "fail", f"Not trusted: {err}",
                  VERIFY_HELP.get(err, "The client refused the certificate. The verify error names the reason."),
                  [r], facts)


# ------------------------------------------------------------------ routers

def op_route(runner: Runner, target: Target, router: str | None = None, **_) -> DiagResult:
    rt = get_router(router)
    title = f"Route on {rt} to {target.ip} ({target.id})"
    r = runner.exec(rt, ["vtysh", "-c", f"show ip route {target.ip}"])
    if (n := not_run("route", title, r)):
        return n
    out = r.output
    if "not in table" in out.lower() or not out.strip():
        return result("route", title, "fail", "No route",
                      f"{rt} has no route to this address, so it drops the traffic. Check that the "
                      "routing protocol learned the prefix (show ip ospf neighbor / show ip route).", [r])
    prefix = re.search(r"Routing entry for (\S+)", out)
    via = re.search(r'Known via "(\w+)", distance (\d+), metric (\d+)', out)
    nh = re.search(r"\*\s+(\d+\.\d+\.\d+\.\d+), via (\S+)", out)
    direct = re.search(r"directly connected, (\S+)", out)
    facts = [("prefix", prefix.group(1) if prefix else "?")]
    if via:
        facts += [("learned from", via.group(1)), ("distance / metric", f"{via.group(2)} / {via.group(3)}")]
    if nh:
        facts.append(("next hop", f"{nh.group(1)} ({name(nh.group(1))}) out {nh.group(2)}"))
        summary = f"via {name(nh.group(1))} ({nh.group(1)}), metric {via.group(3) if via else '?'}"
    elif direct:
        facts.append(("next hop", f"directly connected on {direct.group(1)}"))
        summary = f"directly connected on {direct.group(1)}"
    else:
        summary = "route found"
    return result("route", title, "pass", summary,
                  "The routing table decides the next hop. Distance says how much the source is "
                  "trusted (OSPF 110, RIP 120); metric is the protocol's own cost. Lower wins.", [r], facts)


def op_ospf_neighbors(runner: Runner, router: str | None = None, **_) -> DiagResult:
    rt = get_router(router)
    title = f"OSPF neighbours on {rt}"
    r = runner.exec(rt, ["vtysh", "-c", "show ip ospf neighbor"])
    if (n := not_run("ospf_neighbors", title, r)):
        return n
    rows = re.findall(r"^(\d+\.\d+\.\d+\.\d+)\s+\d+\s+(\S+)\s+.*?(\d+\.\d+\.\d+\.\d+)\s+(\S+?):", r.output, re.M)
    facts = [(f"{rid} via {iface}", f"{state.split('/')[0]} (neighbour address {addr}, {name(addr)})") for rid, state, addr, iface in rows]
    stuck = [s for _, s, _, _ in rows if not s.startswith("Full")]
    if not rows:
        return result("ospf_neighbors", title, "fail", "No OSPF neighbours",
                      "This router has no adjacencies, so it learns no routes from others.", [r])
    if stuck:
        return result("ospf_neighbors", title, "warn", f"{len(rows) - len(stuck)}/{len(rows)} Full; stuck in {stuck[0].split('/')[0]}",
                      "Neighbours that never reach Full do not exchange routes. Init/2-Way problems are "
                      "usually hello/dead timers, area or authentication; ExStart/Exchange problems "
                      "usually mean the two ends disagree on the interface MTU. Compare both ends.", [r], facts)
    return result("ospf_neighbors", title, "pass", f"{len(rows)}/{len(rows)} neighbours Full",
                  "Full means the two routers have synchronised their link-state databases.", [r], facts)


def op_ospf_interfaces(runner: Runner, router: str | None = None, **_) -> DiagResult:
    rt = get_router(router)
    title = f"OSPF interfaces on {rt}"
    r = runner.exec(rt, ["vtysh", "-c", "show ip ospf interface"])
    if (n := not_run("ospf_interfaces", title, r)):
        return n
    facts = []
    for block in re.split(r"\n(?=\S)", r.output.strip()):
        head = re.match(r"(\S+) is (\w+)", block)
        if not head:
            continue
        mtu = re.search(r"MTU (\d+) bytes", block)
        addr = re.search(r"Internet Address ([^\s,]+)", block)
        cost = re.search(r"Cost: (\d+)", block)
        timers = re.search(r"Hello (\d+)s, Dead (\d+)s", block)
        adj = re.search(r"Neighbor Count is (\d+), Adjacent neighbor count is (\d+)", block)
        bits = [f"{head.group(2)}", f"{addr.group(1) if addr else '?'}", f"MTU {mtu.group(1) if mtu else '?'}",
                f"cost {cost.group(1) if cost else '?'}"]
        if timers:
            bits.append(f"hello {timers.group(1)}s / dead {timers.group(2)}s")
        if adj:
            bits.append(f"{adj.group(2)} of {adj.group(1)} neighbours adjacent")
        facts.append((head.group(1), " · ".join(bits)))
    return result("ospf_interfaces", title, "pass" if facts else "fail",
                  f"{len(facts)} OSPF interface{'s' if len(facts) != 1 else ''}",
                  "Two OSPF neighbours must agree on area, network type, hello/dead timers and "
                  "(for the database exchange) MTU. Compare these values with the router at the other "
                  "end of each link.", [r], facts)


def op_rip(runner: Runner, router: str | None = None, **_) -> DiagResult:
    rt = get_router(router)
    title = f"RIP routes on {rt}"
    r = runner.exec(rt, ["vtysh", "-c", "show ip rip"])
    if (n := not_run("rip", title, r)):
        return n
    if "not running" in r.output.lower() or r.exit_code:
        return result("rip", title, "info", "RIP is not running on this router",
                      "The lab routes with OSPF. RIP is an optional exercise (docs/runbooks/rip-vs-ospf.md).", [r])
    return result("rip", title, "pass", "RIP routing table",
                  "RIP chooses routes by hop count only (max 15) and ignores link speed.", [r])


# ------------------------------------------------------------------ firewall

def parse_rules(out: str) -> list[dict]:
    rules, chain = [], None
    for line in out.splitlines():
        s = line.strip()
        m = re.match(r"chain (\S+) \{", s)
        if m:
            chain = m.group(1)
            continue
        if chain != "to_site_b" or not s or s.startswith(("}", "type ")):
            continue
        verdict = re.findall(r"\b(accept|drop|reject)\b", s.split(" comment ")[0].split(" # handle")[0])
        if not verdict:
            continue
        pk = re.search(r"packets (\d+)", s)
        cm = re.search(r'comment "([^"]*)"', s)
        hd = re.search(r"# handle (\d+)", s)
        match = re.split(r"\s+(?:counter\b|accept\b|drop\b|reject\b)", s)[0].strip()
        rules.append({"match": match or "(everything else)", "verdict": verdict[-1],
                      "packets": int(pk.group(1)) if pk else None,
                      "comment": cm.group(1) if cm else "", "handle": hd.group(1) if hd else ""})
    return rules


def op_firewall(runner: Runner, **_) -> DiagResult:
    title = "Firewall rules into Site B (r3)"
    r = runner.exec("r3", ["nft", "-a", "list", "table", "inet", "labfw"])
    if (n := not_run("firewall", title, r)):
        return n
    if r.exit_code != 0:
        return result("firewall", title, "fail", "No firewall table loaded",
                      "Without the labfw table nothing filters traffic into Site B.", [r])
    rules = parse_rules(r.output)
    named = {m.group(1): int(m.group(2)) for m in re.finditer(
        r'counter (\w+) \{[^}]*?packets (\d+)', r.output, re.S)}
    for ru in rules:
        m = re.search(r'counter name "?(\w+)"?', ru["match"])
        if m:
            ru["packets"] = named.get(m.group(1))
            ru["match"] = f"everything else (named counter {m.group(1)})"
    facts = []
    for i, ru in enumerate(rules, 1):
        hits = "no counter" if ru["packets"] is None else f'{ru["packets"]} packets'
        label = f'{i}. {ru["verdict"].upper()} {ru["match"]}'
        facts.append((label, f'{hits}{" · " + ru["comment"] if ru["comment"] else ""}{" · handle " + ru["handle"] if ru["handle"] else ""}'))
    drops = [ru for ru in rules if ru["verdict"] == "drop" and ru["packets"]]
    summary = f"{len(rules)} rules in order" + (f" · drop rules matched {sum(d['packets'] for d in drops)} packets" if drops else "")
    return result("firewall", title, "pass", summary,
                  "Rules are checked top to bottom and the first match wins. Counters show how many "
                  "packets each rule matched: an allow rule stuck at 0 while users fail means something "
                  "above it caught their traffic first. The handle number is how you delete one rule "
                  "(nft delete rule inet labfw to_site_b handle N).", [r], facts)


# ------------------------------------------------------------------ catalog

@dataclass(frozen=True)
class Op:
    id: str
    title: str
    layer: str
    needs: tuple[str, ...]           # target | port | router
    fn: Callable[..., DiagResult]
    tls_only: bool = False
    hint: str = ""


OPS: dict[str, Op] = {o.id: o for o in [
    Op("resolve", "Name resolution", "Layer 7 · DNS", ("target",), op_resolve, hint="Does the name turn into the right address?"),
    Op("ping", "Ping", "Layer 3 · ICMP", ("target",), op_ping, hint="Is the host reachable at the IP level?"),
    Op("traceroute", "Traceroute", "Layer 3 · path", ("target",), op_traceroute, hint="Which routers does the traffic cross?"),
    Op("tcp", "TCP port check", "Layer 4 · TCP", ("target", "port"), op_tcp, hint="Does the port accept a connection? Timeout or refused?"),
    Op("tls", "TLS certificate", "Layer 5-6 · TLS", ("target", "port"), op_tls, tls_only=True, hint="Is the certificate trusted, for the right name, in date?"),
    Op("route", "Route lookup", "Layer 3 · routing", ("router", "target"), op_route, hint="Where does this router send traffic for the target?"),
    Op("ospf_neighbors", "OSPF neighbours", "Layer 3 · OSPF", ("router",), op_ospf_neighbors, hint="Are adjacencies Full?"),
    Op("ospf_interfaces", "OSPF interfaces", "Layer 3 · OSPF", ("router",), op_ospf_interfaces, hint="Compare MTU, cost and timers per link"),
    Op("firewall", "Firewall rules and counters", "Layer 3-4 · nftables", (), op_firewall, hint="Which rule matched the traffic?"),
    Op("rip", "RIP routes", "Layer 3 · RIP", ("router",), op_rip, hint="Only when the RIP exercise is enabled"),
]}


def catalog() -> dict:
    return {
        "ops": [{"id": o.id, "title": o.title, "layer": o.layer, "needs": list(o.needs),
                 "tls_only": o.tls_only, "hint": o.hint} for o in OPS.values()],
        "targets": [{"id": t.id, "host": t.host, "ip": t.ip, "label": t.label,
                     "ports": [{"number": p.number, "label": p.label, "tls": p.tls is not None, "note": p.note}
                               for p in t.ports]} for t in TARGETS.values()],
        "routers": list(ROUTERS),
        "vantage": "toolbox (Site A, 10.10.10.10)",
    }


def run_op(runner: Runner, op_id: str, target: str | None = None, port: int | None = None,
           router: str | None = None) -> DiagResult:
    op = OPS.get(op_id)
    if not op:
        raise InvalidRequest(f"unknown operation; choose one of: {', '.join(OPS)}")
    kwargs: dict = {}
    if "target" in op.needs:
        kwargs["target"] = get_target(target)
    if "port" in op.needs:
        if port is None:
            raise InvalidRequest("port is required")
        kwargs["port"] = port
    if "router" in op.needs:
        kwargs["router"] = get_router(router)
    return op.fn(runner, **kwargs)


# ------------------------------------------------------------------ guided diagnosis

def diagnose(runner: Runner, target_id: str | None, port: int | None) -> WizardResult:
    """Walk up the stack from Site A to one service and say where it breaks."""
    t = get_target(target_id)
    p = get_port(t, port)
    steps: list[WizardStep] = []

    def step(label: str, res: DiagResult) -> DiagResult:
        steps.append(WizardStep(label=label, result=res))
        return res

    dns = step("1. Name resolution", op_resolve(runner, t))
    if dns.status != "pass":
        return WizardResult(target=t.id, port=p.number, steps=steps, verdict="fail",
                            layer="Name resolution",
                            conclusion="The name does not resolve correctly, so every later step would fail. Fix name resolution first.")
    ping = step("2. Reachability (ping)", op_ping(runner, t))
    trace = step("3. Path (traceroute)", op_traceroute(runner, t))  # noqa: F841 (used below)
    tcp = step(f"4. TCP port {p.number}", op_tcp(runner, t, port=p.number))
    tls = step(f"5. TLS on {p.number}", op_tls(runner, t, port=p.number)) if p.tls is not None and tcp.status == "pass" else None

    if tcp.status == "pass":
        if tls and tls.status == "fail":
            return WizardResult(target=t.id, port=p.number, steps=steps, verdict="fail", layer="TLS",
                                conclusion=f"The network path and the port are fine, but the TLS check failed: {tls.summary}. "
                                           "Clients that verify certificates will refuse to connect.")
        hops = parse_trace(trace.evidence[-1].output) if trace.evidence else []
        note = " Traffic is taking the slow backup path (r1 → r3), though." if uses_backup(hops) else ""
        return WizardResult(target=t.id, port=p.number, steps=steps, verdict="warn" if note else "pass",
                            layer="Network path" if note else "None found",
                            conclusion="From Site A the name resolves, the host answers, the port accepts connections"
                                       + (" and the certificate is trusted" if tls else "") + "." + note +
                                       " If users still fail, look higher up: authentication, permissions or the application.")
    if "refused" in tcp.summary.lower():
        return WizardResult(target=t.id, port=p.number, steps=steps, verdict="fail", layer="Service (port closed)",
                            conclusion="Packets reach the host, which actively refuses the port. Nothing is listening there: "
                                       "check that the service is running and on the expected port.")
    if ping.status in ("pass", "warn"):
        return WizardResult(target=t.id, port=p.number, steps=steps, verdict="fail", layer="Firewall (port filtered)",
                            conclusion="The host answers ping, so routing works, yet this port times out with no reply. "
                                       "Something on the path silently drops this port: check the firewall rules and counters on r3.")
    return WizardResult(target=t.id, port=p.number, steps=steps, verdict="fail", layer="Routing",
                        conclusion="The host cannot be reached at the IP level and the path stops early. Check routing and "
                                   "links from the last router that answered (OSPF neighbours, interfaces, routes).")
