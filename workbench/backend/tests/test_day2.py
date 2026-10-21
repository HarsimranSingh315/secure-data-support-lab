"""Day 2: network map and diagnostics, tested against REAL recorded sessions.

tests/fixtures/day2/session_*.json are every command the map and the guided diagnosis ran,
with real output, recorded from a namespace replica of the lab (same router templates and
firewall rules, FRR, nftables, PostgreSQL 16 with TLS, OpenSSL servers) in four states.
The single-file fixtures are individual real captures (see fixtures/day2/README.md).
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from app.diagnostics import (InvalidRequest, catalog, days_left, diagnose, parse_ping, parse_rules,
                             parse_tls, parse_trace, run_op)
from app.runner import ExecResult
from app.topology import collect

FIX = Path(__file__).parent / "fixtures" / "day2"


def fx(name: str) -> str:
    return (FIX / name).read_text()


class ReplayRunner:
    """Answers each command with the output recorded from the replica lab."""

    def __init__(self, session: str, override: dict | None = None, stopped=()):
        self.log = json.loads(fx(f"session_{session}.json"))
        self.override = override or {}
        self.stopped = set(stopped)
        self.calls: list[tuple[str, list[str]]] = []

    def state(self, service):
        return "exited" if service in self.stopped else "running"

    def exec(self, service, argv, timeout=5, env=None):
        self.calls.append((service, list(argv)))
        r = ExecResult(service=service, command=list(argv), env=env or {})
        if service in self.stopped:
            r.error = "container_not_running"
            return r
        key = service + " " + " ".join(argv)
        if key in self.override:
            rec = self.override[key]
        else:
            recs = self.log.get(key)
            if not recs:
                raise AssertionError(f"command not in recorded session: {key}")
            # replay repeated commands in the order they were recorded, then keep the last
            rec = recs.pop(0) if len(recs) > 1 else recs[0]
        r.exit_code, r.output, r.error = rec["exit_code"], rec["output"], rec["error"]
        return r


def by_id(items, i):
    return next(x for x in items if x.id == i)


# ------------------------------------------------------------------ network map

def test_map_healthy():
    t = collect(ReplayRunner("healthy"))
    assert [r.status for r in t.routers] == ["ok", "ok", "ok"]
    assert {l.id: l.status for l in t.links} == {k: "ok" for k in ("lan_a", "r1_r2", "r2_r3", "r1_r3", "lan_b")}
    assert by_id(t.links, "r1_r3").summary == "OSPF adjacency Full · cost 100"
    assert by_id(t.links, "r1_r2").summary == "OSPF adjacency Full · cost 10"
    assert t.path.reached and not t.path.uses_backup
    assert t.path.links == ["lan_a", "r1_r2", "r2_r3", "lan_b"]
    assert t.path.summary == "toolbox → r1 → r2 → r3 → db"
    r1 = by_id(t.routers, "r1")
    db_route = next(r for r in r1.routes if r.prefix == "10.20.20.0/24")
    assert (db_route.protocol, db_route.next_hop, db_route.metric) == ("ospf", "10.0.12.12", 30)


def test_map_core_link_down_moves_path_to_backup():
    t = collect(ReplayRunner("core_link_down"))
    link = by_id(t.links, "r1_r2")
    assert link.status == "down" and "r2" in link.summary and "DOWN" in link.summary
    assert by_id(t.routers, "r1").status == "degraded"           # lost one of two neighbours
    assert t.path.uses_backup and t.path.links == ["lan_a", "r1_r3", "lan_b"]
    r1 = by_id(t.routers, "r1")
    assert next(r for r in r1.routes if r.prefix == "10.20.20.0/24").next_hop == "10.0.13.13"


def test_map_mtu_mismatch_shows_stuck_adjacency_and_both_mtus():
    t = collect(ReplayRunner("ospf_mtu"))
    link = by_id(t.links, "r2_r3")
    assert link.status == "degraded"
    assert "not Full" in link.summary and "ExStart" in link.summary
    assert sorted(e.mtu for e in link.ends) == [1400, 1500]       # the evidence an engineer compares
    assert "MTU" not in link.summary                               # ...but the map does not name the cause
    assert t.path.uses_backup


def test_map_router_container_stopped():
    t = collect(ReplayRunner("healthy", stopped={"r2"}))
    assert by_id(t.routers, "r2").status == "down"
    assert by_id(t.links, "r1_r2").status == "unknown"
    assert by_id(t.links, "r1_r3").status == "ok"


def test_map_toolbox_stopped_means_no_path_not_a_wrong_path():
    t = collect(ReplayRunner("healthy", stopped={"toolbox"}))
    assert not t.path.reached and t.path.links == [] and "toolbox" in t.path.summary


# ------------------------------------------------------------------ guided diagnosis (real sessions)

@pytest.mark.parametrize("session,verdict,layer", [
    ("healthy", "pass", "None found"),
    ("firewall_drop", "fail", "Firewall (port filtered)"),
    ("core_link_down", "warn", "Network path"),
    ("ospf_mtu", "warn", "Network path"),
])
def test_guided_diagnosis_finds_the_right_layer(session, verdict, layer):
    w = diagnose(ReplayRunner(session), "db", 5432)
    assert (w.verdict, w.layer) == (verdict, layer)


def test_firewall_drop_evidence_is_in_the_rule_list():
    d = run_op(ReplayRunner("firewall_drop"), "firewall")
    first = d.facts[0]
    assert first.label.startswith("1. DROP ip daddr 10.20.20.10 tcp dport 5432")
    assert "CHG-1042" in first.value and "handle 14" in first.value
    assert "drop rules matched" in d.summary


def test_mtu_session_ospf_interfaces_show_the_mismatch():
    r = ReplayRunner("ospf_mtu")
    r2 = {f.label: f.value for f in run_op(r, "ospf_interfaces", router="r2").facts}
    r3 = {f.label: f.value for f in run_op(r, "ospf_interfaces", router="r3").facts}
    assert "MTU 1400" in r2["eth1"] and "10.0.23.22/24 ·" in r2["eth1"]
    assert "MTU 1500" in r3["eth1"]
    assert run_op(r, "ospf_neighbors", router="r2").status == "warn"


# ------------------------------------------------------------------ single real captures

def tb(output: str, exit_code: int, error: str | None = None) -> dict:
    return {"exit_code": exit_code, "output": output, "error": error}


TLS_KEY = "toolbox bash -c {s} db.site-b.lab 5432 -starttls postgres"


def run_with(op, kw, key, rec):
    r = ReplayRunner("healthy")
    real_exec = r.exec

    def exec_(service, argv, timeout=5, env=None):
        k = service + " " + " ".join(argv)
        if k.startswith(key):
            res = ExecResult(service=service, command=list(argv))
            res.exit_code, res.output, res.error = rec["exit_code"], rec["output"], rec["error"]
            return res
        return real_exec(service, argv, timeout, env)
    r.exec = exec_
    return run_op(r, op, **kw)


def test_tcp_refused_vs_timeout():
    refused = run_with("tcp", {"target": "ldap", "port": 636}, "toolbox timeout 3 bash", tb(fx("tcp_refused.txt"), 1))
    assert refused.summary.startswith("Connection refused")
    timeout = run_with("tcp", {"target": "db", "port": 5432}, "toolbox timeout 3 bash", tb(fx("tcp_timeout.txt"), 124, "timeout"))
    assert timeout.summary.startswith("Timed out") and "firewall" in timeout.meaning


@pytest.mark.parametrize("file,expect", [
    ("tls_db_wrongname.txt", "hostname mismatch"),
    ("tls_kms_untrusted.txt", "self-signed certificate"),
    ("tls_app_expired.txt", "certificate has expired"),
])
def test_tls_failures_are_named(file, expect):
    d = run_with("tls", {"target": "db", "port": 5432}, "toolbox bash -c openssl", tb(fx(file), 0))
    assert d.status == "fail" and d.summary == f"Not trusted: {expect}"
    assert "Re-issue" in d.meaning or "self" in d.meaning or "Renew" in d.meaning


def test_tls_connection_refused_is_not_called_a_certificate_problem():
    d = run_with("tls", {"target": "app", "port": 8443}, "toolbox bash -c openssl", tb(fx("tls_refused.txt"), 0))
    assert d.status == "fail" and d.summary == "Could not connect to start TLS"


def test_tls_ok_parses_certificate_details():
    t = parse_tls(fx("tls_db_ok.txt"))
    assert t["ok"] and t["protocol"] == "TLSv1.3"
    assert t["san"] == "DNS:db.site-b.lab, IP Address:10.20.20.10"
    assert days_left(t["not_after"], datetime(2027, 11, 1, tzinfo=timezone.utc)) == 20


def test_ping_ttl_counts_routers():
    p = parse_ping(fx("ping_ok.txt"))
    assert (p["sent"], p["received"], p["loss"], p["ttl"]) == (3, 3, 0.0, 61)


def test_traceroute_parsing():
    assert parse_trace(fx("trace_backup.txt")) == ["10.10.10.2", "10.0.13.13", "10.20.20.10"]


def test_rules_parser_reads_real_listing_in_order():
    rules = parse_rules(fx("nft_a_ok.txt"))
    assert [r["verdict"] for r in rules] == ["accept", "drop", "accept", "accept", "accept", "accept", "accept", "drop"]
    assert rules[-1]["match"] == "(everything else)" or rules[-1]["match"].startswith("counter")


def test_resolution_failure():
    d = run_with("resolve", {"target": "db"}, "toolbox getent", tb("", 2))
    assert d.status == "fail" and d.summary == "Name does not resolve"


def test_rip_not_running_is_info_not_failure():
    d = run_with("rip", {"router": "r1"}, "r1 vtysh -c show ip rip", tb(fx("rip_off.txt"), 1))
    assert d.status == "info"


# ------------------------------------------------------------------ input validation

@pytest.mark.parametrize("kw", [
    {"op": "rm"}, {"op": "ping", "target": "8.8.8.8"}, {"op": "ping", "target": "db; reboot"},
    {"op": "tcp", "target": "db", "port": 3306}, {"op": "tls", "target": "db", "port": 22},
    {"op": "route", "target": "db", "router": "toolbox"}, {"op": "tcp", "target": "db"},
])
def test_anything_outside_the_allow_list_is_rejected_before_running(kw):
    r = ReplayRunner("healthy")
    with pytest.raises(InvalidRequest):
        run_op(r, kw.pop("op"), **kw)
    assert r.calls == []


def test_catalog_lists_only_defined_ports():
    c = catalog()
    db = next(t for t in c["targets"] if t["id"] == "db")
    assert [p["number"] for p in db["ports"]] == [5432, 22]
    assert {o["id"] for o in c["ops"]} >= {"ping", "traceroute", "tcp", "tls", "route", "firewall"}


def test_values_reach_bash_as_arguments_not_script_text():
    r = ReplayRunner("healthy")
    run_op(r, "tcp", target="db", port=5432)
    svc, argv = r.calls[0]
    assert argv[:4] == ["timeout", "3", "bash", "-c"]
    assert "db.site-b.lab" not in argv[4] and argv[5:] == ["db.site-b.lab", "5432"]


# ------------------------------------------------------------------ API

@pytest.fixture()
def api():
    from fastapi.testclient import TestClient

    from app.main import create_app
    return TestClient(create_app(ReplayRunner("healthy")))


def test_api_topology_and_diagnostics(api):
    t = api.get("/api/topology").json()
    assert t["path"]["summary"] == "toolbox → r1 → r2 → r3 → db"
    d = api.get("/api/diagnostics/traceroute", params={"target": "db"}).json()
    assert d["status"] == "pass" and d["evidence"][0]["service"] == "toolbox"
    w = api.get("/api/diagnose", params={"target": "db", "port": 5432}).json()
    assert w["verdict"] == "pass" and len(w["steps"]) == 5


def test_api_rejects_bad_input_with_400(api):
    assert api.get("/api/diagnostics/ping", params={"target": "evil"}).status_code == 400
    assert api.get("/api/diagnostics/nope").status_code == 400
    assert api.get("/api/diagnostics/tcp", params={"target": "db", "port": 70000}).status_code == 422
    assert api.get("/api/diagnose", params={"target": "db", "port": 3306}).status_code == 400


def test_api_is_still_read_only(api):
    methods = {m for r in api.app.routes for m in (getattr(r, "methods", None) or ())}
    assert methods <= {"GET", "HEAD"}


def test_api_limits_parallel_diagnostics():
    from fastapi.testclient import TestClient

    import app.main as m
    app = m.create_app(ReplayRunner("healthy"))
    c = TestClient(app)
    sem = next(cell.cell_contents for r in app.routes if getattr(r, "path", "") == "/api/diagnose"
               for cell in (r.endpoint.__closure__ or ()) if callable(cell.cell_contents) and cell.cell_contents.__name__ == "limited").__closure__
    slots = next(c.cell_contents for c in sem if hasattr(c.cell_contents, "acquire"))
    for _ in range(m.MAX_PARALLEL_DIAG):
        slots.acquire()
    try:
        assert c.get("/api/diagnostics/ping", params={"target": "db"}).status_code == 429
    finally:
        for _ in range(m.MAX_PARALLEL_DIAG):
            slots.release()


def test_traceroute_retries_once_when_icmp_rate_limit_hides_the_last_hop():
    """Recorded for real: during the outage sessions the second trace ended in '*' (ICMP replies
    are rate-limited) and the retry reached the database."""
    r = ReplayRunner("core_link_down")
    r.log["toolbox traceroute -n -w 1 -q 1 -m 8 db.site-b.lab"].pop(0)   # start at the silent run
    d = run_op(r, "traceroute", target="db")
    assert d.status == "warn" and "backup link" in d.summary
    assert len(d.evidence) == 2 and any(f.label == "note" for f in d.facts)
    assert "10.20.20.10" not in d.evidence[0].output.splitlines()[-1]


def test_asymmetric_reply_address_is_not_mistaken_for_the_backup_link():
    """Observed once in the replica while OSPF was reconverging (the guided diagnosis reported
    "r1 -> r2 -> r3 -> db (backup link)" because hop 3 answered from 10.0.13.13). It could not be
    re-captured on demand, so this trace is typed to match that observation."""
    from app.diagnostics import uses_backup
    from app.topology import _path
    hops_out = ("traceroute to db.site-b.lab (10.20.20.10), 8 hops max, 60 byte packets\n"
                " 1  10.10.10.2  0.05 ms\n 2  10.0.12.12  0.04 ms\n 3  10.0.13.13  0.05 ms\n 4  10.20.20.10  0.06 ms\n")
    r = ExecResult(service="toolbox", command=["traceroute"], exit_code=0, output=hops_out)
    assert not uses_backup(parse_trace(hops_out))
    p = _path([r])
    assert p.links == ["lan_a", "r1_r2", "r2_r3", "lan_b"] and not p.uses_backup
    assert p.notes and "asymmetric" in p.notes[0]


def test_named_default_deny_counter_is_reported():
    d = run_op(ReplayRunner("healthy"), "firewall")
    last = d.facts[-1]
    assert "everything else" in last.label and "packets" in last.value and "no counter" not in last.value
