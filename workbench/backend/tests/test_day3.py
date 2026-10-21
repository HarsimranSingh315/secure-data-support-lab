"""Day 3: incident library (Break / Hint / Fix) and packet captures.

Incidents: the tests run the lab's REAL scripts/scenario.sh. Only `docker compose` is replaced
(LAB_COMPOSE) by a stub that records each call, so the script's own logic, ticket text and
hints are exercised exactly as on the Mac.

Captures: tests/fixtures/day3/cap_*.pcap are real captures from the namespace replica of the lab,
and cap_*.json the real tshark output for them (see fixtures/day3/README.md). The replay runner
answers tshark with that output, so the analysis is tested on what tshark really printed.
"""
from __future__ import annotations

import json
import re
import stat
from pathlib import Path

import pytest

from app import captures as C
from app import incidents as I
from app.runner import ExecResult

FIX = Path(__file__).parent / "fixtures" / "day3"
REPO = Path(__file__).resolve().parents[3]


# ------------------------------------------------------------------ incidents (real scenario.sh)

@pytest.fixture()
def lab(tmp_path, monkeypatch):
    calls = tmp_path / "compose-calls.txt"
    stub = tmp_path / "compose-stub.sh"
    stub.write_text(f'#!/bin/sh\necho "$*" >> {calls}\n')
    stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("LAB_COMPOSE", str(stub))
    monkeypatch.setattr(I, "REPO", REPO)
    monkeypatch.setattr(I, "DATA", tmp_path / "data")
    return calls


def test_catalog_matches_the_scenario_script():
    script = (REPO / "scripts" / "scenario.sh").read_text()
    names = re.search(r'SCENARIOS="([^"]+)"', script).group(1).split()
    assert names == I.IDS


def test_neutral_titles_do_not_give_away_the_cause(lab):
    reveals = I.describe_all()
    assert set(reveals) == set(I.IDS)
    for inc in I.list_incidents():
        assert inc.reveal is None and inc.state == "ready"
        assert "MTU" not in inc.title and "firewall" not in inc.title.lower() and "seal" not in inc.title.lower()


def test_break_hint_fix_lifecycle_runs_the_real_script(lab):
    inc = I.act("firewall-drop", "break")
    assert inc.state == "active" and inc.ticket_id == "INC-2103" and inc.priority == "P1"
    assert inc.customer.startswith("Our analysts in Site A cannot connect")
    assert inc.reveal is None
    calls = lab.read_text()
    assert "exec -T r3 nft insert rule inet labfw to_site_b ip daddr 10.20.20.10 tcp dport 5432" in calls

    inc = I.act("firewall-drop", "hint")
    assert inc.hints and "Capture on r3" in inc.hints[0]
    inc = I.act("firewall-drop", "hint")
    assert len(inc.hints) == 1                      # same hint is not stored twice

    with pytest.raises(I.IncidentError) as e:
        I.act("firewall-drop", "break")
    assert e.value.status == 409

    inc = I.act("firewall-drop", "fix")
    assert inc.state == "resolved" and inc.minutes_to_resolve is not None
    assert inc.reveal == "Firewall: a change ticket added a rule that blocks the database"
    assert "exec -T r3 nft -f /etc/lab/nftables.nft" in lab.read_text()

    actions = I.recent_actions()
    assert [a["action"] for a in actions[:3]] == ["fix", "hint", "hint"] and all(a["ok"] for a in actions)


def test_hint_requires_an_active_incident(lab):
    with pytest.raises(I.IncidentError) as e:
        I.act("brute-force", "hint")
    assert e.value.status == 409


def test_unknown_incident_and_action_are_rejected_before_running(lab):
    with pytest.raises(I.IncidentError) as e:
        I.act("rm -rf", "break")
    assert e.value.status == 404
    with pytest.raises(I.IncidentError):
        I.act("firewall-drop", "list")
    assert not lab.exists()


def test_failed_script_is_reported_and_state_unchanged(lab, monkeypatch, tmp_path):
    bad = tmp_path / "fail.sh"
    bad.write_text("#!/bin/sh\necho 'Error response from daemon: No such container' >&2\nexit 1\n")
    bad.chmod(0o755)
    monkeypatch.setenv("LAB_COMPOSE", str(bad))
    with pytest.raises(I.IncidentError) as e:
        I.act("core-link-down", "break")
    assert e.value.status == 502 and "No such container" in str(e.value)
    assert I.get("core-link-down").state == "ready"


def test_runbook_is_served_and_path_is_fixed(lab):
    md = I.runbook("ospf-mtu")
    assert md.startswith("#")
    with pytest.raises(I.IncidentError):
        I.runbook("../../etc/passwd")


def test_state_survives_a_restart(lab):
    I.act("kms-sealed", "break")
    assert json.loads((I.DATA / "incidents.json").read_text())["kms-sealed"]["state"] == "active"
    assert I.get("kms-sealed").state == "active"


# ------------------------------------------------------------------ captures (real tshark output)

def norm(cmd: str) -> str:
    return re.sub(r"/tmp/wb-[a-z]+-[\d-]+[0-9a-f]{4}\.pcap", "/tmp/X.pcap", cmd)


class CapRunner:
    """tcpdump 'captures' the recorded pcap; tshark answers with what it printed for that file."""

    def __init__(self, name: str):
        rec = json.loads((FIX / f"cap_{name}.json").read_text())
        self.answers = {norm(k): v[-1] for k, v in rec["commands"].items()}
        self.pcap = (FIX / f"cap_{name}.pcap").read_bytes()
        self.calls: list[tuple[str, list[str]]] = []
        self.files: dict[str, bytes] = {}

    def state(self, service):
        return "running"

    def exec(self, service, argv, timeout=5, env=None, limit=8000):
        self.calls.append((service, list(argv)))
        r = ExecResult(service=service, command=list(argv))
        if "tcpdump" in argv:
            # tcpdump stopped by `timeout -s INT` exits 124 and prints its summary line
            r.exit_code, r.error, r.output = 124, "timeout", "4 packets captured\n4 packets received by filter\n"
            return r
        if argv[0] in ("rm", "curl", "ping", "bash", "timeout", "traceroute"):
            r.exit_code = 0
            return r
        rec = self.answers.get(norm(service + " " + " ".join(argv)))
        if rec is None:
            raise AssertionError("not recorded: " + service + " " + " ".join(argv))
        r.exit_code, r.output, r.error = rec["exit_code"], rec["output"], rec["error"]
        return r

    def get_file(self, service, path, limit):
        return self.pcap

    def put_file(self, service, path, data):
        self.files[path] = data


@pytest.fixture()
def store(tmp_path, monkeypatch):
    monkeypatch.setattr(C, "DATA_DIR", tmp_path / "captures")
    return tmp_path


def run_cap(name: str):
    rec = json.loads((FIX / f"cap_{name}.json").read_text())
    point, flt, secs, traffic = rec["args"]
    return C.capture(CapRunner(name), point, flt, int(secs), traffic, traffic_fn=lambda r, t: [])


def titles(an):
    return [(f.severity, f.title) for f in an.findings]


def test_healthy_database_traffic(store):
    an = run_cap("healthy_db")
    assert an.meta.packets == 45 and len(an.conversations) == 3
    assert all(c.state == "established" for c in an.conversations)
    assert all(s == "pass" for s, _ in titles(an))
    assert "PGSQL" in next(s.value for s in an.stats if s.label == "protocols")


@pytest.mark.parametrize("name", ["firewall_drop_r3", "firewall_drop_toolbox"])
def test_firewall_drop_shows_unanswered_syns(store, name):
    an = run_cap(name)
    assert {c.state for c in an.conversations} == {"no answer"}
    assert any(p.flags == ["SYN"] and "retransmission" in p.marks for p in an.packets)
    sev, title = titles(an)[0]
    assert sev == "fail" and title.startswith("No reply to connection attempts: toolbox (10.10.10.10")


def test_refused_is_a_reset_not_silence(store):
    an = run_cap("refused")
    assert an.conversations[0].state == "refused"
    assert titles(an)[0] == ("fail", "Connection refused: ldap (10.10.10.20:636) answered with a reset")


def test_tls_wrong_name_shows_the_client_alert_first(store):
    an = run_cap("tls_wrongname")
    sev, title = titles(an)[0]
    assert sev == "fail" and title == "TLS alert: bad certificate (sent by toolbox (10.10.10.10))"
    assert any("tls_alert" in p.marks for p in an.packets)


@pytest.mark.parametrize("name,expect", [
    ("ospf_mtu_r3", "r2 (10.0.23.22) advertises MTU 1400; the capturing router's interface on that link (eth1) has MTU 1500"),
    ("ospf_mtu_r2", "r3 (10.0.23.23) advertises MTU 1500; the capturing router's interface on that link (eth1) has MTU 1400"),
])
def test_ospf_mtu_mismatch_is_proven_from_packets(store, name, expect):
    an = run_cap(name)
    sev, title = titles(an)[0]
    assert sev == "fail" and title == "OSPF neighbours disagree on MTU: " + expect


def test_healthy_ospf_is_just_hellos(store):
    an = run_cap("ospf_ok_r3")
    assert [s for s, _ in titles(an)] == ["info"] and "Hello" in titles(an)[0][1]


def test_icmp_unreachable_and_ping(store):
    assert titles(run_cap("unreachable"))[0][1] == "2 ICMP destination unreachable message(s)"
    assert titles(run_cap("ping")) == [("pass", "3 ping replies")]


def test_capture_command_is_fixed_and_router_captures_inbound_only(store):
    r = CapRunner("firewall_drop_r3")
    C.capture(r, "r3", "db", 6, "none")
    svc, argv = next(c for c in r.calls if "tcpdump" in c[1])
    assert svc == "r3"
    assert argv[:6] == ["timeout", "-s", "INT", "6", "tcpdump", "-ni"]
    assert ["-Q", "in"] == argv[7:9] and argv[-3:] == ["tcp", "port", "5432"]
    assert "-s" in argv and argv[argv.index("-s", 5) + 1] == "256"


@pytest.mark.parametrize("args", [("db", "db", 5, "none"), ("r3", "tcp port 22", 5, "none"),
                                  ("r3", "db", 300, "none"), ("r3", "db", 5, "curl evil")])
def test_capture_parameters_outside_the_allow_list_are_refused(store, args):
    r = CapRunner("ping")
    with pytest.raises(C.CaptureError):
        C.capture(r, *args)
    assert r.calls == []


def test_saved_capture_can_be_listed_loaded_and_downloaded(store):
    an = run_cap("refused")
    assert [m.id for m in C.list_captures()] == [an.meta.id]
    assert C.load(an.meta.id).findings == an.findings
    assert C.pcap_bytes(an.meta.id) == (FIX / "cap_refused.pcap").read_bytes()
    with pytest.raises(C.CaptureError):
        C.load("../../etc/passwd")


def test_upload_checks_magic_and_size(store):
    r = CapRunner("ping")
    with pytest.raises(C.CaptureError, match="not a pcap"):
        C.upload(r, b"<html>not a capture</html>", "x.pcap")
    with pytest.raises(C.CaptureError, match="too large"):
        C.upload(r, b"\xd4\xc3\xb2\xa1" + b"\0" * C.MAX_FILE, "big.pcap")
    an = C.upload(r, (FIX / "cap_ping.pcap").read_bytes(), "../../evil name.pcap")
    assert an.meta.source == "upload" and an.meta.point_label == "Uploaded: .._.._evil_name.pcap"
    assert titles(an) == [("pass", "3 ping replies")]


def test_packet_detail_splits_tree_and_hex(store):
    an = run_cap("tls_wrongname")

    class DetailRunner(CapRunner):
        def exec(self, service, argv, timeout=5, env=None, limit=8000):
            if "-V" in argv:
                r = ExecResult(service=service, command=list(argv), exit_code=0,
                               output=(FIX / "detail_tls_alert.txt").read_text())
                return r
            return super().exec(service, argv, timeout, env, limit)

    d = C.packet_detail(DetailRunner("tls_wrongname"), an.meta.id, 20)
    assert "Description: Bad Certificate (42)" in d["tree"] and d["hex"].startswith("0000")
    with pytest.raises(C.CaptureError):
        C.packet_detail(DetailRunner("tls_wrongname"), an.meta.id, 10_000)


# ------------------------------------------------------------------ API guard (CSRF) and wiring

@pytest.fixture()
def api(store, lab, monkeypatch):
    from fastapi.testclient import TestClient

    from app.main import create_app
    return TestClient(create_app(CapRunner("ping")))


H = {"X-Workbench-Action": "1"}


def test_actions_need_the_header(api):
    assert api.post("/api/incidents/firewall-drop/break").status_code == 403
    assert api.post("/api/captures", json={"point": "toolbox", "filter": "icmp"}).status_code == 403


def test_cross_origin_and_cross_site_requests_are_refused(api):
    assert api.post("/api/incidents/firewall-drop/break", headers={**H, "Origin": "https://evil.example"}).status_code == 403
    assert api.post("/api/incidents/firewall-drop/break", headers={**H, "Sec-Fetch-Site": "cross-site"}).status_code == 403


def test_incident_api_flow(api):
    r = api.post("/api/incidents/firewall-drop/break", headers={**H, "Origin": "http://testserver"})
    assert r.status_code == 200 and r.json()["state"] == "active"
    assert api.get("/api/incidents").json()[2]["ticket_id"] == "INC-2103"
    assert api.post("/api/incidents/nope/break", headers=H).status_code == 404
    assert api.post("/api/incidents/firewall-drop/fix", headers=H).json()["reveal"].startswith("Firewall")
    assert api.get("/api/actions").json()[0]["action"] == "fix"
    assert "#" in api.get("/api/incidents/ospf-mtu/runbook").json()["markdown"]


def test_capture_api_flow(api):
    body = {"point": "toolbox", "filter": "icmp", "seconds": 4, "traffic": "ping_db"}
    r = api.post("/api/captures", json=body, headers=H)
    assert r.status_code == 200
    cid = r.json()["meta"]["id"]
    assert api.get("/api/captures").json()[0]["id"] == cid
    pcap = api.get(f"/api/captures/{cid}/pcap")
    assert pcap.headers["content-type"] == "application/vnd.tcpdump.pcap" and pcap.content[:4] in (b"\xd4\xc3\xb2\xa1", b"\x0a\x0d\x0d\x0a")
    assert api.post("/api/captures", json={**body, "point": "kms"}, headers=H).status_code == 400
    assert api.get("/api/captures/20990101-000000-abcd").status_code == 404
    up = api.post("/api/captures/upload?filename=x.pcap", content=b"nope", headers=H)
    assert up.status_code == 400
