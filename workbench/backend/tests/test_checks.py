"""Overview checks against REAL command output captured from the same tools the lab runs
(FRR, nftables, OpenBao 2.4.4, pg_isready, ldapwhoami, curl) - see tests/fixtures/README.md.

Covers the three cases the plan requires: success, failure, and service unavailable.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

os.environ["WB_NO_AUTOAPP"] = "1"

from app.checks import SPECS, parse_nft, parse_ospf_neighbors, run_check  # noqa: E402
from app.main import Monitor, create_app, overall_status  # noqa: E402
from app.runner import ExecResult  # noqa: E402

FIX = Path(__file__).parent / "fixtures"


def fx(name: str) -> str:
    return (FIX / name).read_text()


def two_full() -> str:
    """Each lab router has two neighbours: the real Full entry, used for both."""
    import json
    entry = next(iter(json.loads(fx("ospf_full.json"))["neighbors"].values()))
    return json.dumps({"neighbors": {"10.0.0.1": entry, "10.0.0.2": entry}})


HEALTHY = {
    "r1": (0, two_full()), "r2": (0, two_full()), "r3": (0, two_full()),
    ("r3", "nft"): (0, fx("nft_ok.txt")),
    ("toolbox", "ldapwhoami"): (0, "anonymous\n"),
    ("toolbox", "pg_isready"): (0, "db.site-b.lab:5432 - accepting connections\n"),
    ("toolbox", "curl"): (0, '{"db": "ok", "kms": "ok"}\n200'),
    "kms": (0, fx("bao_unsealed.json")),
    "dam": (0, "0\n"),
}


class FakeRunner:
    """Answers like DockerRunner, from a table of (service, program) -> (exit code, output)."""

    def __init__(self, answers=None, stopped=(), docker_down=False, timeouts=()):
        self.answers = {**HEALTHY, **(answers or {})}
        self.stopped, self.docker_down, self.timeouts = set(stopped), docker_down, set(timeouts)
        self.calls: list[tuple[str, list[str]]] = []

    def state(self, service):
        if self.docker_down:
            return "docker_unavailable"
        return "exited" if service in self.stopped else "running"

    def exec(self, service, argv, timeout=5, env=None):
        self.calls.append((service, argv))
        r = ExecResult(service=service, command=argv, env=env or {})
        st = self.state(service)
        if st != "running":
            r.error = "docker_unavailable" if st == "docker_unavailable" else "container_not_running"
            return r
        if (service, argv[0]) in self.timeouts:
            r.exit_code, r.error = 137, "timeout"
            return r
        r.exit_code, r.output = self.answers.get((service, argv[0]), self.answers.get(service, (0, "")))
        return r


def run(spec_id: str, runner) -> object:
    return run_check(runner, next(s for s in SPECS if s.id == spec_id))


# ------------------------------------------------------------------ parsers

def test_parse_ospf_full_real_frr_output():
    n = parse_ospf_neighbors(fx("ospf_full.json"))
    assert n == [{"router_id": "10.9.0.2", "state": "Full", "iface": "va", "address": "10.9.0.2"}]


def test_parse_ospf_mtu_mismatch_states():
    assert parse_ospf_neighbors(fx("ospf_exstart.json"))[0]["state"] == "ExStart"
    assert parse_ospf_neighbors(fx("ospf_exchange.json"))[0]["state"] == "Exchange"


def test_parse_ospf_old_style_and_empty():
    assert parse_ospf_neighbors('{"neighbors":{"1.1.1.1":[{"nbrState":"Full/DR"}]}}')[0]["state"] == "Full"
    assert parse_ospf_neighbors("{}") == []


def test_parse_nft_real_listing():
    p = parse_nft(fx("nft_ok.txt"))
    assert p["dropped"] == 0
    assert [c for c, _ in p["accepts"]] == ["site A -> PostgreSQL (TLS)", "site A -> KMS API (TLS)",
                                             "site A -> app (HTTPS)"]
    assert p["rules"] == 8


# ------------------------------------------------------------------ success

def test_all_healthy_is_ok():
    r = FakeRunner()
    checks = [run_check(r, s) for s in SPECS]
    assert {c.id: c.status for c in checks} == {s.id: "ok" for s in SPECS}
    assert overall_status(checks) == "ok"
    assert all(c.source == "live" and c.evidence for c in checks)


def test_evidence_shows_exact_command_and_where_it_ran():
    c = run("ldap", FakeRunner())
    ev = c.evidence[0]
    assert ev.service == "toolbox"
    assert ev.command == "LDAPTLS_CACERT=/lab-certs/ca-chain.pem ldapwhoami -x -ZZ -o nettimeout=3 -H ldap://ldap.site-a.lab"
    assert ev.repro == "docker compose exec -e LDAPTLS_CACERT=/lab-certs/ca-chain.pem toolbox ldapwhoami -x -ZZ -o nettimeout=3 -H ldap://ldap.site-a.lab"
    assert ev.exit_code == 0


# ------------------------------------------------------------------ failure

def test_ospf_one_neighbour_stuck_is_degraded():
    import json
    # Combine the two real captures: one neighbour Full, one stuck after the MTU change.
    full = json.loads(fx("ospf_full.json"))["neighbors"]
    stuck = json.loads(fx("ospf_exstart.json"))["neighbors"]
    two = json.dumps({"neighbors": {**full, "10.9.0.9": next(iter(stuck.values()))}})
    c = run("r2", FakeRunner({"r2": (0, two)}))
    assert c.status == "degraded"
    assert "1/2" in c.summary and "ExStart" in c.summary


def test_ospf_no_neighbours_is_down():
    c = run("r1", FakeRunner({"r1": (0, fx("ospf_exstart.json"))}))
    assert c.status == "down" and "0/2" in c.summary


def test_firewall_missing_table_is_degraded():
    c = run("firewall", FakeRunner({("r3", "nft"): (1, "Error: No such file or directory\n")}))
    assert c.status == "degraded" and "No firewall policy" in c.summary


def test_firewall_with_extra_drop_rule_still_reports_policy_without_naming_cause():
    c = run("firewall", FakeRunner({("r3", "nft"): (0, fx("nft_with_drop.txt"))}))
    assert c.status == "ok"
    # The overview must not give the incident answer away.
    assert "CHG-1042" not in c.summary and all("CHG-1042" not in f.label for f in c.facts)


def test_db_no_response_is_down_with_timeout_hint():
    c = run("db", FakeRunner({("toolbox", "pg_isready"): (2, fx("pg_noresponse.txt"))}))
    assert c.status == "down" and "firewall" in c.meaning


def test_kms_sealed_is_down():
    c = run("kms", FakeRunner({"kms": (2, fx("bao_sealed.json"))}))
    assert c.status == "down" and "Sealed" in c.summary


def test_kms_server_not_answering():
    c = run("kms", FakeRunner({"kms": (1, fx("bao_down.txt"))}))
    assert c.status == "down" and "not answering" in c.summary


def test_app_dependency_failure_is_degraded():
    c = run("app", FakeRunner({("toolbox", "curl"): (0, '{"db": "ok", "kms": "sealed"}\n503')}))
    assert c.status == "degraded" and "kms: sealed" in c.summary


def test_app_connection_refused_explained():
    c = run("app", FakeRunner({("toolbox", "curl"): (7, fx("curl_refused.txt"))}))
    assert c.status == "down" and "refused" in c.meaning


def test_ldap_unreachable_vs_tls_failure():
    c = run("ldap", FakeRunner({("toolbox", "ldapwhoami"): (1, fx("ldap_cantcontact.txt"))}))
    assert c.status == "down" and c.summary == "Cannot reach the directory"
    tls = "ldap_start_tls: Connect error (-11)\n\tadditional info: error:0A000086:SSL routines::certificate verify failed\n"
    c = run("ldap", FakeRunner({("toolbox", "ldapwhoami"): (1, tls)}))
    assert c.status == "down" and c.summary.startswith("TLS failure")


def test_timeout_is_reported_as_down_not_ok():
    c = run("db", FakeRunner(timeouts={("toolbox", "pg_isready")}))
    assert c.status == "down" and "timeout" in c.summary.lower()


# ------------------------------------------------------------------ unavailable

def test_stopped_target_container_is_down():
    c = run("kms", FakeRunner(stopped={"kms"}))
    assert c.status == "down" and c.summary == "Container not running"


def test_stopped_toolbox_makes_remote_checks_unknown_not_down():
    r = FakeRunner(stopped={"toolbox"})
    for cid in ("ldap", "db", "app"):
        c = run(cid, r)
        assert c.status == "unknown", cid
        assert "toolbox" in c.summary


def test_docker_unreachable_never_reports_ok():
    r = FakeRunner(docker_down=True)
    checks = [run_check(r, s) for s in SPECS]
    assert all(c.status == "unknown" for c in checks)


def test_a_crashing_check_does_not_break_the_overview():
    class Boom(FakeRunner):
        def exec(self, service, argv, timeout=5, env=None):
            if service == "dam":
                raise RuntimeError("boom")
            return super().exec(service, argv, timeout, env)
    c = run("dam", Boom())
    assert c.status == "unknown" and c.summary == "Check error"


# ------------------------------------------------------------------ API + timeline

@pytest.fixture()
def client():
    from fastapi.testclient import TestClient
    runner = FakeRunner()
    app = create_app(runner)
    return TestClient(app), runner, app


def test_api_health_does_not_touch_the_lab(client):
    c, runner, _ = client
    assert c.get("/api/health").json()["status"] == "ok"
    assert runner.calls == []


def test_api_overview_and_status_change_events(client):
    c, runner, app = client
    body = c.get("/api/overview").json()
    assert body["overall"] == "ok" and body["counts"]["ok"] == len(SPECS) and body["lab_reachable"]
    baseline = len(body["events"])
    assert baseline == len(SPECS)          # first observation of every check

    runner.answers["kms"] = (2, fx("bao_sealed.json"))
    body = c.get("/api/overview?refresh=true").json()
    assert body["overall"] == "down"
    new = body["events"][0]
    assert (new["check_id"], new["previous"], new["status"]) == ("kms", "ok", "down")
    assert len(body["events"]) == baseline + 1


def test_api_overview_is_cached_briefly(client):
    c, runner, _ = client
    c.get("/api/overview")
    n = len(runner.calls)
    c.get("/api/overview")
    assert len(runner.calls) == n          # second call within 2 s reused the result


def test_no_endpoint_accepts_commands(client):
    c, _, app = client
    paths = {r.path for r in app.routes}
    assert {"/api/health", "/api/overview", "/api/events"} <= paths
    assert not any(m in ("POST", "PUT", "PATCH", "DELETE") for r in app.routes for m in getattr(r, "methods", ()) or ())
    assert c.post("/api/overview").status_code == 405


def test_runner_refuses_non_lab_services():
    from app.runner import LAB_SERVICES, DockerRunner
    assert "workbench" not in LAB_SERVICES
    with pytest.raises(ValueError):
        DockerRunner()._find("some-other-container")
