"""Day 4: directory, login tests, database access, audit search and alerts.

Recorded for real from the namespace replica running the repo's own services/ldap (slapd.conf,
seed.ldif) and services/db (postgresql.conf with pgAudit, pg_hba.conf, 01-init.sh), with LDAP
StartTLS authentication from PostgreSQL to the directory. Activity in the log was produced by
real logins and statements (bulk export, brute force, permission denied, GRANT), and alerts.jsonl
is the output of the real services/dam/dam.py over that log. See fixtures/day4/README.md.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from app import data as D
from app.runner import ExecResult

FIX = Path(__file__).parent / "fixtures" / "day4"


def norm(k: str) -> str:
    return re.sub(r"/tmp/wb-bind-[0-9a-f]{8}", "/tmp/wb-bind-X", k)


class Replay:
    def __init__(self, session: str = "baseline", stopped=()):
        raw = json.loads((FIX / f"session_{session}.json").read_text())
        self.log: dict[str, list] = {}
        for k, v in raw.items():          # keys differing only by temp file name hold runs in order
            self.log.setdefault(norm(k), []).extend(v)
        self.stopped = set(stopped)
        self.calls: list[tuple[str, list[str], dict, str | None]] = []
        self.files: dict[str, bytes] = {}

    def state(self, s):
        return "exited" if s in self.stopped else "running"

    def exec(self, service, argv, timeout=5, env=None, limit=8000, user=None):
        self.calls.append((service, list(argv), dict(env or {}), user))
        r = ExecResult(service=service, command=list(argv), env=dict(env or {}), user=user)
        if service in self.stopped:
            r.error = "container_not_running"
            return r
        if argv[0] == "rm":
            r.exit_code = 0
            return r
        if service == "dam" and argv[0] == "tail" and "/pglogs/postgresql.csv" in argv:
            r.exit_code, r.output = 0, (FIX / "postgresql.csv").read_text()
            return r
        if service == "dam" and argv[0] == "sh":
            r.exit_code, r.output = 0, (FIX / "alerts.jsonl").read_text()
            return r
        recs = self.log.get(norm(service + " " + " ".join(argv)))
        if not recs:
            raise AssertionError("not recorded: " + service + " " + " ".join(argv))
        rec = recs.pop(0) if len(recs) > 1 else recs[0]
        r.exit_code, r.output, r.error = rec["exit_code"], rec["output"], rec["error"]
        return r

    def put_file(self, service, path, data):
        self.files[path] = data

    def get_file(self, service, path, limit):
        raise AssertionError("not used")


@pytest.fixture(autouse=True)
def data_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(D, "DATA", tmp_path)


# ------------------------------------------------------------------ directory

def test_directory_users_groups_and_no_password_hashes():
    d = D.directory(Replay())
    assert d.base_dn == "dc=securedata,dc=lab" and d.entries == 8
    assert {u.uid: u.groups for u in d.users} == {"alice": ["dbadmins"], "bob": ["analysts"], "carol": ["analysts"]}
    assert all(u.has_password for u in d.users)
    assert "userpassword" not in d.evidence[0].output.lower()
    assert "SSHA" not in json.dumps(d.model_dump())


def test_ldif_parser_folding_base64_and_hiding_hashes():
    e = D.parse_ldif("dn: uid=x,dc=a\ncn: A very long\n  name\nuserPassword:: e1NTSEF9eHl6\ndescription:: aMOpbGxv\n")
    assert e == [{"dn": ["uid=x,dc=a"], "cn": ["A very long name"], "userPassword": ["(hidden)"], "description": ["héllo"]}]


# ------------------------------------------------------------------ login tests

@pytest.mark.parametrize("mode,status,summary", [
    ("correct", "pass", "Bound as bob"),
    ("wrong", "fail", "Invalid credentials (LDAP result 49)"),
    ("no_tls", "fail", "Confidentiality required (LDAP result 13)"),
])
def test_ldap_bind_outcomes_are_real_and_distinct(mode, status, summary):
    r = Replay()
    zz = [k for k in r.log if k.startswith("toolbox ldapwhoami -x -ZZ")][0]
    if mode == "wrong":
        r.log[zz].pop(0)                  # recorded in order: correct, then wrong
    t = D.ldap_bind_test(r, "bob", mode)
    assert (t.status, t.summary) == (status, summary)
    svc, argv, env, _ = r.calls[0]
    assert ("-ZZ" in argv) == (mode != "no_tls")
    pw_path = argv[argv.index("-y") + 1]
    assert r.files[pw_path] == (b"not-the-password" if mode == "wrong" else b"Lab-bob-2026!")
    assert "Lab-bob" not in " ".join(argv) and "Lab-bob" not in t.evidence[0].command
    assert r.calls[-1][1][:2] == ["rm", "-f"]                       # password file removed


@pytest.mark.parametrize("mode,status,summary", [
    ("correct", "pass", "Logged in as alice over TLSv1.3"),
    ("wrong", "fail", "Authentication failed (SQLSTATE 28P01)"),
])
def test_db_login_goes_through_ldap_and_password_is_redacted(mode, status, summary):
    r = Replay()
    key = [k for k in r.log if k.startswith("toolbox psql")][0]
    if mode == "wrong":
        r.log[key].pop(0)                 # recorded in order: correct, then wrong
    t = D.db_login_test(r, "alice", mode)
    assert (t.status, t.summary) == (status, summary)
    assert "PGPASSWORD='***'" in t.evidence[0].command and "Lab-alice" not in t.evidence[0].command
    assert "Lab-alice" not in t.evidence[0].repro


@pytest.mark.parametrize("user,mode", [("postgres", "correct"), ("bob; rm -rf /", "correct"), ("bob", "guess")])
def test_login_tests_only_accept_lab_users_and_modes(user, mode):
    r = Replay()
    with pytest.raises(D.DataError):
        D.ldap_bind_test(r, user, mode)
    with pytest.raises(D.DataError):
        D.db_login_test(r, user, mode if mode != "correct" else "no_tls")
    assert r.calls == []


# ------------------------------------------------------------------ database access

def readers(db):
    return {m["user"]: m["via"] for m in db.matrix if m["table"] == "cardholders" and m["privilege"] == "SELECT"}


def test_database_access_matrix_explains_where_access_comes_from():
    db = D.database(Replay())
    assert readers(db) == {"alice": "via role dba", "bob": "via role analyst", "carol": "via role analyst",
                           "svc_app": "direct grant"}
    roles = {r["name"]: r for r in db.roles}
    assert roles["bob"]["member_of"] == ["analyst", "ldap_users"] and not roles["analyst"]["login"]
    assert db.settings["pgaudit.log"] == "read, write, ddl, role" and db.settings["ssl"] == "on"
    assert db.findings[0].label == "people who can read cardholders"
    assert next(t for t in db.tables if t["table"] == "cardholders")["rows"] == 3


def test_queries_are_catalog_only_run_as_postgres_and_tagged():
    r = Replay()
    D.database(r)
    for svc, argv, env, user in r.calls:
        assert (svc, user, env) == ("db", "postgres", {"PGAPPNAME": "datashield-workbench"})
        sql = re.sub(r"'[^']*'", "''", argv[-1].lower())     # ignore quoted literals like 'insert'
        assert "cardholders" not in sql
        assert not re.search(r"\b(insert|update|delete|grant|revoke|create|drop|alter|copy)\b", sql)


def test_revoke_removes_analysts_from_the_matrix():
    db = D.database(Replay("after_revoke"))
    assert readers(db) == {"alice": "via role dba", "svc_app": "direct grant"}


def test_hba_change_is_visible_in_the_rules():
    base = {h["user"] for h in D.database(Replay()).hba}
    after = {h["user"] for h in D.database(Replay("hba_change")).hba}
    assert "svc_app" in base and "svc_app" not in after
    hba = D.database(Replay()).hba
    assert [h["method"] for h in hba][-1] == "reject" and any(h["method"] == "ldap" for h in hba)


def test_via_role_follows_nested_membership():
    mem = {"u": ["team"], "team": ["dept"], "dept": []}
    grants = {("t", "dept"): {"SELECT"}}
    assert D.via_role("u", "t", "SELECT", mem, grants) == "via role dept"


# ------------------------------------------------------------------ audit search

def test_audit_trail_parses_real_pgaudit_and_login_events():
    a = D.audit(Replay())
    c = a["counts"]
    # 7 brute-force attempts by carol + the recorded wrong-password login tests for alice
    assert c["audit"] > 10 and c["auth_failure"] == 9 and c["permission_denied"] == 1 and c["login"] > 5
    bob = D.audit(Replay(), kind="audit", user="bob")["events"]
    assert {e["object"] for e in bob} == {"public.cardholders"}
    assert any(e["statement"].lower().startswith("copy") for e in bob)
    fails = D.audit(Replay(), kind="auth_failure", user="carol")["events"]
    assert len(fails) == 7 and all(e["source"] == "10.10.10.10" for e in fails)


def test_audit_text_and_object_filters():
    assert D.audit(Replay(), text="grant")["matched"] >= 1
    assert all("orders" in e["object"] for e in D.audit(Replay(), obj="orders")["events"])
    with pytest.raises(D.DataError):
        D.audit(Replay(), kind="everything")


def test_workbench_own_sessions_are_hidden_by_default():
    log = (FIX / "postgresql.csv").read_text()
    if "datashield-workbench" not in log:
        pytest.skip("fixture recorded before tagging")
    shown = D.audit(Replay())
    everything = D.audit(Replay(), include_workbench=True)
    assert shown["workbench_events"] > 0
    assert everything["total"] == shown["total"] + shown["workbench_events"]


# ------------------------------------------------------------------ alerts

def test_alerts_from_the_real_dam_with_explanations():
    a = D.alerts(Replay())
    rules = sorted(x["rule"] for x in a["alerts"])
    assert rules == ["brute-force-login", "brute-force-login", "bulk-read-sensitive", "bulk-read-sensitive",
                     "human-read-sensitive", "permission-denied", "privilege-change"]
    bf = next(x for x in a["alerts"] if x["rule"] == "brute-force-login")
    assert "WB-001" in bf["benign_when"] and bf["status"] == "open"


def test_acknowledge_and_resolve_are_kept():
    first = D.alerts(Replay())["alerts"][0]
    D.set_alert(first["id"], "acknowledged", "asked carol")
    D.set_alert(D.alerts(Replay())["alerts"][1]["id"], "resolved", "approved export, CHG-77")
    a = D.alerts(Replay())
    assert a["counts"] == {"acknowledged": 1, "resolved": 1, "open": 5}
    assert a["alerts"][0]["note"] == "asked carol"
    for bad in [("zz", "open", ""), (first["id"], "deleted", ""), (first["id"], "open", "x" * 3000)]:
        with pytest.raises(D.DataError):
            D.set_alert(*bad)


def test_related_events_show_the_failed_logins_behind_brute_force():
    a = D.alerts(Replay())
    bf = next(x for x in a["alerts"] if x["rule"] == "brute-force-login" and x["detail"].startswith("5 failed logins for user"))
    rel = D.related_events(Replay(), bf["id"])
    fails = [e for e in rel["events"] if e["kind"] == "auth_failure" and e["user"] == "carol"]
    assert len(fails) >= 5


# ------------------------------------------------------------------ API

@pytest.fixture()
def api(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from app.main import create_app
    return TestClient(create_app(Replay()))


H = {"X-Workbench-Action": "1"}


def test_api_reads(api):
    assert api.get("/api/identity/directory").json()["entries"] == 8
    assert "matrix" in api.get("/api/database/access").json()
    assert api.get("/api/audit", params={"kind": "auth_failure", "user": "carol"}).json()["matched"] == 7
    assert len(api.get("/api/alerts").json()["alerts"]) == 7


def test_api_login_test_is_a_guarded_action(api):
    body = {"kind": "ldap", "user": "bob", "mode": "no_tls"}
    assert api.post("/api/identity/login-test", json=body).status_code == 403
    r = api.post("/api/identity/login-test", json=body, headers=H)
    assert r.status_code == 200 and r.json()["summary"].startswith("Confidentiality required")
    assert api.post("/api/identity/login-test", json={**body, "kind": "ssh"}, headers=H).status_code == 400
    assert api.post("/api/identity/login-test", json={**body, "user": "root"}, headers=H).status_code == 400


def test_api_alert_triage(api):
    aid = api.get("/api/alerts").json()["alerts"][0]["id"]
    assert api.post(f"/api/alerts/{aid}", json={"status": "resolved"}).status_code == 403
    assert api.post(f"/api/alerts/{aid}", json={"status": "resolved", "note": "ok"}, headers=H).json()["status"] == "resolved"
    assert api.get(f"/api/alerts/{aid}/related").status_code == 200
    assert api.get("/api/alerts/../../x/related").status_code in (400, 404)


def test_api_reports_unreadable_lab_as_503(tmp_path):
    from fastapi.testclient import TestClient

    from app.main import create_app
    c = TestClient(create_app(Replay(stopped={"ldap", "db"})))
    assert c.get("/api/identity/directory").status_code == 503
    assert c.get("/api/database/access").status_code == 503
