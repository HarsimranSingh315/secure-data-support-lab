"""Tests for the DAM watcher. The fixture is a real PostgreSQL 16 + pgAudit csvlog captured from
the lab: a DBA session, an analyst bulk-reading the cardholders table three ways, six failed
logins, and a GRANT."""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import dam  # noqa: E402

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "postgresql.csv")


def run_fixture():
    det = dam.Detector(dam.Config())
    alerts = []
    for row in dam.read_once(FIXTURE):
        ev = dam.parse_row(row)
        if ev:
            alerts.extend(det.check(ev))
    return alerts


def by_rule(alerts, rule):
    return [a for a in alerts if a["rule"] == rule]


def test_bulk_reads_of_cardholders_are_high():
    bulk = by_rule(run_fixture(), "bulk-read-sensitive")
    statements = " | ".join(a["evidence"] for a in bulk)
    assert len(bulk) == 3
    assert all(a["severity"] == "HIGH" and a["user"] == "bob" for a in bulk)
    assert "select * from cardholders" in statements
    assert "copy cardholders to stdout" in statements


def test_targeted_read_is_medium_not_high():
    reads = by_rule(run_fixture(), "human-read-sensitive")
    assert reads and all(a["severity"] == "MEDIUM" for a in reads)
    assert any("where id = 1" in a["evidence"] for a in reads)


def test_brute_force_alerts_once_per_key():
    bf = by_rule(run_fixture(), "brute-force-login")
    assert {a["detail"].split(" for ")[1].split(" within")[0] for a in bf} == {
        "user:carol", "source:10.10.10.10"}


def test_init_script_role_changes_over_local_socket_are_quiet():
    alerts = run_fixture()
    assert not [a for a in alerts if a["user"] == "postgres"]


def test_permission_denied_is_reported():
    denied = by_rule(run_fixture(), "permission-denied")
    assert any(a["user"] == "bob" and "schema public" in a["detail"] for a in denied)


def test_app_account_reads_are_not_alerts():
    row = ['2026-10-20 12:00:00.000 GMT', 'svc_app', 'appdb', '1', '10.20.20.30:5000', 's', '1',
           'SELECT', '', '', '0', 'LOG', '00000',
           'AUDIT: SESSION,1,1,READ,SELECT,TABLE,public.cardholders,select * from cardholders,<not logged>']
    ev = dam.parse_row(row)
    assert ev and dam.Detector(dam.Config()).check(ev) == []


def test_is_bulk_rules():
    assert dam.is_bulk("select * from cardholders", "SELECT")
    assert dam.is_bulk("COPY cardholders TO STDOUT", "COPY")
    assert not dam.is_bulk("select * from cardholders where id = 3", "SELECT")
    assert not dam.is_bulk("select * from cardholders limit 10", "SELECT")
    assert not dam.is_bulk("select count(*) from cardholders", "SELECT")


def test_complete_rows_handles_quoted_newlines():
    buf = 'a,"line one\nline two",c\nd,e,f\npartial,"open'
    rows, rest = dam._complete_rows(buf)
    assert rows == [["a", "line one\nline two", "c"], ["d", "e", "f"]]
    assert rest == 'partial,"open'


def test_cli_once_writes_alert_file(tmp_path, capsys):
    out = tmp_path / "alerts.jsonl"
    assert dam.main(["--log", FIXTURE, "--alerts", str(out), "--once"]) == 0
    lines = out.read_text().splitlines()
    assert lines and all(json.loads(l)["severity"] in {"LOW", "MEDIUM", "HIGH"} for l in lines)


def test_health_probe_as_unknown_user_looks_like_brute_force():
    """WB-001: a real PostgreSQL 16 log of six pg_isready probes sent as user "root" and six as
    "wb_probe". Only the root probes are rejected (FATAL 28000) and they alone trip the rule;
    the wb_probe probes leave no authentication record at all."""
    det = dam.Detector(dam.Config())
    alerts = []
    path = os.path.join(os.path.dirname(__file__), "fixtures", "probe_as_root.csv")
    for row in dam.read_once(path):
        ev = dam.parse_row(row)
        if ev:
            alerts.extend(det.check(ev))
    bf = by_rule(alerts, "brute-force-login")
    assert bf and all(a["user"] == "root" for a in bf)
    assert not any("wb_probe" in json.dumps(a) for a in alerts)
