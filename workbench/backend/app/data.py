"""Identity, database access, audit trail and activity-monitor alerts.

How each view is read, and why it does not disturb what it observes:
  * Directory  - `slapcat` on the directory server (an offline-capable admin dump): no network bind,
                 no credentials. Password hashes are removed before anything leaves the parser.
  * Database   - fixed queries against the system catalog only (pg_roles, pg_class, has_table_privilege,
                 pg_hba_file_rules, pg_stat_activity, pg_stat_ssl, pg_settings), run as the local
                 `postgres` user over the Unix socket. pgAudit is configured with log_catalog = off,
                 so these reads do not appear in the audit trail or trigger the activity monitor.
  * Audit      - the tail of PostgreSQL's CSV log, read through the activity monitor's read-only mount.
  * Alerts     - the activity monitor's alerts file; acknowledge/resolve state is kept by the workbench.
  * Login tests - real logins from the Site A toolbox, with passwords passed through a temporary file
                 (directory) or the environment (database), never on the command line, and redacted in
                 the evidence. A wrong-password database test is a real failed login and counts towards
                 the brute-force rule, on purpose.
"""
from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import os
import re
import threading
import uuid
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .checks import evidence, now
from .models import (AlertItem, AuditEvent, DbAccess, Directory, DirGroup, DirUser, Fact, LoginTest)
from .runner import ExecResult, Runner

CA = "/lab-certs/ca-chain.pem"
WB_APP = "datashield-workbench"
BASE_DN = "dc=securedata,dc=lab"
LAB_USERS = ("alice", "bob", "carol")
DATA = Path(os.environ.get("WB_DATA", "/tmp/wb-data"))


class DataError(ValueError):
    """400 = the request was outside the allow-list; 503 = the lab could not be read."""

    def __init__(self, msg: str, status: int = 400):
        super().__init__(msg)
        self.status = status


# ================================================================== directory

def parse_ldif(text: str) -> list[dict[str, list[str]]]:
    """Minimal LDIF reader (RFC 2849 subset): folded lines, base64 values, one dict per entry."""
    unfolded: list[str] = []
    for line in text.splitlines():
        if line.startswith(" ") and unfolded:
            unfolded[-1] += line[1:]
        else:
            unfolded.append(line)
    entries, cur = [], {}
    for line in unfolded + [""]:
        if not line.strip():
            if cur:
                entries.append(cur)
                cur = {}
            continue
        if line.startswith("#") or ":" not in line:
            continue
        attr, _, value = line.partition(":")
        if value.startswith(":"):
            try:
                value = base64.b64decode(value[1:].strip()).decode("utf-8", "replace")
            except ValueError:
                value = "(binary)"
        else:
            value = value.strip()
        if attr.lower() == "userpassword":
            value = "(hidden)"                       # never expose password hashes
        cur.setdefault(attr, []).append(value)
    return entries


def directory(runner: Runner) -> Directory:
    r = runner.exec("ldap", ["slapcat", "-f", "/etc/lab/slapd.conf"], limit=2_000_000)
    if not r.ran or r.exit_code != 0:
        why = r.error or (r.output.strip().splitlines() or ["no output"])[-1]
        raise DataError(f"could not read the directory: {why}", 503)
    entries = parse_ldif(r.output)
    groups = []
    member_of: dict[str, list[str]] = defaultdict(list)
    for e in entries:
        oc = [o.lower() for o in e.get("objectClass", [])]
        if "posixgroup" in oc or "groupofnames" in oc:
            members = e.get("memberUid", []) + [m.split(",")[0].split("=")[-1] for m in e.get("member", [])]
            g = DirGroup(dn=e["dn"][0], cn=e.get("cn", ["?"])[0], gid=e.get("gidNumber", [""])[0], members=members)
            groups.append(g)
            for m in members:
                member_of[m].append(g.cn)
    users = []
    for e in entries:
        oc = [o.lower() for o in e.get("objectClass", [])]
        if "inetorgperson" in oc or "posixaccount" in oc:
            uid = e.get("uid", ["?"])[0]
            users.append(DirUser(dn=e["dn"][0], uid=uid, cn=e.get("cn", [""])[0], mail=e.get("mail", [""])[0],
                                 uid_number=e.get("uidNumber", [""])[0], home=e.get("homeDirectory", [""])[0],
                                 groups=sorted(member_of.get(uid, [])),
                                 has_password="userPassword" in e))
    ous = [e["dn"][0] for e in entries if "organizationalUnit" in e.get("objectClass", [])]
    ev = evidence(r)
    ev.output = "\n".join(l for l in ev.output.splitlines() if not l.lower().startswith("userpassword"))
    return Directory(base_dn=BASE_DN, users=users, groups=groups, ous=ous, entries=len(entries),
                     evidence=[ev], read_at=now())


# ================================================================== login tests

def _pw(user: str, mode: str) -> str:
    return f"Lab-{user}-2026!" if mode != "wrong" else "not-the-password"


def ldap_bind_test(runner: Runner, user: str, mode: str) -> LoginTest:
    if user not in LAB_USERS or mode not in ("correct", "wrong", "no_tls"):
        raise DataError("choose a lab user (alice, bob, carol) and a mode (correct, wrong, no_tls)")
    dn = f"uid={user},ou=people,{BASE_DN}"
    pwfile = f"/tmp/wb-bind-{uuid.uuid4().hex[:8]}"
    runner.put_file("toolbox", pwfile, _pw(user, "wrong" if mode == "wrong" else "correct").encode())
    argv = ["ldapwhoami", "-x"] + ([] if mode == "no_tls" else ["-ZZ"]) + \
           ["-o", "nettimeout=3", "-H", "ldap://ldap.site-a.lab", "-D", dn, "-y", pwfile]
    try:
        r = runner.exec("toolbox", argv, env={"LDAPTLS_CACERT": CA})
    finally:
        runner.exec("toolbox", ["rm", "-f", pwfile])
    out = r.output.lower()
    if r.ran and r.exit_code == 0:
        res = ("pass", f"Bound as {user}", "The directory accepted the password over an encrypted StartTLS session. "
               "This is exactly what PostgreSQL does on the user's behalf when they log in to the database.")
    elif "invalid credentials" in out:
        res = ("fail", "Invalid credentials (LDAP result 49)",
               "The server was reached and TLS worked; the password (or DN) is wrong. Directories return the same "
               "error for an unknown user and a wrong password, so attackers cannot tell which.")
    elif "confidentiality required" in out:
        res = ("fail", "Confidentiality required (LDAP result 13)",
               "The directory refuses a password over an unencrypted connection (slapd.conf: security simple_bind=128). "
               "Clients must use StartTLS (-ZZ) or LDAPS. A good control: passwords never cross the network in clear.")
    elif "can't contact" in out:
        res = ("fail", "Cannot reach the directory", "Network or service problem, not a credential problem.")
    elif "tls" in out or "certificate" in out or "ssl" in out:
        res = ("fail", "TLS failure before the bind", "The StartTLS handshake failed, so the password was never sent. "
               "Check the directory's certificate (name and issuer).")
    else:
        res = ("fail", f"Bind failed (exit {r.exit_code})", "See the output.")
    return LoginTest(kind="ldap", user=user, mode=mode, status=res[0], summary=res[1], meaning=res[2],
                     evidence=[evidence(r)], ran_at=now())


DB_TEST_SQL = ("select current_user, s.ssl, s.version, inet_client_addr() "
               "from pg_stat_ssl s where s.pid = pg_backend_pid()")


def db_login_test(runner: Runner, user: str, mode: str) -> LoginTest:
    if user not in LAB_USERS or mode not in ("correct", "wrong"):
        raise DataError("choose a lab user (alice, bob, carol) and a mode (correct, wrong)")
    env = {"PGPASSWORD": _pw(user, mode), "PGSSLMODE": "verify-full", "PGSSLROOTCERT": CA, "PGCONNECT_TIMEOUT": "5"}
    r = runner.exec("toolbox", ["psql", "-X", "-A", "-t", "-F", "\t", "-h", "db.site-b.lab", "-d", "appdb",
                                "-U", user, "-c", DB_TEST_SQL], env=env, timeout=12)
    out = r.output.lower()
    if r.ran and r.exit_code == 0:
        cols = (r.output.strip().splitlines() or [""])[-1].split("\t") + ["", "", "", ""]
        res = ("pass", f"Logged in as {cols[0]} over {cols[2] or 'TLS'}",
               "Full chain worked: TLS to PostgreSQL (certificate verified), pg_hba.conf matched an ldap rule, and "
               "PostgreSQL bound to the directory over StartTLS with this password.")
    elif "password authentication failed" in out or "ldap authentication failed" in out:
        res = ("fail", "Authentication failed (SQLSTATE 28P01)",
               "PostgreSQL asked the directory and the directory said no. This attempt is now a FATAL 28P01 line "
               "in the database log: the activity monitor counts it, and five within a minute raise brute-force-login.")
    elif "no pg_hba.conf entry" in out or "rejects connection" in out:
        res = ("fail", "Rejected by pg_hba.conf (SQLSTATE 28000)",
               "No access rule matches this user, database, source address and connection type. Read the rules below.")
    elif "certificate" in out or "ssl" in out:
        res = ("fail", "TLS verification failed", "The client refused the database's certificate (sslmode=verify-full).")
    elif "timeout" in out or "could not connect" in out or r.error == "timeout":
        res = ("fail", "Could not connect", "Network path or service problem: try the Diagnostics page.")
    else:
        res = ("fail", f"Login failed (exit {r.exit_code})", "See the output.")
    return LoginTest(kind="db", user=user, mode=mode, status=res[0], summary=res[1], meaning=res[2],
                     evidence=[evidence(r)], ran_at=now())


# ================================================================== database access

Q_ROLES = ("select r.rolname, r.rolcanlogin, r.rolsuper, "
           "coalesce(string_agg(b.rolname, ',' order by b.rolname), '') "
           "from pg_roles r left join pg_auth_members m on m.member = r.oid left join pg_roles b on b.oid = m.roleid "
           "where r.rolname !~ '^pg_' group by 1,2,3 order by 1")
Q_GRANTS = ("select c.relname, coalesce(g.rolname, 'PUBLIC'), a.privilege_type "
            "from pg_class c join pg_namespace n on n.oid = c.relnamespace and n.nspname = 'public', "
            "aclexplode(c.relacl) a left join pg_roles g on g.oid = a.grantee "
            "where c.relkind = 'r' order by 1,2,3")
Q_EFFECTIVE = ("select r.rolname, c.relname, p.priv, has_table_privilege(r.oid, c.oid, p.priv) "
               "from pg_roles r cross join pg_class c join pg_namespace n on n.oid = c.relnamespace "
               "and n.nspname = 'public' and c.relkind = 'r' "
               "cross join (values ('SELECT'), ('INSERT'), ('UPDATE'), ('DELETE')) p(priv) "
               "where r.rolcanlogin and not r.rolsuper order by 1,2,3")
Q_HBA = ("select line_number, type, array_to_string(database, ','), array_to_string(user_name, ','), "
         "coalesce(address, ''), coalesce(netmask, ''), auth_method, "
         "coalesce(array_to_string(options, ' '), ''), coalesce(error, '') from pg_hba_file_rules order by line_number")
Q_CONN = ("select a.pid, coalesce(a.usename, ''), coalesce(a.datname, ''), coalesce(host(a.client_addr), 'local'), "
          "coalesce(a.application_name, ''), to_char(a.backend_start at time zone 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'), "
          "coalesce(a.state, ''), coalesce(s.ssl, false), coalesce(s.version, '') "
          "from pg_stat_activity a left join pg_stat_ssl s on s.pid = a.pid "
          "where a.backend_type = 'client backend' and a.pid <> pg_backend_pid() order by a.backend_start")
Q_SETTINGS = ("select name, setting from pg_settings where name in ('ssl', 'ssl_min_protocol_version', "
              "'password_encryption', 'pgaudit.log', 'pgaudit.log_catalog', 'pgaudit.log_relation', "
              "'log_connections', 'log_disconnections', 'server_version') order by name")
Q_TABLES = ("select relname, n_live_tup, seq_scan, coalesce(idx_scan, 0), n_tup_ins "
            "from pg_stat_user_tables order by relname")

DB_QUERIES = {"roles": Q_ROLES, "grants": Q_GRANTS, "effective": Q_EFFECTIVE, "hba": Q_HBA,
              "connections": Q_CONN, "settings": Q_SETTINGS, "tables": Q_TABLES}


def _psql(runner: Runner, sql: str) -> ExecResult:
    # application_name marks the workbench's own sessions in the log so the audit view can hide them
    return runner.exec("db", ["psql", "-X", "-q", "-A", "-t", "-F", "\t", "-d", "appdb", "-c", sql],
                       user="postgres", limit=1_000_000, env={"PGAPPNAME": WB_APP})


def via_role(user: str, table: str, priv: str, memberships: dict[str, list[str]],
             grants: dict[tuple[str, str], set[str]]) -> str:
    """Which role a privilege comes from: the user itself, PUBLIC, or the first role it inherits."""
    if priv in grants.get((table, user), set()):
        return "direct grant"
    seen, todo = set(), list(memberships.get(user, []))
    while todo:
        role = todo.pop(0)
        if role in seen:
            continue
        seen.add(role)
        if priv in grants.get((table, role), set()):
            return f"via role {role}"
        todo += memberships.get(role, [])
    if priv in grants.get((table, "PUBLIC"), set()):
        return "via PUBLIC"
    return "inherited"


def database(runner: Runner) -> DbAccess:
    with ThreadPoolExecutor(max_workers=7) as pool:
        futs = {k: pool.submit(_psql, runner, q) for k, q in DB_QUERIES.items()}
        res = {k: f.result() for k, f in futs.items()}
    bad = [r for r in res.values() if not r.ran or r.exit_code != 0]
    if bad:
        r = bad[0]
        why = r.error or (r.output.strip().splitlines() or ["no output"])[-1]
        raise DataError(f"could not read the database catalog: {why}", 503)
    rows = {k: [l.split("\t") for l in r.output.splitlines() if l.strip()] for k, r in res.items()}

    memberships: dict[str, list[str]] = {}
    roles = []
    for name, login, sup, member in rows["roles"]:
        memberships[name] = [m for m in member.split(",") if m]
        roles.append({"name": name, "login": login == "t", "superuser": sup == "t", "member_of": memberships[name]})
    grants: dict[tuple[str, str], set[str]] = defaultdict(set)
    for table, grantee, priv in rows["grants"]:
        grants[(table, grantee)].add(priv)
    matrix = []
    for user, table, priv, allowed in rows["effective"]:
        if allowed == "t":
            matrix.append({"user": user, "table": table, "privilege": priv,
                           "via": via_role(user, table, priv, memberships, grants)})
    hba = [{"line": int(l[0] or 0), "type": l[1], "database": l[2], "user": l[3], "address": l[4],
            "netmask": l[5], "method": l[6], "options": l[7], "error": l[8]} for l in rows["hba"]]
    conns = [{"pid": int(c[0]), "user": c[1], "database": c[2], "client": c[3], "application": c[4],
              "since": c[5], "state": c[6], "ssl": c[7] == "t", "tls_version": c[8]} for c in rows["connections"]]
    settings = {s[0]: s[1] for s in rows["settings"]}
    tables = [{"table": t[0], "rows": int(t[1]), "seq_scans": int(t[2]), "index_scans": int(t[3]),
               "inserted": int(t[4])} for t in rows["tables"]]
    findings = db_findings(matrix, hba, conns, settings)
    return DbAccess(roles=roles, matrix=matrix, hba=hba, connections=conns, settings=settings, tables=tables,
                    findings=findings, evidence=[evidence(r) for r in res.values()], read_at=now())


SENSITIVE = {"cardholders"}
APP_USERS = {"svc_app"}


def db_findings(matrix: list[dict], hba: list[dict], conns: list[dict], settings: dict) -> list[Fact]:
    out = []
    humans = sorted({m["user"] for m in matrix if m["table"] in SENSITIVE and m["privilege"] == "SELECT"
                     and m["user"] not in APP_USERS})
    if humans:
        how = {m["user"]: m["via"] for m in matrix if m["table"] in SENSITIVE and m["privilege"] == "SELECT"}
        out.append(Fact(label="people who can read cardholders",
                        value=", ".join(f"{u} ({how[u]})" for u in humans)))
    non_tls = [c for c in conns if c["client"] != "local" and not c["ssl"]]
    if non_tls:
        out.append(Fact(label="network connections without TLS", value=", ".join(f'{c["user"]}@{c["client"]}' for c in non_tls)))
    errors = [h for h in hba if h["error"]]
    if errors:
        out.append(Fact(label="pg_hba.conf lines with errors", value=", ".join(f'line {h["line"]}: {h["error"]}' for h in errors)))
    if settings.get("ssl") != "on":
        out.append(Fact(label="TLS", value="ssl is off"))
    if "read" not in settings.get("pgaudit.log", ""):
        out.append(Fact(label="audit", value=f'pgaudit.log = {settings.get("pgaudit.log", "(not set)")}: reads are not audited'))
    return out


# ================================================================== audit trail

COLS = {"time": 0, "user": 1, "db": 2, "pid": 3, "from": 4, "session": 5, "severity": 11, "state": 12,
        "message": 13, "query": 19, "app": 22, "backend": 23}


def _source(conn_from: str) -> str:
    if not conn_from or conn_from.startswith("[local]"):
        return "local"
    return conn_from.rsplit(":", 1)[0]


def parse_csvlog(text: str) -> list[AuditEvent]:
    events = []
    for row in csv.reader(io.StringIO(text)):
        if len(row) <= COLS["message"]:
            continue
        msg, sev, state = row[COLS["message"]], row[COLS["severity"]], row[COLS["state"]]
        app = row[COLS["app"]] if len(row) > COLS["app"] else ""
        if not app:   # "connection authorized" is logged before the column is set; the name is in the text
            m = re.search(r"application_name=(\S+)", msg)
            app = m.group(1) if m else ""
        base = dict(time=row[COLS["time"]], user=row[COLS["user"]], database=row[COLS["db"]],
                    source=_source(row[COLS["from"]]), session=row[COLS["session"]], pid=row[COLS["pid"]],
                    application=app)
        if msg.startswith("AUDIT: "):
            f = next(csv.reader(io.StringIO(msg[7:])), [])
            if len(f) >= 8:
                events.append(AuditEvent(kind="audit", audit_class=f[3], command=f[4], object=f[6],
                                         statement=f[7][:500], message="", **base))
            continue
        if sev == "FATAL" and state in ("28000", "28P01"):
            events.append(AuditEvent(kind="auth_failure", message=msg[:300], **base))
        elif state == "42501":
            q = row[COLS["query"]] if len(row) > COLS["query"] else ""
            events.append(AuditEvent(kind="permission_denied", message=msg[:300], statement=q[:500], **base))
        elif msg.startswith("connection authorized"):
            events.append(AuditEvent(kind="login", message=msg[:300], **base))
        elif msg.startswith("disconnection"):
            events.append(AuditEvent(kind="logout", message=msg[:300], **base))
    return events


AUDIT_LOG_TAIL = 6000


def audit(runner: Runner, kind: str = "", user: str = "", obj: str = "", text: str = "", limit: int = 300,
          include_workbench: bool = False) -> dict:
    if kind and kind not in ("audit", "auth_failure", "permission_denied", "login", "logout"):
        raise DataError("unknown event kind")
    for v in (user, obj, text):
        if len(v) > 80:
            raise DataError("filter too long")
    r = runner.exec("dam", ["tail", "-n", str(AUDIT_LOG_TAIL), "/pglogs/postgresql.csv"], limit=12_000_000)
    if not r.ran or r.exit_code not in (0,):
        raise DataError("could not read the database log: " + (r.error or r.output.strip()[:200]), 503)
    events = parse_csvlog(r.output)
    own = sum(1 for e in events if e.application == WB_APP)
    if not include_workbench:
        events = [e for e in events if e.application != WB_APP]
    total = len(events)
    sel = [e for e in events if (not kind or e.kind == kind) and (not user or e.user == user)
           and (not obj or obj.lower() in e.object.lower()) and
           (not text or text.lower() in (e.statement + " " + e.message).lower())]
    users = sorted({e.user for e in events if e.user})
    objects = sorted({e.object for e in events if e.object})
    counts = defaultdict(int)
    for e in events:
        counts[e.kind] += 1
    ev = evidence(r)
    ev.output = f"(last {AUDIT_LOG_TAIL} log lines read; {total} relevant events parsed)"
    return {"events": [e.model_dump() for e in reversed(sel[-limit:])], "matched": len(sel), "total": total,
            "workbench_events": own,
            "users": users, "objects": objects, "counts": dict(counts), "evidence": [ev.model_dump()],
            "read_at": now()}


# ================================================================== activity-monitor alerts

RULES = {
    "bulk-read-sensitive": ("A person read every row of a sensitive table (a SELECT without WHERE, or COPY).",
                            "A DBA running an approved, ticketed export or a data-quality job.",
                            "Who ran it, from where, and was it approved? Then: should this role be able to read the table at all?"),
    "human-read-sensitive": ("A person (not the application account) queried a sensitive table directly.",
                             "Support looking up one record for a ticket.",
                             "Match it to a ticket. Direct access should be rare and justified."),
    "brute-force-login": ("At least 5 failed logins for the same user, or from the same source, within 60 seconds.",
                          "A service or monitoring probe using a wrong or unknown account and retrying on a timer "
                          "(this lab's own health check did exactly that: docs/postmortems/WB-001-probe-false-positive.md).",
                          "One source and one user at a steady rate = automation. Many users from one source = password spraying."),
    "ddl-by-non-dba": ("Someone outside the DBA role changed the schema.", "A migration run by a deployment account.",
                       "Who has CREATE on the schema, and should they?"),
    "privilege-change-by-non-dba": ("Someone outside the DBA role ran GRANT/REVOKE or role changes.", "Rarely benign.",
                                    "Treat as a priority: who, from where, and what changed?"),
    "privilege-change": ("A DBA changed privileges over the network.", "Planned access change.",
                         "Match it to a change ticket."),
    "permission-denied": ("A statement was refused for lack of privileges.", "Someone exploring, or an app bug.",
                          "Repeated denials from one user can be probing."),
}

_alert_lock = threading.Lock()


def _alert_state_file() -> Path:
    DATA.mkdir(parents=True, exist_ok=True)
    return DATA / "alerts-state.json"


def _alert_state() -> dict:
    try:
        return json.loads(_alert_state_file().read_text())
    except (OSError, ValueError):
        return {}


def alert_id(line: str) -> str:
    return hashlib.sha1(line.encode()).hexdigest()[:12]


def alerts(runner: Runner) -> dict:
    r = runner.exec("dam", ["sh", "-c", "tail -n 2000 /dam/alerts.jsonl 2>/dev/null; true"], limit=4_000_000)
    if not r.ran:
        raise DataError("could not read alerts: " + (r.error or ""), 503)
    state = _alert_state()
    items = []
    for line in r.output.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            a = json.loads(line)
        except ValueError:
            continue
        aid = alert_id(line)
        st = state.get(aid, {})
        rule = a.get("rule", "")
        what, benign, ask = RULES.get(rule, ("", "", ""))
        items.append(AlertItem(id=aid, time=a.get("time", ""), severity=a.get("severity", ""), rule=rule,
                               user=a.get("user", ""), source=a.get("source", ""), database=a.get("database", ""),
                               detail=a.get("detail", ""), evidence=a.get("evidence", ""),
                               status=st.get("status", "open"), note=st.get("note", ""), updated=st.get("at"),
                               rule_explained=what, benign_when=benign, ask=ask))
    items.reverse()
    counts = defaultdict(int)
    for i in items:
        counts[i.status] += 1
    return {"alerts": [i.model_dump() for i in items], "counts": dict(counts), "evidence": [evidence(r).model_dump()],
            "read_at": now()}


def set_alert(aid: str, status: str, note: str) -> dict:
    if not re.fullmatch(r"[0-9a-f]{12}", aid):
        raise DataError("bad alert id")
    if status not in ("open", "acknowledged", "resolved"):
        raise DataError("status must be open, acknowledged or resolved")
    if len(note) > 2000:
        raise DataError("note too long")
    with _alert_lock:
        st = _alert_state()
        st[aid] = {"status": status, "note": note, "at": now()}
        f = _alert_state_file()
        tmp = f.with_suffix(".tmp")
        tmp.write_text(json.dumps(st, indent=1))
        tmp.replace(f)
    return st[aid]


def _ts(t: str) -> datetime | None:
    for fmt in ("%Y-%m-%d %H:%M:%S.%f %Z", "%Y-%m-%d %H:%M:%S %Z"):
        try:
            return datetime.strptime(t.replace("UTC", "GMT"), fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def related_events(runner: Runner, aid: str, minutes: int = 3) -> dict:
    """Audit-trail events from the same user or source around an alert: the evidence behind it."""
    data = alerts(runner)
    a = next((x for x in data["alerts"] if x["id"] == aid), None)
    if not a:
        raise FileNotFoundError(aid)
    t0 = _ts(a["time"])
    log = audit(runner, limit=100000)
    out = []
    for e in log["events"]:
        same = (a["user"] and e["user"] == a["user"]) or (a["source"] and e["source"] == a["source"])
        te = _ts(e["time"])
        if same and t0 and te and abs(te - t0) <= timedelta(minutes=minutes):
            out.append(e)
    out.sort(key=lambda e: e["time"])
    return {"alert": a, "events": out[-200:], "window_minutes": minutes, "evidence": log["evidence"]}
