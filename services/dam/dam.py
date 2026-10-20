#!/usr/bin/env python3
"""DAM watcher: a small database activity monitor for PostgreSQL + pgAudit.

It follows PostgreSQL's CSV log (csvlog), turns pgAudit records, failed logins and permission
errors into events, applies detection rules, and writes alerts as JSON lines. This is the same
idea commercial database activity monitoring products are built on, kept small enough to read.

    python3 dam.py --log /var/log/postgresql/lab/postgresql.csv --alerts /var/log/dam/alerts.jsonl
    python3 dam.py --log fixtures/postgresql.csv --once        # scan an existing file and exit
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import os
import re
import sys
import time
import urllib.request
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterable, Iterator

# PostgreSQL 16 csvlog column positions
COL_TIME, COL_USER, COL_DB, COL_FROM = 0, 1, 2, 4
COL_SEVERITY, COL_SQLSTATE, COL_MESSAGE, COL_QUERY = 11, 12, 13, 19

AUTH_FAILURE_STATES = {"28000", "28P01"}   # invalid authorization / invalid password
PERMISSION_DENIED = "42501"


@dataclass
class Config:
    sensitive_tables: set[str] = field(default_factory=lambda: {"public.cardholders"})
    app_users: set[str] = field(default_factory=lambda: {"svc_app"})
    dba_users: set[str] = field(default_factory=lambda: {"alice", "postgres"})
    brute_force_threshold: int = 5
    brute_force_window_s: int = 60

    @classmethod
    def load(cls, path: str | None) -> "Config":
        if not path:
            return cls()
        with open(path, encoding="utf-8") as fh:
            raw = json.load(fh)
        return cls(
            sensitive_tables=set(raw.get("sensitive_tables", [])),
            app_users=set(raw.get("app_users", [])),
            dba_users=set(raw.get("dba_users", [])),
            brute_force_threshold=int(raw.get("brute_force_threshold", 5)),
            brute_force_window_s=int(raw.get("brute_force_window_s", 60)),
        )


@dataclass
class Event:
    time: str
    user: str
    database: str
    source: str
    kind: str                  # audit | auth_failure | permission_denied
    audit_class: str = ""      # READ, WRITE, DDL, ROLE ...
    command: str = ""          # SELECT, COPY, GRANT ...
    obj: str = ""              # schema.table
    statement: str = ""
    message: str = ""


def _source(conn_from: str) -> str:
    """'10.10.10.10:40052' -> '10.10.10.10'; '[local]' or empty -> 'local' (Unix socket)."""
    if not conn_from or conn_from.startswith("[local]"):
        return "local"
    return conn_from.rsplit(":", 1)[0]


def parse_row(row: list[str]) -> Event | None:
    if len(row) <= COL_MESSAGE:
        return None
    msg = row[COL_MESSAGE]
    base = dict(time=row[COL_TIME], user=row[COL_USER], database=row[COL_DB],
                source=_source(row[COL_FROM]))
    if msg.startswith("AUDIT: "):
        # AUDIT_TYPE,STATEMENT_ID,SUBSTATEMENT_ID,CLASS,COMMAND,OBJECT_TYPE,OBJECT_NAME,STATEMENT,PARAMETER
        fields = next(csv.reader(io.StringIO(msg[len("AUDIT: "):])), [])
        if len(fields) < 8:
            return None
        return Event(kind="audit", audit_class=fields[3], command=fields[4], obj=fields[6],
                     statement=fields[7], message=msg, **base)
    state = row[COL_SQLSTATE]
    if row[COL_SEVERITY] == "FATAL" and state in AUTH_FAILURE_STATES:
        return Event(kind="auth_failure", message=msg, **base)
    if state == PERMISSION_DENIED:
        query = row[COL_QUERY] if len(row) > COL_QUERY else ""
        return Event(kind="permission_denied", message=msg, statement=query, **base)
    return None


_WHERE = re.compile(r"\bwhere\b", re.IGNORECASE)
_LIMIT = re.compile(r"\blimit\s+(\d+)", re.IGNORECASE)


def is_bulk(statement: str, command: str) -> bool:
    """A read that can return the whole table: COPY, or a SELECT with no WHERE and no small LIMIT."""
    if command.upper() == "COPY" or statement.lstrip().lower().startswith("copy"):
        return True
    if "count(" in statement.lower():
        return False
    if _WHERE.search(statement):
        return False
    m = _LIMIT.search(statement)
    return not (m and int(m.group(1)) <= 100)


def _epoch(ts: str) -> float:
    # csvlog time looks like: 2026-10-20 11:06:13.124 GMT
    try:
        return datetime.strptime(ts.replace(" GMT", "").replace(" UTC", ""), "%Y-%m-%d %H:%M:%S.%f").timestamp()
    except ValueError:
        return time.time()


class Detector:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self._fails: dict[str, deque[float]] = defaultdict(deque)
        self._bf_alerted_until: dict[str, float] = {}

    def check(self, ev: Event) -> list[dict]:
        alerts: list[dict] = []
        cfg = self.cfg

        def alert(severity: str, rule: str, detail: str) -> None:
            alerts.append({"time": ev.time, "severity": severity, "rule": rule, "user": ev.user,
                           "source": ev.source, "database": ev.database, "detail": detail,
                           "evidence": (ev.statement or ev.message)[:300]})

        if ev.kind == "audit":
            sensitive = ev.obj in cfg.sensitive_tables
            human = ev.user not in cfg.app_users
            if ev.audit_class == "READ" and sensitive and human:
                if is_bulk(ev.statement, ev.command):
                    how = "COPY" if ev.statement.lstrip().lower().startswith("copy") else ev.command
                    alert("HIGH", "bulk-read-sensitive",
                          f"{ev.user} read all rows of {ev.obj} ({how}); possible data export")
                else:
                    alert("MEDIUM", "human-read-sensitive",
                          f"{ev.user} read {ev.obj} directly instead of through the application")
            elif ev.audit_class == "DDL" and ev.user not in cfg.dba_users:
                alert("MEDIUM", "ddl-by-non-dba", f"{ev.user} changed the schema: {ev.command}")
            elif ev.audit_class == "ROLE" and ev.user not in cfg.dba_users:
                alert("HIGH", "privilege-change-by-non-dba", f"{ev.user} ran {ev.command}")
            elif ev.audit_class == "ROLE" and ev.source != "local":
                alert("LOW", "privilege-change", f"{ev.user} ran {ev.command} on {ev.obj or 'roles'}")

        elif ev.kind == "permission_denied":
            alert("MEDIUM", "permission-denied", f"{ev.user} was denied: {ev.message}")

        elif ev.kind == "auth_failure":
            now = _epoch(ev.time)
            for key in (f"user:{ev.user}", f"source:{ev.source}"):
                window = self._fails[key]
                window.append(now)
                while window and now - window[0] > cfg.brute_force_window_s:
                    window.popleft()
                if len(window) >= cfg.brute_force_threshold and now >= self._bf_alerted_until.get(key, 0):
                    self._bf_alerted_until[key] = now + cfg.brute_force_window_s
                    alert("HIGH", "brute-force-login",
                          f"{len(window)} failed logins for {key} within {cfg.brute_force_window_s}s")
        return alerts


def follow(path: str, from_start: bool) -> Iterator[list[str]]:
    """Yield CSV rows as PostgreSQL writes them; survives the file being recreated or truncated."""
    fh, inode, buf = None, None, ""
    if not os.path.exists(path):
        from_start = True   # the database has not written its log yet: read it all once it appears
    while True:
        if fh is None:
            try:
                fh = open(path, encoding="utf-8", newline="")
                inode = os.fstat(fh.fileno()).st_ino
                if not from_start:
                    fh.seek(0, os.SEEK_END)
                from_start = True   # after a rotation, read the new file from its start
            except FileNotFoundError:
                time.sleep(1)
                continue
        chunk = fh.read()
        if chunk:
            buf += chunk
            # csvlog quotes embedded newlines, so only split on newlines outside quotes
            rows, buf = _complete_rows(buf)
            yield from rows
            continue
        time.sleep(0.5)
        try:
            st = os.stat(path)
            if st.st_ino != inode or st.st_size < fh.tell():
                fh.close()
                fh = None
        except FileNotFoundError:
            fh.close()
            fh = None


def _complete_rows(buf: str) -> tuple[list[list[str]], str]:
    rows, start, in_quotes = [], 0, False
    for i, ch in enumerate(buf):
        if ch == '"':
            in_quotes = not in_quotes
        elif ch == "\n" and not in_quotes:
            rows.extend(csv.reader(io.StringIO(buf[start:i + 1])))
            start = i + 1
    return rows, buf[start:]


def read_once(path: str) -> Iterable[list[str]]:
    with open(path, encoding="utf-8", newline="") as fh:
        yield from csv.reader(fh)


def emit(alert: dict, alerts_path: str | None, webhook: str | None) -> None:
    line = json.dumps(alert)
    print(line, flush=True)
    if alerts_path:
        os.makedirs(os.path.dirname(alerts_path) or ".", exist_ok=True)
        with open(alerts_path, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    if webhook:
        req = urllib.request.Request(webhook, data=line.encode(), method="POST",
                                     headers={"Content-Type": "application/json"})
        try:
            urllib.request.urlopen(req, timeout=5).close()
        except OSError as exc:   # never let a broken webhook stop monitoring
            print(f"dam: webhook failed: {exc}", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--log", required=True, help="PostgreSQL csvlog file to follow")
    ap.add_argument("--alerts", help="append alerts as JSON lines to this file")
    ap.add_argument("--rules", help="JSON rules file (see rules.json)")
    ap.add_argument("--webhook", help="POST each alert as JSON to this URL (e.g. a ticketing system)")
    ap.add_argument("--once", action="store_true", help="scan the file once and exit")
    ap.add_argument("--from-start", action="store_true", help="when following, start at the beginning")
    args = ap.parse_args(argv)

    det = Detector(Config.load(args.rules))
    rows = read_once(args.log) if args.once else follow(args.log, args.from_start)
    count = 0
    for row in rows:
        ev = parse_row(row)
        if not ev:
            continue
        for a in det.check(ev):
            emit(a, args.alerts, args.webhook)
            count += 1
    if args.once:
        print(f"dam: {count} alert(s)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
