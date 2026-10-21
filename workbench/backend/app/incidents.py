"""Incident library: Break / Hint / Fix through the lab's own scripts/scenario.sh.

The workbench does not reimplement faults. It runs the same script you run in the terminal
(`make break S=...`), so both paths always do exactly the same thing. The scenario name is
checked against a fixed list and passed as a separate argument; the root cause is never shown
until the incident is fixed (or the runbook is opened on purpose).
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from .models import Incident, IncidentRun

def default_repo(here: Path | None = None) -> Path:
    """The repository root when WB_REPO is not set: three levels above this file in a checkout.
    In the container the code lives at /srv/app (too shallow), so fall back to the current dir.
    (Never compute this as a .get() default: Python evaluates defaults even when the variable is set.)"""
    here = (here or Path(__file__)).resolve()
    return here.parents[3] if len(here.parents) > 3 else Path.cwd()


REPO = Path(os.environ["WB_REPO"]) if os.environ.get("WB_REPO") else default_repo()
DATA = Path(os.environ.get("WB_DATA", "/tmp/wb-data"))
TIMEOUT_S = 180

# Neutral titles: what the customer experiences, never the cause.
CATALOG: list[tuple[str, str, str]] = [
    ("ospf-mtu", "Network", "Slow app and a routing alarm after maintenance"),
    ("core-link-down", "Network", "Latency between the sites jumped"),
    ("firewall-drop", "Network", "Analysts cannot connect to the database"),
    ("cert-renewal", "TLS / PKI", "App errors after a planned certificate renewal"),
    ("ldap-cert-untrusted", "Identity", "Directory logins fail after a server rebuild"),
    ("kms-sealed", "Key management", "New cardholders fail after patching"),
    ("hba-change", "Database", "App health check fails after a hardening change"),
    ("data-exfiltration", "Security", "Monitoring alerts on the cardholder table"),
    ("brute-force", "Security", "A user says her account feels locked"),
]
IDS = [c[0] for c in CATALOG]


class IncidentError(Exception):
    def __init__(self, msg: str, status: int = 400):
        super().__init__(msg)
        self.status = status


_lock = threading.Lock()
_state_lock = threading.Lock()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _state_file() -> Path:
    DATA.mkdir(parents=True, exist_ok=True)
    return DATA / "incidents.json"


def _load() -> dict:
    try:
        return json.loads(_state_file().read_text())
    except (OSError, ValueError):
        return {}


def _save(state: dict) -> None:
    f = _state_file()
    tmp = f.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=1))
    tmp.replace(f)


def audit(entry: dict) -> None:
    DATA.mkdir(parents=True, exist_ok=True)
    with open(DATA / "actions.jsonl", "a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry) + "\n")


def recent_actions(n: int = 50) -> list[dict]:
    try:
        lines = (DATA / "actions.jsonl").read_text().splitlines()[-n:]
    except OSError:
        return []
    out = []
    for line in reversed(lines):
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return out


def script_available() -> bool:
    return (REPO / "scripts" / "scenario.sh").is_file()


def run_script(action: str, sid: str | None = None) -> IncidentRun:
    argv = ["./scripts/scenario.sh", action] + ([sid] if sid else [])
    env = {**os.environ, "HOME": os.environ.get("HOME", "/tmp")}
    start = time.monotonic()
    try:
        p = subprocess.run(argv, cwd=REPO, capture_output=True, text=True, timeout=TIMEOUT_S, env=env)
        out, code = (p.stdout + p.stderr), p.returncode
    except subprocess.TimeoutExpired as exc:
        out = ((exc.stdout or b"").decode() if isinstance(exc.stdout, bytes) else (exc.stdout or "")) + "\n(timed out)"
        code = None
    except OSError as exc:
        out, code = f"could not run scenario.sh: {exc}", None
    out = re.sub(r"\x1b\[[0-9;]*m", "", out)[-20000:]
    return IncidentRun(action=action, ok=code == 0, output=out.strip(), exit_code=code,
                       duration_ms=int((time.monotonic() - start) * 1000), at=_now())


def parse_ticket(out: str) -> dict:
    m = re.search(r"TICKET (\S+)\s+\(priority (\S+)\)\s*\n\s*Customer: \"(.*)\"", out)
    return {"ticket_id": m.group(1), "priority": m.group(2), "customer": m.group(3)} if m else {}


def describe_all() -> dict[str, str]:
    """The scenario's real description (the root cause), from `scenario.sh list`."""
    r = run_script("list")
    res = {}
    for line in r.output.splitlines():
        m = re.match(r"\s*(\S+)\s{2,}(.+)$", line)
        if m and m.group(1) in IDS:
            res[m.group(1)] = m.group(2).strip()
    return res


def _incident(sid: str, st: dict) -> Incident:
    area, title = next((a, t) for i, a, t in CATALOG if i == sid)
    s = st.get(sid, {})
    return Incident(id=sid, area=area, title=title, state=s.get("state", "ready"),
                    ticket_id=s.get("ticket_id"), priority=s.get("priority"), customer=s.get("customer"),
                    broken_at=s.get("broken_at"), fixed_at=s.get("fixed_at"),
                    minutes_to_resolve=s.get("minutes_to_resolve"), hints=s.get("hints", []),
                    reveal=s.get("reveal") if s.get("state") == "resolved" else None,
                    runbook=f"docs/runbooks/{sid}.md",
                    last_run=IncidentRun(**s["last_run"]) if s.get("last_run") else None)


def list_incidents() -> list[Incident]:
    st = _load()
    return [_incident(i, st) for i in IDS]


def get(sid: str) -> Incident:
    check_id(sid)
    return _incident(sid, _load())


def check_id(sid: str) -> None:
    if sid not in IDS:
        raise IncidentError("unknown incident", 404)


def act(sid: str, action: str) -> Incident:
    check_id(sid)
    if action not in ("break", "hint", "fix"):
        raise IncidentError("unknown action", 400)
    if not script_available():
        raise IncidentError("scenario scripts are not available to the workbench (is the repo mounted?)", 503)
    if not _lock.acquire(blocking=False):
        raise IncidentError("another action is still running; wait for it to finish", 409)
    try:
        with _state_lock:
            st = _load()
            cur = st.get(sid, {})
        if action == "break" and cur.get("state") == "active":
            raise IncidentError("this incident is already active; fix it first", 409)
        if action == "hint" and cur.get("state") != "active":
            raise IncidentError("start the incident before asking for a hint", 409)
        run = run_script(action, sid)
        audit({"at": run.at, "action": action, "incident": sid, "ok": run.ok, "exit_code": run.exit_code,
               "duration_ms": run.duration_ms})
        with _state_lock:
            st = _load()
            cur = st.get(sid, {})
            cur["last_run"] = run.model_dump()
            if run.ok and action == "break":
                cur.update({"state": "active", "broken_at": run.at, "fixed_at": None, "minutes_to_resolve": None,
                            "hints": [], "reveal": None, **parse_ticket(run.output)})
            elif run.ok and action == "hint":
                hint = run.output.strip()
                if hint and hint not in cur.get("hints", []):
                    cur.setdefault("hints", []).append(hint)
            elif run.ok and action == "fix":
                mins = None
                if cur.get("broken_at"):
                    t0 = datetime.fromisoformat(cur["broken_at"])
                    mins = round((datetime.fromisoformat(run.at) - t0).total_seconds() / 60, 1)
                cur.update({"state": "resolved", "fixed_at": run.at, "minutes_to_resolve": mins})
            st[sid] = cur
            _save(st)
        if run.ok and action == "fix":
            reveal = describe_all().get(sid)
            with _state_lock:
                st = _load()
                st[sid]["reveal"] = reveal
                _save(st)
        if not run.ok:
            last = run.output.strip().splitlines()[-1][:300] if run.output.strip() else "no output"
            raise IncidentError(f"scenario.sh {action} {sid} failed (exit {run.exit_code}): {last}", 502)
        return get(sid)
    finally:
        _lock.release()


def reset_record(sid: str) -> Incident:
    """Forget a resolved incident's record (does not touch the lab)."""
    check_id(sid)
    with _state_lock:
        st = _load()
        if st.get(sid, {}).get("state") == "active":
            raise IncidentError("fix the incident before clearing it", 409)
        st.pop(sid, None)
        _save(st)
    return get(sid)


def runbook(sid: str) -> str:
    check_id(sid)
    p = REPO / "docs" / "runbooks" / f"{sid}.md"
    if not p.is_file():
        raise IncidentError("runbook not found", 404)
    return p.read_text()[:60000]
