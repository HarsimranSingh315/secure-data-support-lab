from __future__ import annotations

from typing import Literal

from pydantic import BaseModel

Status = Literal["ok", "degraded", "down", "unknown"]


class Fact(BaseModel):
    label: str
    value: str


class Evidence(BaseModel):
    service: str            # the container the command ran in
    command: str            # exactly what ran (env + argv, shell-quoted for reading)
    repro: str              # the same command as you would type it on the Mac
    exit_code: int | None
    output: str
    duration_ms: int
    error: str | None = None
    truncated: bool = False


class Check(BaseModel):
    id: str
    title: str
    group: str
    target: str
    status: Status
    summary: str
    meaning: str
    facts: list[Fact]
    evidence: list[Evidence]
    checked_at: str
    source: Literal["live", "simulated"] = "live"


class Event(BaseModel):
    time: str
    check_id: str
    title: str
    previous: Status | None
    status: Status
    summary: str


class Overview(BaseModel):
    overall: Status
    counts: dict[str, int]
    checks: list[Check]
    events: list[Event]
    checked_at: str
    duration_ms: int
    lab_reachable: bool
