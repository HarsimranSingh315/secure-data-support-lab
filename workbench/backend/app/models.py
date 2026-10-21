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


DiagStatus = Literal["pass", "warn", "fail", "error", "info"]


class DiagResult(BaseModel):
    op: str
    title: str
    status: DiagStatus
    summary: str
    meaning: str
    facts: list[Fact]
    evidence: list[Evidence]
    ran_at: str


class WizardStep(BaseModel):
    label: str
    result: DiagResult


class WizardResult(BaseModel):
    target: str
    port: int
    steps: list[WizardStep]
    verdict: Literal["pass", "warn", "fail"]
    layer: str            # where the problem is (or "None found")
    conclusion: str


class MapInterface(BaseModel):
    name: str
    address: str | None
    state: str
    mtu: int | None
    link: str | None
    ospf_cost: int | None = None
    ospf_role: str | None = None
    ospf_neighbors: int | None = None
    ospf_adjacent: int | None = None


class MapNeighbor(BaseModel):
    router_id: str
    name: str
    state: str
    interface: str
    address: str
    link: str | None


class MapRoute(BaseModel):
    prefix: str
    protocol: str
    next_hop: str
    interface: str
    metric: int | None
    distance: int | None


class MapRouter(BaseModel):
    id: str
    status: Status
    summary: str
    interfaces: list[MapInterface]
    neighbors: list[MapNeighbor]
    routes: list[MapRoute]
    evidence: list[Evidence]


class MapEnd(BaseModel):
    router: str
    address: str
    interface: str | None
    state: str | None
    mtu: int | None
    ospf_cost: int | None
    neighbor_state: str | None


class MapLink(BaseModel):
    id: str
    label: str
    subnet: str
    kind: Literal["lan", "transit"]
    status: Status
    summary: str
    ends: list[MapEnd]


class MapPath(BaseModel):
    source: str
    destination: str
    hops: list[Fact]          # label = hop address, value = device name
    links: list[str]
    reached: bool
    uses_backup: bool
    summary: str
    evidence: list[Evidence]
    notes: list[str] = []


class Topology(BaseModel):
    routers: list[MapRouter]
    links: list[MapLink]
    path: MapPath
    hosts: list[Fact]
    checked_at: str


# ---------------------------------------------------------------- captures
class CaptureMeta(BaseModel):
    id: str
    source: Literal["capture", "upload"]
    point: str
    point_label: str
    filter: str
    filter_label: str
    seconds: int
    traffic: str
    created: str
    size: int
    packets: int


class CapturePacket(BaseModel):
    no: int
    time: float
    src: str
    dst: str
    sport: int | None
    dport: int | None
    protocol: str
    length: int
    flags: list[str]
    stream: int | None
    info: str
    marks: list[str]


class CaptureConversation(BaseModel):
    stream: int
    client: str
    server: str
    packets: int
    bytes: int
    state: str
    retransmissions: int
    start: float
    duration: float
    protocols: list[str]


class CaptureFinding(BaseModel):
    severity: Literal["pass", "info", "warn", "fail"]
    title: str
    detail: str
    packets: list[int]


class CaptureAnalysis(BaseModel):
    meta: CaptureMeta
    packets: list[CapturePacket]
    conversations: list[CaptureConversation]
    findings: list[CaptureFinding]
    stats: list[Fact]
    evidence: list[Evidence]


# ---------------------------------------------------------------- incidents
class IncidentRun(BaseModel):
    action: str
    ok: bool
    output: str
    exit_code: int | None
    duration_ms: int
    at: str


class Incident(BaseModel):
    id: str
    area: str
    title: str
    state: Literal["ready", "active", "resolved"]
    ticket_id: str | None = None
    priority: str | None = None
    customer: str | None = None
    broken_at: str | None = None
    fixed_at: str | None = None
    minutes_to_resolve: float | None = None
    hints: list[str] = []
    reveal: str | None = None
    runbook: str
    last_run: IncidentRun | None = None


# ---------------------------------------------------------------- identity, database, audit
class DirUser(BaseModel):
    dn: str
    uid: str
    cn: str
    mail: str
    uid_number: str
    home: str
    groups: list[str]
    has_password: bool


class DirGroup(BaseModel):
    dn: str
    cn: str
    gid: str
    members: list[str]


class Directory(BaseModel):
    base_dn: str
    users: list[DirUser]
    groups: list[DirGroup]
    ous: list[str]
    entries: int
    evidence: list[Evidence]
    read_at: str


class LoginTest(BaseModel):
    kind: Literal["ldap", "db"]
    user: str
    mode: str
    status: Literal["pass", "fail"]
    summary: str
    meaning: str
    evidence: list[Evidence]
    ran_at: str


class DbAccess(BaseModel):
    roles: list[dict]
    matrix: list[dict]
    hba: list[dict]
    connections: list[dict]
    settings: dict[str, str]
    tables: list[dict]
    findings: list[Fact]
    evidence: list[Evidence]
    read_at: str


class AuditEvent(BaseModel):
    kind: Literal["audit", "auth_failure", "permission_denied", "login", "logout"]
    time: str
    user: str
    database: str
    source: str
    session: str
    pid: str
    application: str = ""
    audit_class: str = ""
    command: str = ""
    object: str = ""
    statement: str = ""
    message: str = ""


class AlertItem(BaseModel):
    id: str
    time: str
    severity: str
    rule: str
    user: str
    source: str
    database: str
    detail: str
    evidence: str
    status: Literal["open", "acknowledged", "resolved"]
    note: str
    updated: str | None
    rule_explained: str
    benign_when: str
    ask: str
