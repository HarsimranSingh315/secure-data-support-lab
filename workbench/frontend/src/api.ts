// Types mirror workbench/backend/app/models.py
export type Status = "ok" | "degraded" | "down" | "unknown";

export interface Fact { label: string; value: string }

export interface Evidence {
  service: string;
  command: string;
  repro: string;
  exit_code: number | null;
  output: string;
  duration_ms: number;
  error: string | null;
  truncated: boolean;
}

export interface Check {
  id: string;
  title: string;
  group: string;
  target: string;
  status: Status;
  summary: string;
  meaning: string;
  facts: Fact[];
  evidence: Evidence[];
  checked_at: string;
  source: "live" | "simulated";
}

export interface LabEvent {
  time: string;
  check_id: string;
  title: string;
  previous: Status | null;
  status: Status;
  summary: string;
}

export interface Overview {
  overall: Status;
  counts: Record<Status, number>;
  checks: Check[];
  events: LabEvent[];
  checked_at: string;
  duration_ms: number;
  lab_reachable: boolean;
}

export async function fetchOverview(refresh: boolean, signal?: AbortSignal): Promise<Overview> {
  const res = await fetch(`/api/overview${refresh ? "?refresh=true" : ""}`, { signal });
  if (!res.ok) throw new Error(`API returned HTTP ${res.status}`);
  return (await res.json()) as Overview;
}

// ---------------------------------------------------------------- network map
export interface MapInterface {
  name: string; address: string | null; state: string; mtu: number | null; link: string | null;
  ospf_cost: number | null; ospf_role: string | null; ospf_neighbors: number | null; ospf_adjacent: number | null;
}
export interface MapNeighbor { router_id: string; name: string; state: string; interface: string; address: string; link: string | null }
export interface MapRoute { prefix: string; protocol: string; next_hop: string; interface: string; metric: number | null; distance: number | null }
export interface MapRouter {
  id: string; status: Status; summary: string; interfaces: MapInterface[]; neighbors: MapNeighbor[];
  routes: MapRoute[]; evidence: Evidence[];
}
export interface MapEnd {
  router: string; address: string; interface: string | null; state: string | null; mtu: number | null;
  ospf_cost: number | null; neighbor_state: string | null;
}
export interface MapLink { id: string; label: string; subnet: string; kind: "lan" | "transit"; status: Status; summary: string; ends: MapEnd[] }
export interface MapPath {
  source: string; destination: string; hops: Fact[]; links: string[]; reached: boolean;
  uses_backup: boolean; summary: string; evidence: Evidence[]; notes: string[];
}
export interface Topology { routers: MapRouter[]; links: MapLink[]; path: MapPath; hosts: Fact[]; checked_at: string }

// ---------------------------------------------------------------- diagnostics
export type DiagStatus = "pass" | "warn" | "fail" | "error" | "info";
export interface DiagResult {
  op: string; title: string; status: DiagStatus; summary: string; meaning: string;
  facts: Fact[]; evidence: Evidence[]; ran_at: string;
}
export interface WizardResult {
  target: string; port: number; steps: { label: string; result: DiagResult }[];
  verdict: "pass" | "warn" | "fail"; layer: string; conclusion: string;
}
export interface CatalogOp { id: string; title: string; layer: string; needs: string[]; tls_only: boolean; hint: string }
export interface CatalogPort { number: number; label: string; tls: boolean; note: string }
export interface CatalogTarget { id: string; host: string; ip: string; label: string; ports: CatalogPort[] }
export interface Catalog { ops: CatalogOp[]; targets: CatalogTarget[]; routers: string[]; vantage: string }

async function getJSON<T>(url: string, signal?: AbortSignal): Promise<T> {
  const res = await fetch(url, { signal });
  if (!res.ok) {
    let detail = `HTTP ${res.status}`;
    try { detail = (await res.json()).detail ?? detail; } catch { /* not JSON */ }
    throw new Error(detail);
  }
  return (await res.json()) as T;
}

export const fetchTopology = (refresh: boolean, signal?: AbortSignal) =>
  getJSON<Topology>(`/api/topology${refresh ? "?refresh=true" : ""}`, signal);
export const fetchCatalog = () => getJSON<Catalog>("/api/diagnostics");
export function runDiagnostic(op: string, params: Record<string, string | number | undefined>) {
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== "") q.set(k, String(v));
  return getJSON<DiagResult>(`/api/diagnostics/${encodeURIComponent(op)}?${q}`);
}
export const runWizard = (target: string, port: number) =>
  getJSON<WizardResult>(`/api/diagnose?target=${encodeURIComponent(target)}&port=${port}`);

// ---------------------------------------------------------------- actions (change the lab)
// The header proves the request comes from this page (the server refuses actions without it).
async function postJSON<T>(url: string, body?: unknown): Promise<T> {
  const res = await fetch(url, {
    method: "POST",
    headers: { "X-Workbench-Action": "1", ...(body !== undefined ? { "Content-Type": "application/json" } : {}) },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) {
    let detail = `HTTP ${res.status}`;
    try { detail = (await res.json()).detail ?? detail; } catch { /* not JSON */ }
    throw new Error(detail);
  }
  return (await res.json()) as T;
}

// ---------------------------------------------------------------- incidents
export interface IncidentRun { action: string; ok: boolean; output: string; exit_code: number | null; duration_ms: number; at: string }
export interface Incident {
  id: string; area: string; title: string; state: "ready" | "active" | "resolved";
  ticket_id: string | null; priority: string | null; customer: string | null;
  broken_at: string | null; fixed_at: string | null; minutes_to_resolve: number | null;
  hints: string[]; reveal: string | null; runbook: string; last_run: IncidentRun | null;
}
export interface ActionEntry { at: string; action: string; incident: string; ok: boolean; exit_code: number | null; duration_ms: number }
export const fetchIncidents = () => getJSON<Incident[]>("/api/incidents");
export const incidentAction = (id: string, action: "break" | "hint" | "fix" | "clear") =>
  postJSON<Incident>(`/api/incidents/${encodeURIComponent(id)}/${action}`);
export const fetchRunbook = (id: string) => getJSON<{ id: string; markdown: string }>(`/api/incidents/${encodeURIComponent(id)}/runbook`);
export const fetchActions = () => getJSON<ActionEntry[]>("/api/actions");

// ---------------------------------------------------------------- captures
export interface CaptureMeta {
  id: string; source: "capture" | "upload"; point: string; point_label: string; filter: string; filter_label: string;
  seconds: number; traffic: string; created: string; size: number; packets: number;
}
export interface CapturePacket {
  no: number; time: number; src: string; dst: string; sport: number | null; dport: number | null;
  protocol: string; length: number; flags: string[]; stream: number | null; info: string; marks: string[];
}
export interface CaptureConversation {
  stream: number; client: string; server: string; packets: number; bytes: number; state: string;
  retransmissions: number; start: number; duration: number; protocols: string[];
}
export interface CaptureFinding { severity: "pass" | "info" | "warn" | "fail"; title: string; detail: string; packets: number[] }
export interface CaptureAnalysis {
  meta: CaptureMeta; packets: CapturePacket[]; conversations: CaptureConversation[];
  findings: CaptureFinding[]; stats: Fact[]; evidence: Evidence[];
}
export interface CaptureOptions {
  points: { id: string; label: string }[]; filters: { id: string; label: string; bpf: string }[];
  traffic: { id: string; label: string }[]; seconds: { min: number; max: number; default: number };
}
export interface PacketDetail { no: number; tree: string; hex: string }
export const fetchCaptureOptions = () => getJSON<CaptureOptions>("/api/captures/options");
export const fetchCaptures = () => getJSON<CaptureMeta[]>("/api/captures");
export const fetchCapture = (id: string) => getJSON<CaptureAnalysis>(`/api/captures/${encodeURIComponent(id)}`);
export const fetchPacket = (id: string, no: number) => getJSON<PacketDetail>(`/api/captures/${encodeURIComponent(id)}/packets/${no}`);
export const startCapture = (b: { point: string; filter: string; seconds: number; traffic: string }) =>
  postJSON<CaptureAnalysis>("/api/captures", b);
export async function uploadCapture(file: File): Promise<CaptureAnalysis> {
  const res = await fetch(`/api/captures/upload?filename=${encodeURIComponent(file.name.slice(0, 100))}`, {
    method: "POST", headers: { "X-Workbench-Action": "1", "Content-Type": "application/octet-stream" }, body: file,
  });
  if (!res.ok) {
    let detail = `HTTP ${res.status}`;
    try { detail = (await res.json()).detail ?? detail; } catch { /* not JSON */ }
    throw new Error(detail);
  }
  return (await res.json()) as CaptureAnalysis;
}
