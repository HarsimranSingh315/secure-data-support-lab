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
