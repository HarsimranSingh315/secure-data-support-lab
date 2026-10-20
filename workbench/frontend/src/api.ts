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
