import type { Check, Status } from "./api";

export const STATUS_LABEL: Record<Status, string> = {
  ok: "Healthy",
  degraded: "Degraded",
  down: "Down",
  unknown: "Unknown",
};

export function headline(overall: Status, counts: Record<Status, number>): string {
  if (overall === "ok") return "All lab services healthy";
  const parts: string[] = [];
  if (counts.down) parts.push(`${counts.down} down`);
  if (counts.degraded) parts.push(`${counts.degraded} degraded`);
  if (counts.unknown) parts.push(`${counts.unknown} not checkable`);
  return parts.length ? `Attention: ${parts.join(", ")}` : STATUS_LABEL[overall];
}

// Worst status wins; used for nodes that several checks describe (r3 = OSPF + firewall).
const RANK: Record<Status, number> = { ok: 0, unknown: 1, degraded: 2, down: 3 };
export function worst(statuses: Status[]): Status {
  if (!statuses.length) return "unknown";
  return statuses.reduce((a, b) => (RANK[b] > RANK[a] ? b : a));
}

export function statusFor(checks: Check[], ids: string[]): Status {
  return worst(checks.filter((c) => ids.includes(c.id)).map((c) => c.status));
}

export function groupChecks(checks: Check[]): [string, Check[]][] {
  const order = ["Network", "Identity", "Data", "Crypto", "Monitoring"];
  const map = new Map<string, Check[]>();
  for (const c of checks) map.set(c.group, [...(map.get(c.group) ?? []), c]);
  return [...map.entries()].sort((a, b) => order.indexOf(a[0]) - order.indexOf(b[0]));
}

export function clock(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "" : d.toLocaleTimeString([], { hour12: false });
}

export function ago(iso: string, now = Date.now()): string {
  const s = Math.max(0, Math.round((now - new Date(iso).getTime()) / 1000));
  if (s < 5) return "just now";
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  return m < 60 ? `${m}m ago` : `${Math.floor(m / 60)}h ago`;
}

const ERROR_LABEL: Record<string, string> = {
  timeout: "timed out",
  container_not_running: "container stopped",
  container_missing: "container missing",
  docker_unavailable: "docker unreachable",
};
export function exitLabel(code: number | null, error: string | null): string {
  if (error) return ERROR_LABEL[error] ?? error;
  return code === null ? "-" : `exit ${code}`;
}
