import type { Check } from "../api";
import { ago } from "../status";
import { StatusDot, StatusPill } from "./StatusDot";

export function CheckCard({ check, active, onOpen }: { check: Check; active: boolean; onOpen: () => void }) {
  const ev = check.evidence[0];
  return (
    <button className={`card card-${check.status}${active ? " card-active" : ""}`} onClick={onOpen}
      aria-label={`${check.title}: ${check.summary}. Open evidence.`}>
      <div className="card-eyebrow">{check.group}</div>
      <div className="card-head">
        <StatusDot status={check.status} />
        <span className="card-title">{check.title}</span>
        <StatusPill status={check.status} />
      </div>
      <div className="card-summary">{check.summary}</div>
      <div className="card-foot">
        <span className="mono">{ev ? `ran in ${ev.service}` : "no evidence"}</span>
        <span>{ev ? `${ev.duration_ms} ms` : ""}</span>
        <span>{ago(check.checked_at)}</span>
      </div>
    </button>
  );
}
