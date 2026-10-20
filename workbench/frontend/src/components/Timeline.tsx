import type { LabEvent } from "../api";
import { clock, STATUS_LABEL } from "../status";
import { StatusDot } from "./StatusDot";

export function Timeline({ events, onSelect }: { events: LabEvent[]; onSelect: (id: string) => void }) {
  const changes = events.filter((e) => e.previous !== null);
  const baseline = events.filter((e) => e.previous === null);
  return (
    <div className="panel">
      <h3>Status changes</h3>
      {changes.length === 0 ? (
        <p className="muted small">
          {baseline.length ? `No changes since the workbench started watching ${baseline.length} checks.` : "Waiting for the first checks…"}
        </p>
      ) : (
        <ol className="timeline">
          {changes.slice(0, 20).map((e, i) => (
            <li key={`${e.time}-${e.check_id}-${i}`}>
              <button className="tl-item" onClick={() => onSelect(e.check_id)}>
                <span className="tl-time mono">{clock(e.time)}</span>
                <StatusDot status={e.status} />
                <span className="tl-text">
                  <strong>{e.title}</strong>
                  <span className="muted"> {STATUS_LABEL[e.previous!]} → {STATUS_LABEL[e.status]}</span>
                  <span className="tl-sum">{e.summary}</span>
                </span>
              </button>
            </li>
          ))}
        </ol>
      )}
      <p className="muted tiny">Kept in memory by the workbench; cleared when it restarts.</p>
    </div>
  );
}
