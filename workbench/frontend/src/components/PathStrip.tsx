import type { Check } from "../api";
import { statusFor } from "../status";
import { StatusDot } from "./StatusDot";

// The request path an analyst in Site A uses to reach the data in Site B.
// Each node's colour comes from the live checks listed in `ids` (worst one wins).
const NODES: { label: string; sub: string; ids: string[]; open: string }[] = [
  { label: "Site A", sub: "toolbox · ldap", ids: ["ldap"], open: "ldap" },
  { label: "r1", sub: "edge", ids: ["r1"], open: "r1" },
  { label: "r2", sub: "core", ids: ["r2"], open: "r2" },
  { label: "r3", sub: "edge + firewall", ids: ["r3", "firewall"], open: "firewall" },
  { label: "Site B", sub: "app · db · kms", ids: ["app", "db", "kms"], open: "app" },
];

export function PathStrip({ checks, onSelect }: { checks: Check[]; onSelect: (id: string) => void }) {
  return (
    <section className="path panel" aria-label="Request path from Site A to Site B">
      <div className="path-head">
        <h3>Request path</h3>
        <span className="muted small">How a Site A analyst reaches the data in Site B. Click a hop for its evidence.</span>
      </div>
      <ol className="path-row">
        {NODES.map((n, i) => {
          const st = checks.length ? statusFor(checks, n.ids) : "unknown";
          return (
            <li key={n.label} className="path-cell">
              {i > 0 && <span className={`path-link link-${st}`} aria-hidden="true" />}
              <button className={`path-node node-${st}`} onClick={() => onSelect(n.open)} disabled={!checks.length}>
                <StatusDot status={st} />
                <span className="path-label">{n.label}</span>
                <span className="path-sub">{n.sub}</span>
              </button>
            </li>
          );
        })}
      </ol>
    </section>
  );
}
