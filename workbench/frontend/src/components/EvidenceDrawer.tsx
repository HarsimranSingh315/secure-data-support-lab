import { useEffect, useRef, useState } from "react";
import type { Check } from "../api";
import { clock, exitLabel } from "../status";
import { StatusDot, StatusPill } from "./StatusDot";

export function EvidenceDrawer({ check, onClose }: { check: Check; onClose: () => void }) {
  const closeRef = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    closeRef.current?.focus();
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  return (
    <div className="drawer-backdrop" onClick={onClose}>
      <aside className="drawer" role="dialog" aria-modal="true" aria-labelledby="drawer-title"
        onClick={(e) => e.stopPropagation()}>
        <div className="drawer-head">
          <StatusDot status={check.status} size="lg" />
          <div className="drawer-titles">
            <h2 id="drawer-title">{check.title}</h2>
            <div className="muted small">
              <StatusPill status={check.status} /> live check · {clock(check.checked_at)}
            </div>
          </div>
          <button ref={closeRef} className="btn btn-ghost" onClick={onClose} aria-label="Close">Close</button>
        </div>

        <p className="drawer-summary">{check.summary}</p>

        <section className="drawer-sec">
          <h3>What this means</h3>
          <p>{check.meaning}</p>
        </section>

        {check.facts.length > 0 && (
          <section className="drawer-sec">
            <h3>Facts from the output</h3>
            <dl className="facts">
              {check.facts.map((f, i) => (
                <div key={i} className="fact"><dt>{f.label}</dt><dd className="mono">{f.value}</dd></div>
              ))}
            </dl>
          </section>
        )}

        <section className="drawer-sec">
          <h3>Evidence</h3>
          {check.evidence.length === 0 && <p className="muted">The check failed before running a command.</p>}
          {check.evidence.map((e, i) => (
            <div key={i} className="evidence">
              <div className="evidence-meta">
                <span>ran in <strong className="mono">{e.service}</strong></span>
                <span className={`badge ${e.error || e.exit_code ? "badge-warn" : "badge-ok"}`}>{exitLabel(e.exit_code, e.error)}</span>
                <span>{e.duration_ms} ms</span>
              </div>
              <CommandLine command={e.command} service={e.service} />
              <pre className="output" tabIndex={0} aria-label="Command output">
                {e.output.trim() || (e.error ? "(no output: the command did not run)" : "(no output)")}
              </pre>
              {e.truncated && <p className="muted small">Output was truncated by the workbench's size limit.</p>}
            </div>
          ))}
        </section>

        <section className="drawer-sec">
          <h3>Try it yourself</h3>
          <p className="muted small">Run the same command from your Mac's terminal, in the lab folder:</p>
          {check.evidence.map((e, i) => (
            <CommandLine key={i} command={e.repro} service="" />
          ))}
        </section>
      </aside>
    </div>
  );
}

function CommandLine({ command, service }: { command: string; service: string }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(command);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch { /* clipboard blocked: the text is still selectable */ }
  };
  return (
    <div className="cmd">
      <code className="mono">{service ? <span className="cmd-host">{service} $ </span> : "$ "}{command}</code>
      <button className="btn btn-ghost btn-sm" onClick={copy}>{copied ? "Copied" : "Copy"}</button>
    </div>
  );
}
