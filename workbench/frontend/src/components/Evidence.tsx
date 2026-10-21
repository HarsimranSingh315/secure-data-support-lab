import { useState } from "react";
import type { Evidence, Fact } from "../api";
import { exitLabel } from "../status";

export function FactsTable({ facts }: { facts: Fact[] }) {
  if (!facts.length) return null;
  return (
    <dl className="facts">
      {facts.map((f, i) => (
        <div key={i} className="fact"><dt>{f.label}</dt><dd className="mono">{f.value}</dd></div>
      ))}
    </dl>
  );
}

export function EvidenceList({ evidence, emptyText = "No command ran." }: { evidence: Evidence[]; emptyText?: string }) {
  if (!evidence.length) return <p className="muted">{emptyText}</p>;
  return (
    <>
      {evidence.map((e, i) => (
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
          {e.truncated && <p className="muted small pad">Output was truncated by the workbench's size limit.</p>}
        </div>
      ))}
    </>
  );
}

export function TryIt({ evidence }: { evidence: Evidence[] }) {
  const unique = [...new Set(evidence.map((e) => e.repro))];
  if (!unique.length) return null;
  return (
    <>
      <p className="muted small">Run the same command from your Mac's terminal, in the lab folder:</p>
      {unique.map((r) => <CommandLine key={r} command={r} service="" boxed />)}
    </>
  );
}

export function CommandLine({ command, service, boxed = false }: { command: string; service: string; boxed?: boolean }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(command);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch { /* clipboard blocked: the text is still selectable */ }
  };
  return (
    <div className={`cmd${boxed ? " cmd-boxed" : ""}`}>
      <code className="mono">{service ? <span className="cmd-host">{service} $ </span> : "$ "}{command}</code>
      <button className="btn btn-ghost btn-sm" onClick={copy}>{copied ? "Copied" : "Copy"}</button>
    </div>
  );
}

export function Collapsible({ title, children, open = false }: { title: string; children: React.ReactNode; open?: boolean }) {
  return (
    <details className="collapsible" open={open}>
      <summary>{title}</summary>
      <div className="collapsible-body">{children}</div>
    </details>
  );
}
