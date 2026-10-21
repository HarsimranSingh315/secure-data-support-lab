import { useCallback, useEffect, useState } from "react";
import { fetchActions, fetchIncidents, fetchRunbook, incidentAction, type ActionEntry, type Incident } from "../api";
import { ago, clock } from "../status";
import { Markdown } from "../components/Markdown";
import { Collapsible } from "../components/Evidence";

export type Goto = (page: "overview" | "map" | "diagnostics" | "captures", preset?: Record<string, string | number>) => void;

const STATE_LABEL = { ready: "Ready", active: "In progress", resolved: "Resolved" } as const;

// Where to start looking, by area. Deliberately generic: tools, not answers.
const START: Record<string, { label: string; page: "overview" | "map" | "diagnostics" | "captures"; preset?: Record<string, string | number> }[]> = {
  Network: [
    { label: "Network map", page: "map" },
    { label: "Guided diagnosis", page: "diagnostics" },
    { label: "Capture on r3", page: "captures", preset: { point: "r3", filter: "db", traffic: "db" } },
  ],
  "TLS / PKI": [
    { label: "Overview", page: "overview" },
    { label: "TLS certificate test", page: "diagnostics", preset: { op: "tls", target: "db", port: 5432 } },
    { label: "Capture at the client", page: "captures", preset: { point: "toolbox", filter: "db", traffic: "db" } },
  ],
  Identity: [
    { label: "Overview", page: "overview" },
    { label: "TLS test on LDAP", page: "diagnostics", preset: { op: "tls", target: "ldap", port: 389 } },
    { label: "Capture LDAP", page: "captures", preset: { point: "toolbox", filter: "ldap", traffic: "none" } },
  ],
  "Key management": [
    { label: "Overview", page: "overview" },
    { label: "Guided diagnosis (KMS)", page: "diagnostics" },
  ],
  Database: [
    { label: "Overview", page: "overview" },
    { label: "Guided diagnosis", page: "diagnostics" },
  ],
  Security: [
    { label: "Overview (activity monitor)", page: "overview" },
  ],
};

function useNotes(id: string): [string, (v: string) => void] {
  const key = `wb-notes-${id}`;
  const [v, setV] = useState("");
  useEffect(() => {
    try { setV(localStorage.getItem(key) ?? ""); } catch { setV(""); }
  }, [key]);
  const set = (x: string) => {
    setV(x);
    try { localStorage.setItem(key, x); } catch { /* storage blocked: keep in memory */ }
  };
  return [v, set];
}

export function Incidents({ go }: { go: Goto }) {
  const [list, setList] = useState<Incident[] | null>(null);
  const [actions, setActions] = useState<ActionEntry[]>([]);
  const [sel, setSel] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [confirm, setConfirm] = useState<"break" | "fix" | null>(null);
  const [runbook, setRunbook] = useState<string | null>(null);
  const [, tick] = useState(0);

  const load = useCallback(async () => {
    try {
      const [l, a] = await Promise.all([fetchIncidents(), fetchActions()]);
      setList(l); setActions(a); setErr(null);
      setSel((s) => s ?? (l.find((x) => x.state === "active")?.id ?? l[0]?.id ?? null));
    } catch (e) { setErr((e as Error).message); }
  }, []);
  useEffect(() => { void load(); }, [load]);
  useEffect(() => { const t = setInterval(() => tick((n) => n + 1), 1000); return () => clearInterval(t); }, []);

  const inc = list?.find((x) => x.id === sel) ?? null;
  const [notes, setNotes] = useNotes(inc?.id ?? "none");

  const act = async (action: "break" | "hint" | "fix" | "clear") => {
    if (!inc) return;
    setBusy(action); setErr(null); setConfirm(null);
    try {
      const updated = await incidentAction(inc.id, action);
      setList((l) => l?.map((x) => (x.id === updated.id ? updated : x)) ?? null);
      setActions(await fetchActions());
    } catch (e) { setErr((e as Error).message); await load(); }
    finally { setBusy(null); }
  };

  const openRunbook = async () => {
    if (!inc) return;
    try { setRunbook((await fetchRunbook(inc.id)).markdown); } catch (e) { setErr((e as Error).message); }
  };

  const active = list?.filter((x) => x.state === "active") ?? [];
  const solved = list?.filter((x) => x.state === "resolved") ?? [];

  return (
    <>
      <section className="page-head">
        <div>
          <h1>Incidents</h1>
          <p className="muted">Nine realistic faults. Break one and you get only what a customer would say. Find the cause with the
            Overview, Map, Diagnostics and Captures, then fix it. Each button runs the lab's own <code>scripts/scenario.sh</code>,
            the same as <code>make break</code> in the terminal.</p>
        </div>
        <div className="page-actions small muted">
          {list && <span>{active.length} in progress · {solved.length} of {list.length} solved</span>}
        </div>
      </section>
      {err && <div className="banner banner-down" role="alert">{err}</div>}

      <div className="inc-layout">
        <nav className="inc-list" aria-label="Incidents">
          {!list && <div className="skeleton inc-skel" />}
          {list?.map((x) => (
            <button key={x.id} className={`inc-item inc-${x.state}${x.id === sel ? " inc-on" : ""}`} onClick={() => { setSel(x.id); setRunbook(null); setConfirm(null); }}>
              <span className="inc-area">{x.area}</span>
              <span className="inc-title">{x.title}</span>
              <span className="inc-meta">
                <span className={`inc-state st-${x.state}`}>{STATE_LABEL[x.state]}</span>
                {x.state === "active" && x.broken_at && <span className="mono">{elapsed(x.broken_at)}</span>}
                {x.state === "resolved" && x.minutes_to_resolve != null && <span className="mono">{x.minutes_to_resolve} min</span>}
              </span>
            </button>
          ))}
        </nav>

        {inc && (
          <section className="panel inc-detail" aria-live="polite">
            <div className="inc-head">
              <div>
                <div className="inc-area">{inc.area} · <span className="mono">{inc.id}</span></div>
                <h2>{inc.title}</h2>
              </div>
              <span className={`inc-state st-${inc.state} big`}>{STATE_LABEL[inc.state]}</span>
            </div>

            {inc.state === "ready" && (
              <div className="inc-body">
                <p className="muted">Starting this incident changes your lab: it injects a real fault. You will get the customer's
                  ticket, nothing more. The cause stays hidden until you fix it.</p>
                {confirm === "break" ? (
                  <div className="confirm">
                    <span>Inject the fault into your lab now?</span>
                    <button className="btn btn-danger" onClick={() => void act("break")} disabled={!!busy}>{busy === "break" ? "Breaking…" : "Yes, break it"}</button>
                    <button className="btn btn-ghost" onClick={() => setConfirm(null)}>Cancel</button>
                  </div>
                ) : (
                  <button className="btn btn-danger" onClick={() => setConfirm("break")} disabled={!!busy}>Start incident</button>
                )}
              </div>
            )}

            {inc.state !== "ready" && inc.customer && (
              <div className="ticket">
                <div className="ticket-head">
                  <span className="mono">{inc.ticket_id}</span>
                  <span className={`prio prio-${inc.priority}`}>{inc.priority}</span>
                  <span className="muted small">opened {inc.broken_at ? clock(inc.broken_at) : ""}</span>
                  {inc.state === "active" && inc.broken_at && <span className="ticket-timer mono">{elapsed(inc.broken_at)}</span>}
                </div>
                <blockquote>“{inc.customer}”</blockquote>
              </div>
            )}

            {inc.state === "active" && (
              <div className="inc-body">
                <h3>Start investigating</h3>
                <div className="btn-row">
                  {(START[inc.area] ?? []).map((s) => (
                    <button key={s.label} className="btn btn-ghost btn-sm" onClick={() => go(s.page, s.preset)}>{s.label}</button>
                  ))}
                </div>

                <h3>Your notes</h3>
                <textarea className="notes" value={notes} onChange={(e) => setNotes(e.target.value)} rows={5}
                  placeholder={"What did you check? What did you see? What do you think the root cause is?\n(Saved in this browser.)"} />

                <h3>Stuck?</h3>
                {inc.hints.map((h, i) => <div key={i} className="hint"><strong>Hint</strong> {h}</div>)}
                <div className="btn-row">
                  {inc.hints.length === 0 && (
                    <button className="btn btn-ghost btn-sm" onClick={() => void act("hint")} disabled={!!busy}>{busy === "hint" ? "…" : "Show a hint"}</button>
                  )}
                  <button className="btn btn-ghost btn-sm" onClick={() => void openRunbook()}>Open the runbook (contains the answer)</button>
                </div>

                <h3>Resolve</h3>
                <p className="muted small">When you know the cause, fix it the way the runbook would (by hand in the terminal), or let the
                  lab restore its baseline:</p>
                {confirm === "fix" ? (
                  <div className="confirm">
                    <span>Restore the baseline and close the incident?</span>
                    <button className="btn" onClick={() => void act("fix")} disabled={!!busy}>{busy === "fix" ? "Fixing…" : "Yes, fix it"}</button>
                    <button className="btn btn-ghost" onClick={() => setConfirm(null)}>Cancel</button>
                  </div>
                ) : (
                  <button className="btn" onClick={() => setConfirm("fix")} disabled={!!busy}>Fix and close</button>
                )}
              </div>
            )}

            {inc.state === "resolved" && (
              <div className="inc-body">
                <div className="reveal">
                  <div className="reveal-label">What was broken</div>
                  <p>{inc.reveal ?? "(not available)"}</p>
                  <p className="muted small">Resolved {inc.fixed_at ? clock(inc.fixed_at) : ""}
                    {inc.minutes_to_resolve != null && <> · time to resolve <strong>{inc.minutes_to_resolve} min</strong> (lab metric)</>}
                    {inc.hints.length > 0 && <> · {inc.hints.length} hint used</>}</p>
                </div>
                {notes && (<><h3>Your notes</h3><pre className="notes-view">{notes}</pre></>)}
                <div className="btn-row">
                  <button className="btn btn-ghost btn-sm" onClick={() => void openRunbook()}>Compare with the runbook</button>
                  <button className="btn btn-ghost btn-sm" onClick={() => setConfirm("break")}>Run it again</button>
                  <button className="btn btn-ghost btn-sm" onClick={() => void act("clear")}>Clear this record</button>
                </div>
                {confirm === "break" && (
                  <div className="confirm">
                    <span>Inject the fault again?</span>
                    <button className="btn btn-danger" onClick={() => void act("break")} disabled={!!busy}>{busy === "break" ? "Breaking…" : "Yes, break it"}</button>
                    <button className="btn btn-ghost" onClick={() => setConfirm(null)}>Cancel</button>
                  </div>
                )}
                <p className="muted small">Write it up: <code>docs/postmortem-template.md</code>.</p>
              </div>
            )}

            {busy && <p className="muted small">Running <code>scripts/scenario.sh {busy} {inc.id}</code>… this can take up to a minute.</p>}

            {inc.last_run && (
              <Collapsible title={`Script output: ${inc.last_run.action} (${inc.last_run.ok ? "ok" : "failed"}, ${(inc.last_run.duration_ms / 1000).toFixed(1)} s)`}>
                <pre className="output">{inc.last_run.output || "(no output)"}</pre>
              </Collapsible>
            )}

            {runbook && (
              <div className="runbook">
                <div className="runbook-head">
                  <strong>Runbook</strong>
                  <span className="muted small mono">{inc.runbook}</span>
                  <button className="btn btn-ghost btn-sm push-right" onClick={() => setRunbook(null)}>Hide</button>
                </div>
                <Markdown text={runbook} />
              </div>
            )}
          </section>
        )}
      </div>

      <section className="panel action-log">
        <h3>Action log</h3>
        {actions.length === 0 ? <p className="muted small">No actions yet.</p> : (
          <table className="tbl">
            <thead><tr><th>Time</th><th>Action</th><th>Incident</th><th>Result</th><th>Duration</th></tr></thead>
            <tbody>{actions.slice(0, 15).map((a, i) => (
              <tr key={i}><td className="mono">{clock(a.at)} <span className="muted">({ago(a.at)})</span></td><td>{a.action}</td>
                <td className="mono">{a.incident}</td><td>{a.ok ? "ok" : `failed (exit ${a.exit_code})`}</td>
                <td className="mono">{(a.duration_ms / 1000).toFixed(1)} s</td></tr>))}</tbody>
          </table>
        )}
        <p className="muted tiny">Every lab change made from the workbench is recorded in <code>.workbench/actions.jsonl</code>.</p>
      </section>
    </>
  );
}

function elapsed(iso: string): string {
  const s = Math.max(0, Math.floor((Date.now() - new Date(iso).getTime()) / 1000));
  const m = Math.floor(s / 60);
  return `${m}:${String(s % 60).padStart(2, "0")}`;
}
