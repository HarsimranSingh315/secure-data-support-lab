import { useCallback, useEffect, useState } from "react";
import {
  fetchAlerts, fetchAudit, fetchRelated, setAlert,
  type AlertItem, type AlertList, type AuditEvent, type AuditResult,
} from "../api";
import { Collapsible, EvidenceList } from "../components/Evidence";

const KIND_LABEL: Record<string, string> = {
  audit: "Audit", auth_failure: "Failed login", permission_denied: "Denied", login: "Login", logout: "Logout",
};
const SEV_CLASS: Record<string, string> = { HIGH: "fail", MEDIUM: "warn", LOW: "info" };

function shortTime(t: string) {
  const m = /(\d{4}-\d\d-\d\d) (\d\d:\d\d:\d\d)/.exec(t);
  return m ? `${m[2]}` : t;
}

export function AuditAlerts() {
  return (
    <>
      <section className="page-head">
        <div>
          <h1>Audit &amp; alerts</h1>
          <p className="muted">The activity monitor's alerts, with what each rule means and what evidence sits behind it,
            and a search over the database audit trail (pgAudit + logins). Triage each alert: acknowledge it while you
            investigate, resolve it with a note.</p>
        </div>
      </section>
      <Alerts />
      <AuditSearch />
    </>
  );
}

function Alerts() {
  const [data, setData] = useState<AlertList | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [filter, setFilter] = useState<"open" | "acknowledged" | "resolved" | "all">("open");
  const [sel, setSel] = useState<string | null>(null);

  const load = useCallback(async () => {
    try { setData(await fetchAlerts()); setErr(null); } catch (e) { setErr((e as Error).message); }
  }, []);
  useEffect(() => { void load(); const t = setInterval(() => void load(), 15000); return () => clearInterval(t); }, [load]);

  const list = (data?.alerts ?? []).filter((a) => filter === "all" || a.status === filter);
  const cur = data?.alerts.find((a) => a.id === sel) ?? list[0] ?? null;
  return (
    <section className="panel alerts-panel">
      <div className="pk-toolbar">
        <h3>Activity-monitor alerts</h3>
        <div className="seg" role="tablist">
          {(["open", "acknowledged", "resolved", "all"] as const).map((f) => (
            <button key={f} role="tab" aria-selected={filter === f} className={filter === f ? "on" : ""} onClick={() => { setFilter(f); setSel(null); }}>
              {f} {f !== "all" && data ? `(${data.counts[f] ?? 0})` : ""}
            </button>
          ))}
        </div>
        <button className="btn btn-ghost btn-sm push-right" onClick={() => void load()}>Refresh</button>
      </div>
      {err && <p className="err">{err}</p>}
      {data && data.alerts.length === 0 && <p className="muted small">No alerts yet. Try Incidents → "Monitoring alerts on the cardholder table".</p>}
      {data && data.alerts.length > 0 && (
        <div className="alert-layout">
          <ul className="alert-list">
            {list.length === 0 && <li className="muted small">Nothing {filter}.</li>}
            {list.map((a) => (
              <li key={a.id}>
                <button className={`alert-item sev-${SEV_CLASS[a.severity] ?? "info"}${cur?.id === a.id ? " on" : ""}`} onClick={() => setSel(a.id)}>
                  <span className={`dstat dstat-${SEV_CLASS[a.severity] ?? "info"}`}>{a.severity}</span>
                  <span className="alert-rule">{a.rule}</span>
                  <span className="muted small">{a.user || "?"}@{a.source} · {shortTime(a.time)}</span>
                  {a.status !== "open" && <span className={`astate as-${a.status}`}>{a.status}</span>}
                </button>
              </li>
            ))}
          </ul>
          {cur && <AlertDetail key={cur.id} a={cur} onSaved={load} />}
        </div>
      )}
    </section>
  );
}

function AlertDetail({ a, onSaved }: { a: AlertItem; onSaved: () => void }) {
  const [note, setNote] = useState(a.note);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [rel, setRel] = useState<AuditEvent[] | null>(null);
  const [relErr, setRelErr] = useState<string | null>(null);
  useEffect(() => {
    fetchRelated(a.id).then((r) => setRel(r.events)).catch((e: Error) => setRelErr(e.message));
  }, [a.id]);

  async function save(status: AlertItem["status"]) {
    setBusy(true); setErr(null);
    try { await setAlert(a.id, status, note); onSaved(); } catch (e) { setErr((e as Error).message); } finally { setBusy(false); }
  }
  return (
    <div className="alert-detail">
      <div className="inc-area">{a.rule} · {a.database} · {a.time}</div>
      <h2>{a.detail}</h2>
      <dl className="facts">
        <div className="fact"><dt>who</dt><dd className="mono">{a.user || "(unknown)"}</dd></div>
        <div className="fact"><dt>from</dt><dd className="mono">{a.source}</dd></div>
        <div className="fact"><dt>evidence</dt><dd className="mono">{a.evidence}</dd></div>
      </dl>
      <div className="explain">
        <div><strong>What the rule detects</strong><p>{a.rule_explained}</p></div>
        <div><strong>Benign when</strong><p>{a.benign_when}</p></div>
        <div><strong>Ask</strong><p>{a.ask}</p></div>
      </div>
      <h3 className="sub">Triage</h3>
      <textarea className="notes" rows={3} value={note} onChange={(e) => setNote(e.target.value)}
        placeholder="What did you find? Who did you contact? Ticket or change number?" />
      <div className="btn-row pad-top">
        {a.status !== "acknowledged" && <button className="btn btn-ghost btn-sm" onClick={() => void save("acknowledged")} disabled={busy}>Acknowledge</button>}
        {a.status !== "resolved" && <button className="btn btn-sm" onClick={() => void save("resolved")} disabled={busy}>Resolve</button>}
        {a.status !== "open" && <button className="btn btn-ghost btn-sm" onClick={() => void save("open")} disabled={busy}>Reopen</button>}
        <span className="muted small">Status: {a.status}{a.updated ? ` · updated ${shortTime(a.updated.replace("T", " "))}` : ""}</span>
      </div>
      {err && <p className="err">{err}</p>}
      <h3 className="sub">Evidence behind it · same user or source, ±3 minutes</h3>
      {relErr && <p className="err">{relErr}</p>}
      {!rel && !relErr && <div className="skeleton block-skel small" />}
      {rel && <EventTable events={rel} compact />}
    </div>
  );
}

function AuditSearch() {
  const [f, setF] = useState({ kind: "", user: "", object: "", text: "", include_workbench: false });
  const [res, setRes] = useState<AuditResult | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  async function run(next = f) {
    setBusy(true);
    try { setRes(await fetchAudit(next)); setErr(null); } catch (e) { setErr((e as Error).message); } finally { setBusy(false); }
  }
  useEffect(() => { void run(); }, []); // eslint-disable-line react-hooks/exhaustive-deps
  const upd = (k: string, v: string | boolean) => { const n = { ...f, [k]: v }; setF(n); void run(n); };

  return (
    <section className="panel">
      <div className="pk-toolbar">
        <h3>Audit trail search</h3>
        {res && <span className="muted small push-right">{res.matched} of {res.total} events (last 6000 log lines)</span>}
      </div>
      <div className="form-row">
        <label>Kind
          <select value={f.kind} onChange={(e) => upd("kind", e.target.value)}>
            <option value="">All</option>{Object.entries(KIND_LABEL).map(([k, l]) => <option key={k} value={k}>{l}{res?.counts[k] ? ` (${res.counts[k]})` : ""}</option>)}
          </select>
        </label>
        <label>User
          <select value={f.user} onChange={(e) => upd("user", e.target.value)}>
            <option value="">Anyone</option>{res?.users.map((u) => <option key={u} value={u}>{u}</option>)}
          </select>
        </label>
        <label>Object
          <select value={f.object} onChange={(e) => upd("object", e.target.value)}>
            <option value="">Any</option>{res?.objects.map((o) => <option key={o} value={o}>{o}</option>)}
          </select>
        </label>
        <label>Text
          <input className="search" value={f.text} maxLength={80} placeholder="copy, grant, delete…"
            onChange={(e) => setF({ ...f, text: e.target.value })} onKeyDown={(e) => e.key === "Enter" && void run()} />
        </label>
        <button className="btn btn-ghost" onClick={() => void run()} disabled={busy}>{busy ? "Searching…" : "Search"}</button>
      </div>
      <label className="toggle small">
        <input type="checkbox" checked={f.include_workbench} onChange={(e) => upd("include_workbench", e.target.checked)} />
        <span>Include the workbench's own catalog reads{res && res.workbench_events ? ` (${res.workbench_events} hidden)` : ""}</span>
      </label>
      {err && <p className="err">{err}</p>}
      {res && <EventTable events={res.events} />}
      {res && <Collapsible title="Evidence"><EvidenceList evidence={res.evidence} /></Collapsible>}
    </section>
  );
}

function EventTable({ events, compact = false }: { events: AuditEvent[]; compact?: boolean }) {
  if (!events.length) return <p className="muted small">No events.</p>;
  return (
    <div className="pk-wrap">
      <table className="tbl pk audit-tbl">
        <thead><tr><th>Time (UTC)</th><th>Kind</th><th>User</th><th>From</th>{!compact && <th>Class</th>}<th>What</th></tr></thead>
        <tbody>{events.map((e, i) => (
          <tr key={i} className={e.kind === "auth_failure" || e.kind === "permission_denied" ? "pk-bad" :
            e.kind === "audit" && e.object.includes("cardholders") && e.audit_class === "READ" ? "pk-warn" : ""}>
            <td className="mono">{shortTime(e.time)}</td><td><span className={`kind k-${e.kind}`}>{KIND_LABEL[e.kind]}</span></td>
            <td className="mono">{e.user || "-"}</td><td className="mono">{e.source}</td>
            {!compact && <td className="mono">{e.audit_class ? `${e.audit_class} ${e.command}` : ""}</td>}
            <td className="pk-info">{e.kind === "audit" ? <><span className="mono">{e.object}</span> <span className="muted">{e.statement}</span></> : e.message}</td>
          </tr>))}</tbody>
      </table>
    </div>
  );
}
