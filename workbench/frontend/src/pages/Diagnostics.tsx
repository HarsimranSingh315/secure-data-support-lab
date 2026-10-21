import { useEffect, useMemo, useState } from "react";
import { fetchCatalog, runDiagnostic, runWizard, type Catalog, type CatalogOp, type DiagResult, type WizardResult } from "../api";
import { clock } from "../status";
import { EvidenceList, FactsTable, TryIt, Collapsible } from "../components/Evidence";

export type DiagPreset = Record<string, string | number>;

const D_LABEL: Record<string, string> = { pass: "Pass", warn: "Warning", fail: "Fail", error: "Could not run", info: "Info" };

export function Diagnostics({ preset }: { preset: DiagPreset | null }) {
  const [cat, setCat] = useState<Catalog | null>(null);
  const [catErr, setCatErr] = useState<string | null>(null);
  useEffect(() => { fetchCatalog().then(setCat).catch((e: Error) => setCatErr(e.message)); }, []);

  return (
    <>
      <section className="page-head">
        <div>
          <h1>Diagnostics</h1>
          <p className="muted">Safe, predefined tests run from {cat?.vantage ?? "the Site A toolbox"} and the routers. You pick from fixed
            lists; nothing you type is ever run as a command.</p>
        </div>
      </section>
      {catErr && <div className="banner banner-down" role="alert"><strong>Could not load the test catalog.</strong> {catErr}</div>}
      {cat && (
        <div className="columns">
          <div className="cards-col">
            <Wizard cat={cat} />
            <Tools cat={cat} preset={preset} />
          </div>
          <aside className="side-col"><ReadingGuide /></aside>
        </div>
      )}
    </>
  );
}

// ---------------------------------------------------------------- guided diagnosis

function Wizard({ cat }: { cat: Catalog }) {
  const services = cat.targets.filter((t) => t.ports.length);
  const [target, setTarget] = useState("db");
  const t = services.find((x) => x.id === target) ?? services[0];
  const [port, setPort] = useState<number>(t.ports[0].number);
  const [res, setRes] = useState<WizardResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => { setPort(t.ports[0].number); }, [t]);

  const run = async () => {
    setBusy(true); setErr(null); setRes(null);
    try { setRes(await runWizard(t.id, port)); } catch (e) { setErr((e as Error).message); } finally { setBusy(false); }
  };

  return (
    <section className="panel wizard">
      <h3>Guided diagnosis</h3>
      <p className="muted small">"A user in Site A can't reach a service." Walks up the stack (name → reachability → path → port → TLS)
        and says at which layer it breaks.</p>
      <div className="form-row">
        <label>Service
          <select value={t.id} onChange={(e) => setTarget(e.target.value)}>
            {services.map((s) => <option key={s.id} value={s.id}>{s.label} · {s.host}</option>)}
          </select>
        </label>
        <label>Port
          <select value={port} onChange={(e) => setPort(Number(e.target.value))}>
            {t.ports.map((p) => <option key={p.number} value={p.number}>{p.number} · {p.label}</option>)}
          </select>
        </label>
        <button className="btn" onClick={run} disabled={busy}>{busy ? "Diagnosing…" : "Diagnose"}</button>
      </div>
      {t.ports.find((p) => p.number === port)?.note && <p className="muted small">{t.ports.find((p) => p.number === port)!.note}.</p>}
      {err && <p className="err">{err}</p>}
      {busy && <div className="steps-skeleton skeleton" />}
      {res && (
        <div className="wizard-res">
          <div className={`verdict verdict-${res.verdict}`}>
            <div className="verdict-layer">{res.verdict === "pass" ? "No network problem found" : `Problem layer: ${res.layer}`}</div>
            <p>{res.conclusion}</p>
          </div>
          <ol className="steps">
            {res.steps.map((s) => (
              <li key={s.label} className={`step step-${s.result.status}`}>
                <details>
                  <summary>
                    <span className={`dstat dstat-${s.result.status}`}>{D_LABEL[s.result.status]}</span>
                    <span className="step-label">{s.label}</span>
                    <span className="step-sum">{s.result.summary}</span>
                  </summary>
                  <ResultBody r={s.result} />
                </details>
              </li>
            ))}
          </ol>
        </div>
      )}
    </section>
  );
}

// ---------------------------------------------------------------- individual tools

function Tools({ cat, preset }: { cat: Catalog; preset: DiagPreset | null }) {
  const [opId, setOpId] = useState<string>(String(preset?.op ?? "traceroute"));
  const op = cat.ops.find((o) => o.id === opId) ?? cat.ops[0];
  const [target, setTarget] = useState<string>(String(preset?.target ?? "db"));
  const [router, setRouter] = useState<string>(String(preset?.router ?? "r1"));
  const [port, setPort] = useState<number | "">(preset?.port ? Number(preset.port) : "");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [history, setHistory] = useState<DiagResult[]>([]);

  const targets = useMemo(() => cat.targets.filter((t) => !op.needs.includes("port") || t.ports.some((p) => !op.tls_only || p.tls)), [cat, op]);
  const tgt = targets.find((t) => t.id === target) ?? targets[0];
  const ports = (tgt?.ports ?? []).filter((p) => !op.tls_only || p.tls);
  useEffect(() => { if (tgt && tgt.id !== target) setTarget(tgt.id); }, [tgt, target]);
  useEffect(() => { if (op.needs.includes("port") && !ports.some((p) => p.number === port)) setPort(ports[0]?.number ?? ""); }, [op, ports, port]);

  useEffect(() => {
    if (!preset) return;
    setOpId(String(preset.op));
    if (preset.target) setTarget(String(preset.target));
    if (preset.router) setRouter(String(preset.router));
    if (preset.port) setPort(Number(preset.port));
    void run(String(preset.op), { target: preset.target, router: preset.router, port: preset.port });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [preset]);

  async function run(id = op.id, params?: Record<string, string | number | undefined>) {
    const o = cat.ops.find((x) => x.id === id)!;
    const p = params ?? {
      target: o.needs.includes("target") ? tgt?.id : undefined,
      router: o.needs.includes("router") ? router : undefined,
      port: o.needs.includes("port") ? port || undefined : undefined,
    };
    setBusy(true); setErr(null);
    try { const r = await runDiagnostic(id, p); setHistory((h) => [r, ...h].slice(0, 12)); }
    catch (e) { setErr((e as Error).message); } finally { setBusy(false); }
  }

  return (
    <section className="panel tools">
      <h3>Individual tests</h3>
      <div className="op-grid" role="radiogroup" aria-label="Test">
        {cat.ops.map((o: CatalogOp) => (
          <button key={o.id} role="radio" aria-checked={o.id === op.id} className={`op${o.id === op.id ? " op-on" : ""}`} onClick={() => setOpId(o.id)}>
            <span className="op-layer">{o.layer}</span>
            <span className="op-title">{o.title}</span>
            <span className="op-hint">{o.hint}</span>
          </button>
        ))}
      </div>
      <div className="form-row">
        {op.needs.includes("router") && (
          <label>On router
            <select value={router} onChange={(e) => setRouter(e.target.value)}>
              {cat.routers.map((r) => <option key={r} value={r}>{r}</option>)}
            </select>
          </label>
        )}
        {op.needs.includes("target") && (
          <label>{op.needs.includes("router") ? "Destination" : "Target"}
            <select value={tgt?.id} onChange={(e) => setTarget(e.target.value)}>
              {targets.map((t) => <option key={t.id} value={t.id}>{t.label} · {t.host}</option>)}
            </select>
          </label>
        )}
        {op.needs.includes("port") && (
          <label>Port
            <select value={port} onChange={(e) => setPort(Number(e.target.value))}>
              {ports.map((p) => <option key={p.number} value={p.number}>{p.number} · {p.label}</option>)}
            </select>
          </label>
        )}
        <button className="btn" onClick={() => void run()} disabled={busy}>{busy ? "Running…" : `Run ${op.title.toLowerCase()}`}</button>
      </div>
      {op.needs.includes("port") && ports.find((p) => p.number === port)?.note && (
        <p className="muted small">{ports.find((p) => p.number === port)!.note}.</p>
      )}
      {err && <p className="err">{err}</p>}
      {history.length === 0 && !busy && <p className="muted small">Results appear here, newest first, so you can compare runs (try TCP to db:22 and ldap:636).</p>}
      <div className="history">
        {history.map((r, i) => (
          <article key={r.ran_at + r.title + i} className={`result result-${r.status}`}>
            <header>
              <span className={`dstat dstat-${r.status}`}>{D_LABEL[r.status]}</span>
              <span className="result-title">{r.title}</span>
              <span className="muted small">{clock(r.ran_at)}</span>
            </header>
            <p className="result-sum">{r.summary}</p>
            {i === 0 ? <ResultBody r={r} /> : <Collapsible title="Details"><ResultBody r={r} /></Collapsible>}
          </article>
        ))}
      </div>
    </section>
  );
}

function ResultBody({ r }: { r: DiagResult }) {
  return (
    <div className="result-body">
      <p>{r.meaning}</p>
      <FactsTable facts={r.facts} />
      <Collapsible title={`Evidence (${r.evidence.length} command${r.evidence.length === 1 ? "" : "s"})`}>
        <EvidenceList evidence={r.evidence} />
        <TryIt evidence={r.evidence} />
      </Collapsible>
    </div>
  );
}

// ---------------------------------------------------------------- reading guide

function ReadingGuide() {
  const items: [string, string][] = [
    ["Timeout vs refused",
      "Refused = the host answered with a reset: the network works, nothing listens on the port. Timeout = no answer at all: something dropped the packet (usually a firewall) or there is no way back."],
    ["Missing route vs firewall drop",
      "No route: ping and traceroute stop at a router, and that router has no route to the destination. Firewall drop: ping and traceroute reach the host, but one port times out; the drop rule's counter goes up."],
    ["DNS failure vs TCP failure",
      "If the name does not resolve, nothing is ever sent. If it resolves and TCP then fails, the name was fine: look at the network or service."],
    ["TCP works, TLS fails",
      "The handshake completed, so network and service are fine. The certificate is the problem: wrong name (SAN), not issued by a trusted CA, or expired. Fix the certificate; never switch verification off."],
    ["Path changed",
      "If traceroute goes r1 → r3 instead of r1 → r2 → r3, OSPF has lost the cheaper path. Check the r1–r2 and r2–r3 adjacencies on the map."],
  ];
  return (
    <div className="panel note">
      <h3>Reading the result</h3>
      {items.map(([t, d]) => (
        <div key={t} className="guide-item"><strong>{t}</strong><p>{d}</p></div>
      ))}
    </div>
  );
}
