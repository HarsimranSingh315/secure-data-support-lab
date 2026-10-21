import { useCallback, useEffect, useRef, useState } from "react";
import { fetchOverview, type Overview } from "./api";
import { ago, clock, groupChecks, headline } from "./status";
import { PathStrip } from "./components/PathStrip";
import { CheckCard } from "./components/CheckCard";
import { Drawer } from "./components/EvidenceDrawer";
import { Timeline } from "./components/Timeline";
import { StatusDot } from "./components/StatusDot";
import { NetworkMap } from "./pages/NetworkMap";
import { Diagnostics, type DiagPreset } from "./pages/Diagnostics";

const AUTO_MS = 10_000;
type Page = "overview" | "map" | "diagnostics";
const PAGES: { id: Page; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "map", label: "Network map" },
  { id: "diagnostics", label: "Diagnostics" },
];

function pageFromHash(): Page {
  const h = window.location.hash.replace("#", "");
  return (PAGES.find((p) => p.id === h)?.id ?? "overview");
}

export default function App() {
  const [page, setPage] = useState<Page>(pageFromHash());
  const [data, setData] = useState<Overview | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [auto, setAuto] = useState(true);
  const [selected, setSelected] = useState<string | null>(null);
  const [preset, setPreset] = useState<DiagPreset | null>(null);
  const [, tick] = useState(0);
  const inflight = useRef<AbortController | null>(null);

  useEffect(() => {
    const onHash = () => setPage(pageFromHash());
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);
  const go = (p: Page) => { window.location.hash = p; setPage(p); window.scrollTo(0, 0); };

  const load = useCallback(async (refresh: boolean) => {
    inflight.current?.abort();
    const ctl = new AbortController();
    inflight.current = ctl;
    setLoading(true);
    try {
      setData(await fetchOverview(refresh, ctl.signal));
      setError(null);
    } catch (e) {
      if ((e as Error).name !== "AbortError") setError((e as Error).message);
    } finally {
      if (inflight.current === ctl) setLoading(false);
    }
  }, []);

  useEffect(() => { void load(true); }, [load]);
  useEffect(() => {
    if (!auto) return;
    const t = setInterval(() => void load(false), AUTO_MS);
    return () => clearInterval(t);
  }, [auto, load]);
  useEffect(() => {
    const t = setInterval(() => tick((n) => n + 1), 5_000);
    return () => clearInterval(t);
  }, []);

  const selectedCheck = data?.checks.find((c) => c.id === selected);
  const goDiagnose = (p: DiagPreset) => { setSelected(null); setPreset({ ...p, _t: Date.now() }); go("diagnostics"); };

  return (
    <div className="shell">
      <header className="topbar">
        <div className="brand">
          <svg className="mark" viewBox="0 0 24 24" aria-hidden="true">
            <path d="M12 2 4 5v6c0 5 3.4 9.3 8 11 4.6-1.7 8-6 8-11V5l-8-3Z" />
            <path d="M8.5 12.5 11 15l4.5-5" className="tick" />
          </svg>
          <div>
            <div className="brand-name">DataShield Support Workbench</div>
            <div className="brand-sub">SecureData Support Lab · isolated practice environment</div>
          </div>
        </div>
        <div className="topbar-right">
          {data && (
            <button className={`top-status top-${data.overall}`} onClick={() => go("overview")} title="Overall lab status">
              <StatusDot status={data.overall} /> {headline(data.overall, data.counts)}
            </button>
          )}
          <span className="lab-tag" title="Everything here is a local lab with synthetic data">LAB · not production</span>
          <label className="toggle">
            <input type="checkbox" checked={auto} onChange={(e) => setAuto(e.target.checked)} />
            <span>Auto-refresh</span>
          </label>
        </div>
      </header>

      <nav className="rail" aria-label="Sections">
        {PAGES.map((p) => (
          <a key={p.id} className={`rail-item${page === p.id ? " active" : ""}`} aria-current={page === p.id ? "page" : undefined}
            href={`#${p.id}`} onClick={(e) => { e.preventDefault(); go(p.id); }}>{p.label}</a>
        ))}
      </nav>

      <main className="main">
        {error && (
          <div className="banner banner-down" role="alert">
            <strong>Workbench API unreachable.</strong> {error}. Is the workbench container running?
            Try <code>docker compose ps workbench</code>.
          </div>
        )}

        {page === "overview" && (
          <>
            {data && !data.lab_reachable && (
              <div className="banner banner-unknown" role="status">
                <strong>Docker is not reachable from the workbench</strong>, so no lab check could run.
                Nothing below is reported as healthy.
              </div>
            )}
            <section className={`hero hero-${data?.overall ?? "unknown"}`} aria-live="polite">
              <div className="hero-main">
                {data ? <StatusDot status={data.overall} size="lg" /> : <span className="skeleton dot" />}
                <div>
                  <h1>{data ? headline(data.overall, data.counts) : "Running first checks…"}</h1>
                  <p className="muted">
                    {data
                      ? <>Last checked {clock(data.checked_at)} ({ago(data.checked_at)}) · {data.checks.length} live checks in {data.duration_ms} ms</>
                      : "Each card runs a real command inside the lab."}
                  </p>
                </div>
              </div>
              <div className="hero-side">
                <div className="counts">
                  {(["ok", "degraded", "down", "unknown"] as const).map((s) => (
                    <div key={s} className={`count count-${s}`}>
                      <span className="count-n">{data ? data.counts[s] : "–"}</span>
                      <span className="count-l">{{ ok: "healthy", degraded: "degraded", down: "down", unknown: "unknown" }[s]}</span>
                    </div>
                  ))}
                </div>
                <button className="btn" onClick={() => void load(true)} disabled={loading}>{loading ? "Checking…" : "Run checks now"}</button>
              </div>
            </section>

            <PathStrip checks={data?.checks ?? []} onSelect={setSelected} onMap={() => go("map")} />

            <div className="columns">
              <div className="cards-col">
                {!data && !error && <SkeletonGrid />}
                {data && data.checks.length === 0 && <p className="empty">No checks are configured.</p>}
                {data && data.checks.length > 0 && (
                  <div className="grid">
                    {groupChecks(data.checks).flatMap(([, checks]) => checks).map((c) => (
                      <CheckCard key={c.id} check={c} active={c.id === selected} onOpen={() => setSelected(c.id)} />
                    ))}
                  </div>
                )}
              </div>
              <aside className="side-col">
                <Timeline events={data?.events ?? []} onSelect={setSelected} />
                <div className="panel note">
                  <h3>How to read this</h3>
                  <p>Every card is a live check: the workbench runs one fixed, allow-listed command in a lab
                    container and shows you the exact command and its output. Click a card to see the evidence.</p>
                  <p className="muted small">Try it: run <code>make break S=kms-sealed</code>, then watch the card and
                    the timeline. Use the <a href="#diagnostics" onClick={(e) => { e.preventDefault(); go("diagnostics"); }}>Diagnostics</a> page to find out why.</p>
                </div>
              </aside>
            </div>
          </>
        )}

        {page === "map" && <NetworkMap overview={data} onOpenCheck={setSelected} goDiagnose={goDiagnose} />}
        {page === "diagnostics" && <Diagnostics preset={preset} />}
      </main>

      {selectedCheck && (
        <Drawer onClose={() => setSelected(null)} content={{
          title: selectedCheck.title, status: selectedCheck.status, time: selectedCheck.checked_at,
          summary: selectedCheck.summary, meaning: selectedCheck.meaning, facts: selectedCheck.facts,
          evidence: selectedCheck.evidence,
        }} />
      )}
    </div>
  );
}

function SkeletonGrid() {
  return (
    <div className="grid" aria-hidden="true">
      {Array.from({ length: 6 }).map((_, i) => <div key={i} className="card skeleton-card" />)}
    </div>
  );
}
