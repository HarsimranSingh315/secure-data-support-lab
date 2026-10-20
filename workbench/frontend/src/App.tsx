import { useCallback, useEffect, useRef, useState } from "react";
import { fetchOverview, type Check, type Overview } from "./api";
import { ago, clock, groupChecks, headline } from "./status";
import { PathStrip } from "./components/PathStrip";
import { CheckCard } from "./components/CheckCard";
import { EvidenceDrawer } from "./components/EvidenceDrawer";
import { Timeline } from "./components/Timeline";
import { StatusDot } from "./components/StatusDot";

const AUTO_MS = 10_000;

export default function App() {
  const [data, setData] = useState<Overview | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [auto, setAuto] = useState(true);
  const [selected, setSelected] = useState<string | null>(null);
  const [, tick] = useState(0);
  const inflight = useRef<AbortController | null>(null);

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
    const t = setInterval(() => tick((n) => n + 1), 5_000); // keeps "12s ago" fresh
    return () => clearInterval(t);
  }, []);

  const selectedCheck: Check | undefined = data?.checks.find((c) => c.id === selected);

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
          <span className="lab-tag" title="Everything here is a local lab with synthetic data">LAB · not production</span>
          <label className="toggle">
            <input type="checkbox" checked={auto} onChange={(e) => setAuto(e.target.checked)} />
            <span>Auto-refresh 10s</span>
          </label>
          <button className="btn" onClick={() => void load(true)} disabled={loading}>
            {loading ? "Checking…" : "Run checks now"}
          </button>
        </div>
      </header>

      <nav className="rail" aria-label="Sections">
        <a className="rail-item active" aria-current="page" href="#overview">Overview</a>
      </nav>

      <main className="main" id="overview">
        {error && (
          <div className="banner banner-down" role="alert">
            <strong>Workbench API unreachable.</strong> {error}. Is the workbench container running?
            Try <code>docker compose ps workbench</code>.
          </div>
        )}
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
          <div className="counts">
            {(["ok", "degraded", "down", "unknown"] as const).map((s) => (
              <div key={s} className={`count count-${s}`}>
                <span className="count-n">{data ? data.counts[s] : "–"}</span>
                <span className="count-l">{{ ok: "healthy", degraded: "degraded", down: "down", unknown: "unknown" }[s]}</span>
              </div>
            ))}
          </div>
        </section>

        <PathStrip checks={data?.checks ?? []} onSelect={setSelected} />

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
              <p className="muted small">Try it: stop <code>kms</code> in Docker Desktop, or run{" "}
                <code>make break S=kms-sealed</code>, then watch the card and the timeline.</p>
            </div>
          </aside>
        </div>
      </main>

      {selectedCheck && <EvidenceDrawer check={selectedCheck} onClose={() => setSelected(null)} />}
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
