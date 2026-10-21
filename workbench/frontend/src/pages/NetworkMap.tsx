import { useCallback, useEffect, useRef, useState } from "react";
import { fetchTopology, type MapLink, type MapRouter, type Overview, type Status, type Topology } from "../api";
import { ago, clock, STATUS_LABEL } from "../status";
import { StatusDot, StatusPill } from "../components/StatusDot";
import { Drawer, type DrawerContent } from "../components/EvidenceDrawer";
import { Collapsible } from "../components/Evidence";

// Layout of the designed topology (positions only; all states come from the API).
const W = 1120, H = 470;
const ROUTER_POS: Record<string, [number, number]> = { r1: [335, 250], r2: [560, 100], r3: [785, 250] };
const SITE_A = { x: 24, y: 130, w: 196, h: 230 };
const SITE_B = { x: 900, y: 70, w: 196, h: 360 };
const HOSTS_A = [{ id: "toolbox", label: "toolbox", sub: "10.10.10.10" }, { id: "ldap", label: "ldap", sub: "10.10.10.20" }];
const HOSTS_B = [
  { id: "db", label: "db", sub: "10.20.20.10" }, { id: "kms", label: "kms", sub: "10.20.20.20" },
  { id: "app", label: "app", sub: "10.20.20.30" }, { id: "dam", label: "dam", sub: "no network" },
];
const LINK_GEOM: Record<string, { d: string; lx: number; ly: number }> = {
  lan_a: { d: `M ${SITE_A.x + SITE_A.w} 250 L 335 250`, lx: 278, ly: 238 },
  r1_r2: { d: "M 335 250 L 560 100", lx: 430, ly: 158 },
  r2_r3: { d: "M 560 100 L 785 250", lx: 690, ly: 158 },
  r1_r3: { d: "M 335 250 Q 560 430 785 250", lx: 560, ly: 362 },
  lan_b: { d: `M 785 250 L ${SITE_B.x} 250`, lx: 842, ly: 238 },
};

type Sel = { kind: "router"; id: string } | { kind: "link"; id: string } | { kind: "host"; id: string } | null;

export function NetworkMap({ overview, onOpenCheck, goDiagnose }: {
  overview: Overview | null;
  onOpenCheck: (id: string) => void;
  goDiagnose: (preset: Record<string, string | number>) => void;
}) {
  const [topo, setTopo] = useState<Topology | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [sel, setSel] = useState<Sel>(null);
  const inflight = useRef<AbortController | null>(null);

  const load = useCallback(async (refresh: boolean) => {
    inflight.current?.abort();
    const ctl = new AbortController();
    inflight.current = ctl;
    setLoading(true);
    try { setTopo(await fetchTopology(refresh, ctl.signal)); setError(null); }
    catch (e) { if ((e as Error).name !== "AbortError") setError((e as Error).message); }
    finally { if (inflight.current === ctl) setLoading(false); }
  }, []);
  useEffect(() => { void load(true); const t = setInterval(() => void load(false), 10_000); return () => clearInterval(t); }, [load]);

  const checks = overview?.checks ?? [];
  const hostStatus = (id: string): Status => checks.find((c) => c.id === id)?.status ?? "unknown";
  const router = (id: string) => topo?.routers.find((r) => r.id === id);
  const link = (id: string) => topo?.links.find((l) => l.id === id);
  const inPath = (id: string) => topo?.path.links.includes(id) ?? false;

  const drawer: DrawerContent | null = (() => {
    if (!sel || !topo) return null;
    if (sel.kind === "router") { const r = router(sel.id); return r ? routerDrawer(r, topo, goDiagnose) : null; }
    if (sel.kind === "link") { const l = link(sel.id); return l ? linkDrawer(l, inPath(l.id), topo, goDiagnose) : null; }
    return null;
  })();

  return (
    <>
      <section className="page-head">
        <div>
          <h1>Network map</h1>
          <p className="muted">Live from the routers: interface state, OSPF adjacencies, costs and the path traffic takes right now.
            Click any router, link or server.</p>
        </div>
        <div className="page-actions">
          {topo && <span className="muted small">Updated {clock(topo.checked_at)} ({ago(topo.checked_at)})</span>}
          <button className="btn" onClick={() => void load(true)} disabled={loading}>{loading ? "Reading routers…" : "Refresh"}</button>
        </div>
      </section>

      {error && <div className="banner banner-down" role="alert"><strong>Could not load the map.</strong> {error}</div>}

      {topo && (
        <div className={`path-banner path-${!topo.path.reached ? "down" : topo.path.uses_backup ? "degraded" : "ok"}`} role="status">
          <span className="path-banner-label">Current path, Site A → database</span>
          <span className="mono">{topo.path.summary}</span>
          {topo.path.uses_backup && <span className="pill pill-degraded">backup link</span>}
          <button className="btn btn-ghost btn-sm" onClick={() => setSel({ kind: "link", id: topo.path.links[1] ?? "lan_a" })}>Why this path?</button>
          {topo.path.notes.map((n) => <span key={n} className="path-note small">{n}</span>)}
        </div>
      )}

      <div className="map-wrap panel">
        {!topo && !error && <div className="map-skeleton skeleton" />}
        {topo && (
          <svg viewBox={`0 0 ${W} ${H}`} className="map" role="group" aria-label="Network topology">
            <defs>
              <filter id="glow" x="-20%" y="-20%" width="140%" height="140%">
                <feGaussianBlur stdDeviation="4" result="b" /><feMerge><feMergeNode in="b" /><feMergeNode in="SourceGraphic" /></feMerge>
              </filter>
            </defs>

            <SiteBox {...SITE_A} title="Site A · 10.10.10.0/24" />
            <SiteBox {...SITE_B} title="Site B · 10.20.20.0/24" />

            {topo.links.map((l) => {
              const g = LINK_GEOM[l.id];
              if (!g) return null;
              const cost = l.ends[0]?.ospf_cost;
              return (
                <g key={l.id} className={`link link-${l.status}${inPath(l.id) ? " link-inpath" : ""}${sel?.kind === "link" && sel.id === l.id ? " link-selected" : ""}`}
                  onClick={() => setSel({ kind: "link", id: l.id })} role="button" tabIndex={0}
                  aria-label={`${l.label}: ${STATUS_LABEL[l.status]}. ${l.summary}`}
                  onKeyDown={(e) => e.key === "Enter" && setSel({ kind: "link", id: l.id })}>
                  <path d={g.d} className="link-hit" />
                  {inPath(l.id) && <path d={g.d} className="link-flow" filter="url(#glow)" />}
                  <path d={g.d} className="link-line" />
                  <text x={g.lx} y={g.ly} className="link-label" textAnchor="middle">
                    {l.kind === "transit" ? `${l.subnet.replace("/24", "")}${cost != null ? ` · cost ${cost}` : ""}` : ""}
                  </text>
                  {l.status !== "ok" && (
                    <text x={g.lx} y={g.ly + 16} className={`link-alert alert-${l.status}`} textAnchor="middle">{STATUS_LABEL[l.status]}</text>
                  )}
                </g>
              );
            })}

            {(["r1", "r2", "r3"] as const).map((id) => {
              const r = router(id);
              const [x, y] = ROUTER_POS[id];
              const st = r?.status ?? "unknown";
              return (
                <g key={id} className={`rnode rnode-${st}${sel?.kind === "router" && sel.id === id ? " rnode-selected" : ""}`}
                  transform={`translate(${x} ${y})`} onClick={() => setSel({ kind: "router", id })} role="button" tabIndex={0}
                  aria-label={`Router ${id}: ${r?.summary ?? "unknown"}`} onKeyDown={(e) => e.key === "Enter" && setSel({ kind: "router", id })}>
                  <circle r="34" className="rnode-ring" />
                  <circle r="27" className="rnode-core" />
                  <path d="M -11 -4 h 22 m -6 -5 l 6 5 l -6 5 M 11 6 h -22 m 6 -5 l -6 5 l 6 5" className="rnode-glyph" />
                  <text y="56" textAnchor="middle" className="rnode-name">{id}{id === "r3" ? " + firewall" : ""}</text>
                  <text y="72" textAnchor="middle" className="rnode-sub">{r ? r.summary.split(" · ")[0] : "no data"}</text>
                </g>
              );
            })}

            {HOSTS_A.map((h, i) => (
              <HostNode key={h.id} x={SITE_A.x + 22} y={SITE_A.y + 44 + i * 82} {...h}
                status={h.id === "toolbox" ? (topo.path.hops.length ? "ok" : "unknown") : hostStatus(h.id)}
                onClick={() => (h.id === "toolbox" ? setSel({ kind: "link", id: "lan_a" }) : onOpenCheck(h.id))} />
            ))}
            {HOSTS_B.map((h, i) => (
              <HostNode key={h.id} x={SITE_B.x + 22} y={SITE_B.y + 40 + i * 78} {...h} status={hostStatus(h.id)}
                inPath={h.id === "db" && topo.path.reached} onClick={() => onOpenCheck(h.id)} />
            ))}
          </svg>
        )}
        <div className="map-legend" aria-hidden="true">
          <span><i className="lg lg-ok" />Up · adjacency Full</span>
          <span><i className="lg lg-degraded" />Up, adjacency not Full</span>
          <span><i className="lg lg-down" />Down</span>
          <span><i className="lg lg-path" />Current path to db</span>
        </div>
      </div>

      {topo && (
        <div className="map-tables">
          {topo.links.filter((l) => l.kind === "transit").map((l) => (
            <button key={l.id} className={`mini-card card-${l.status}`} onClick={() => setSel({ kind: "link", id: l.id })}>
              <div className="card-head"><StatusDot status={l.status} /><span className="card-title">{l.label}</span><StatusPill status={l.status} /></div>
              <div className="card-summary">{l.summary}</div>
              <div className="card-foot"><span className="mono">{l.subnet}</span><span>{inPath(l.id) ? "in current path" : ""}</span></div>
            </button>
          ))}
        </div>
      )}

      {drawer && <Drawer content={drawer} onClose={() => setSel(null)} />}
    </>
  );
}

function SiteBox({ x, y, w, h, title }: { x: number; y: number; w: number; h: number; title: string }) {
  return (
    <g className="site">
      <rect x={x} y={y} width={w} height={h} rx="14" />
      <text x={x + 14} y={y + 22} className="site-title">{title}</text>
    </g>
  );
}

function HostNode({ x, y, label, sub, status, onClick, inPath = false }: {
  x: number; y: number; label: string; sub: string; status: Status; onClick: () => void; inPath?: boolean;
}) {
  return (
    <g className={`hnode hnode-${status}${inPath ? " hnode-inpath" : ""}`} transform={`translate(${x} ${y})`} onClick={onClick}
      role="button" tabIndex={0} aria-label={`${label}: ${STATUS_LABEL[status]}`} onKeyDown={(e) => e.key === "Enter" && onClick()}>
      <rect width="152" height="54" rx="10" />
      <circle cx="20" cy="27" r="6" className="hnode-dot" />
      <text x="36" y="24" className="hnode-name">{label}</text>
      <text x="36" y="41" className="hnode-sub">{sub}</text>
    </g>
  );
}

function routerDrawer(r: MapRouter, topo: Topology, goDiagnose: (p: Record<string, string | number>) => void): DrawerContent {
  const linkLabel = (id: string | null) => topo.links.find((l) => l.id === id)?.label ?? "";
  return {
    title: `Router ${r.id}${r.id === "r3" ? " (Site B edge + firewall)" : r.id === "r1" ? " (Site A edge)" : " (core)"}`,
    status: r.status, time: topo.checked_at, summary: r.summary,
    meaning: "Interfaces, OSPF neighbours and the routing table as this router reports them right now. "
      + "A route learned from OSPF disappears when the neighbour it came from is not Full.",
    evidence: r.evidence,
    extra: (
      <>
        <section className="drawer-sec">
          <h3>Interfaces</h3>
          <table className="tbl">
            <thead><tr><th>Interface</th><th>Address</th><th>State</th><th>MTU</th><th>OSPF cost</th><th>Adjacent</th><th>Link</th></tr></thead>
            <tbody>{r.interfaces.map((i) => (
              <tr key={i.name} className={i.state !== "UP" ? "row-bad" : ""}>
                <td className="mono">{i.name}</td><td className="mono">{i.address ?? "-"}</td><td>{i.state}</td>
                <td className="mono">{i.mtu ?? "-"}</td><td className="mono">{i.ospf_cost ?? "-"}</td>
                <td className="mono">{i.ospf_neighbors != null ? `${i.ospf_adjacent}/${i.ospf_neighbors}` : "-"}</td>
                <td>{linkLabel(i.link)}</td>
              </tr>))}</tbody>
          </table>
        </section>
        <section className="drawer-sec">
          <h3>OSPF neighbours</h3>
          {r.neighbors.length === 0 ? <p className="muted">No neighbours.</p> : (
            <table className="tbl">
              <thead><tr><th>Neighbour</th><th>Router ID</th><th>State</th><th>Via</th><th>Address</th></tr></thead>
              <tbody>{r.neighbors.map((n) => (
                <tr key={n.router_id + n.interface} className={n.state.startsWith("Full") ? "" : "row-warn"}>
                  <td>{n.name}</td><td className="mono">{n.router_id}</td><td>{n.state}</td><td className="mono">{n.interface}</td><td className="mono">{n.address}</td>
                </tr>))}</tbody>
            </table>)}
        </section>
        <section className="drawer-sec">
          <h3>Routing table</h3>
          <table className="tbl">
            <thead><tr><th>Prefix</th><th>From</th><th>Next hop</th><th>Out</th><th>Metric</th></tr></thead>
            <tbody>{r.routes.map((x) => (
              <tr key={x.prefix}><td className="mono">{x.prefix}</td><td>{x.protocol}</td><td className="mono">{x.next_hop}</td>
                <td className="mono">{x.interface}</td><td className="mono">{x.protocol === "connected" ? "-" : x.metric}</td></tr>))}</tbody>
          </table>
        </section>
        <section className="drawer-sec">
          <h3>Dig deeper</h3>
          <div className="btn-row">
            <button className="btn btn-ghost btn-sm" onClick={() => goDiagnose({ op: "ospf_interfaces", router: r.id })}>OSPF interfaces on {r.id}</button>
            <button className="btn btn-ghost btn-sm" onClick={() => goDiagnose({ op: "route", router: r.id, target: "db" })}>Route to db from {r.id}</button>
            {r.id === "r3" && <button className="btn btn-ghost btn-sm" onClick={() => goDiagnose({ op: "firewall" })}>Firewall rules</button>}
          </div>
        </section>
      </>
    ),
  };
}

function linkDrawer(l: MapLink, inPath: boolean, topo: Topology, goDiagnose: (p: Record<string, string | number>) => void): DrawerContent {
  const why = l.id === "r1_r3"
    ? "This is the slow backup link (OSPF cost 100). OSPF only uses it when the path through r2 (10 + 10 = 20) is unavailable."
    : l.kind === "transit"
      ? "A core link (OSPF cost 10). OSPF picks the lowest total cost, so the normal path from Site A to Site B is r1 → r2 → r3."
      : "The LAN between the servers and their gateway router.";
  return {
    title: `${l.label} · ${l.subnet}`, status: l.status, time: topo.checked_at, summary: l.summary,
    meaning: `${why} ${inPath ? "Traffic from Site A to the database is using this link right now." : "Traffic to the database is not using this link right now."}`,
    evidence: [...topo.routers.filter((r) => l.ends.some((e) => e.router === r.id)).flatMap((r) => r.evidence.slice(0, 2)), ...(inPath ? topo.path.evidence : [])],
    extra: (
      <>
        <section className="drawer-sec">
          <h3>Both ends</h3>
          <table className="tbl">
            <thead><tr><th>Router</th><th>Interface</th><th>Address</th><th>State</th><th>MTU</th><th>OSPF cost</th><th>Neighbour state</th></tr></thead>
            <tbody>{l.ends.map((e) => (
              <tr key={e.router}><td>{e.router}</td><td className="mono">{e.interface ?? "-"}</td><td className="mono">{e.address}</td>
                <td>{e.state ?? "-"}</td><td className="mono">{e.mtu ?? "-"}</td><td className="mono">{e.ospf_cost ?? "-"}</td>
                <td>{l.kind === "lan" ? "n/a (no OSPF neighbours on a LAN)" : e.neighbor_state ?? "none"}</td></tr>))}</tbody>
          </table>
          {l.kind === "transit" && <p className="muted small pad-top">For an adjacency to reach Full, both ends must agree on area, hello/dead timers, network type and MTU.</p>}
        </section>
        <section className="drawer-sec">
          <Collapsible title="Current path (traceroute from the toolbox)">
            <p className="mono small">{topo.path.summary}</p>
          </Collapsible>
          <div className="btn-row pad-top">
            {l.ends.map((e) => (
              <button key={e.router} className="btn btn-ghost btn-sm" onClick={() => goDiagnose({ op: "ospf_interfaces", router: e.router })}>OSPF interfaces on {e.router}</button>
            ))}
            <button className="btn btn-ghost btn-sm" onClick={() => goDiagnose({ op: "traceroute", target: "db" })}>Traceroute to db</button>
          </div>
        </section>
      </>
    ),
  };
}

