import { useEffect, useMemo, useRef, useState } from "react";
import {
  fetchCapture, fetchCaptureOptions, fetchCaptures, fetchPacket, startCapture, uploadCapture,
  type CaptureAnalysis, type CaptureMeta, type CaptureOptions, type CapturePacket, type PacketDetail,
} from "../api";
import { clock } from "../status";
import { Collapsible, EvidenceList } from "../components/Evidence";

export type CapPreset = Record<string, string | number>;
const PAGE = 100;
const SEV_LABEL = { fail: "Problem", warn: "Warning", info: "Info", pass: "OK" } as const;
const MARK_LABEL: Record<string, string> = {
  retransmission: "retransmission", dup_ack: "dup ACK", tls_alert: "TLS alert", icmp_unreach: "unreachable", icmp_ttl: "TTL exceeded",
};

export function Captures({ preset }: { preset: CapPreset | null }) {
  const [opts, setOpts] = useState<CaptureOptions | null>(null);
  const [history, setHistory] = useState<CaptureMeta[]>([]);
  const [an, setAn] = useState<CaptureAnalysis | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [form, setForm] = useState({ point: "r3", filter: "db", seconds: 8, traffic: "db" });
  const [running, setRunning] = useState<number | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    fetchCaptureOptions().then(setOpts).catch((e: Error) => setErr(e.message));
    fetchCaptures().then((h) => { setHistory(h); if (h[0] && !preset) void open(h[0].id); }).catch(() => undefined);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  useEffect(() => {
    if (preset) setForm((f) => ({ ...f, ...Object.fromEntries(Object.entries(preset).filter(([k]) => k in f)) }));
  }, [preset]);
  useEffect(() => {
    if (running === null) return;
    const t = setInterval(() => setRunning((r) => (r === null ? null : r + 1)), 1000);
    return () => clearInterval(t);
  }, [running === null]); // eslint-disable-line react-hooks/exhaustive-deps

  async function open(id: string) {
    try { setAn(await fetchCapture(id)); setErr(null); } catch (e) { setErr((e as Error).message); }
  }
  async function run() {
    setErr(null); setRunning(0);
    try {
      const a = await startCapture(form);
      setAn(a); setHistory(await fetchCaptures());
    } catch (e) { setErr((e as Error).message); } finally { setRunning(null); }
  }
  async function upload(f: File | undefined) {
    if (!f) return;
    setErr(null); setRunning(0);
    try { const a = await uploadCapture(f); setAn(a); setHistory(await fetchCaptures()); }
    catch (e) { setErr((e as Error).message); } finally { setRunning(null); if (fileRef.current) fileRef.current.value = ""; }
  }

  const bpf = opts?.filters.find((f) => f.id === form.filter)?.bpf ?? "";
  return (
    <>
      <section className="page-head">
        <div>
          <h1>Packet captures</h1>
          <p className="muted">Record real traffic on a lab device with <code>tcpdump</code>, decoded with <code>tshark</code>. The workbench
            points out what matters (unanswered SYNs, resets, TLS alerts, OSPF problems); the packets are there to check it.</p>
        </div>
      </section>
      {err && <div className="banner banner-down" role="alert">{err}</div>}

      <div className="cap-top">
        <section className="panel cap-form">
          <h3>New capture</h3>
          {opts && (
            <>
              <div className="form-row">
                <label>Where
                  <select value={form.point} onChange={(e) => setForm({ ...form, point: e.target.value })}>
                    {opts.points.map((p) => <option key={p.id} value={p.id}>{p.label}</option>)}
                  </select>
                </label>
                <label>What
                  <select value={form.filter} onChange={(e) => setForm({ ...form, filter: e.target.value })}>
                    {opts.filters.map((f) => <option key={f.id} value={f.id}>{f.label}</option>)}
                  </select>
                </label>
                <label>Seconds <span className="mono">{form.seconds}</span>
                  <input type="range" min={opts.seconds.min} max={opts.seconds.max} value={form.seconds}
                    onChange={(e) => setForm({ ...form, seconds: Number(e.target.value) })} />
                </label>
                <label>Test traffic while capturing
                  <select value={form.traffic} onChange={(e) => setForm({ ...form, traffic: e.target.value })}>
                    {opts.traffic.map((t) => <option key={t.id} value={t.id}>{t.label}</option>)}
                  </select>
                </label>
              </div>
              <div className="cmd-preview mono small">
                {form.point} $ tcpdump -ni any{form.point !== "toolbox" ? " -Q in" : ""} -s 256 -w capture.pcap {bpf}
              </div>
              <div className="btn-row pad-top">
                <button className="btn" onClick={() => void run()} disabled={running !== null}>
                  {running !== null ? `Capturing… ${Math.min(running, form.seconds)}/${form.seconds}s${running > form.seconds ? " · decoding" : ""}` : "Start capture"}
                </button>
                <button className="btn btn-ghost" onClick={() => fileRef.current?.click()} disabled={running !== null}>Upload a .pcap</button>
                <input ref={fileRef} type="file" accept=".pcap,.pcapng,.cap" hidden onChange={(e) => void upload(e.target.files?.[0])} />
              </div>
              {running !== null && <div className="progress"><span style={{ width: `${Math.min(100, (running / (form.seconds + 3)) * 100)}%` }} /></div>}
              <p className="muted tiny">Routers capture inbound only (<code>-Q in</code>) so forwarded packets are not counted twice. Snap length 256 bytes:
                headers and handshakes, not bulk data.</p>
            </>
          )}
        </section>
        <section className="panel cap-hist">
          <h3>Recent captures</h3>
          {history.length === 0 && <p className="muted small">None yet.</p>}
          <ul className="hist-list">
            {history.map((h) => (
              <li key={h.id}>
                <button className={`hist-item${an?.meta.id === h.id ? " hist-on" : ""}`} onClick={() => void open(h.id)}>
                  <span className="mono small">{clock(h.created)}</span>
                  <span>{h.source === "upload" ? h.point_label : `${h.point} · ${h.filter_label}`}</span>
                  <span className="muted small">{h.packets} pkts</span>
                </button>
              </li>
            ))}
          </ul>
        </section>
      </div>

      {an && <Analysis an={an} />}
    </>
  );
}

function Analysis({ an }: { an: CaptureAnalysis }) {
  const [q, setQ] = useState("");
  const [proto, setProto] = useState<string>("all");
  const [focus, setFocus] = useState<number[] | null>(null);
  const [page, setPage] = useState(0);
  const [stream, setStream] = useState<number | null>(an.conversations[0]?.stream ?? null);
  const [detail, setDetail] = useState<PacketDetail | null>(null);
  const [detailErr, setDetailErr] = useState<string | null>(null);
  useEffect(() => { setQ(""); setProto("all"); setFocus(null); setPage(0); setStream(an.conversations[0]?.stream ?? null); setDetail(null); }, [an.meta.id]); // eslint-disable-line

  const protos = useMemo(() => ["all", ...new Set(an.packets.map((p) => p.protocol))], [an]);
  const shown = useMemo(() => an.packets.filter((p) =>
    (proto === "all" || p.protocol === proto) && (!focus || focus.includes(p.no)) &&
    (!q || `${p.src} ${p.dst} ${p.sport ?? ""} ${p.dport ?? ""} ${p.protocol} ${p.info} ${p.marks.join(" ")}`.toLowerCase().includes(q.toLowerCase()))), [an, q, proto, focus]);
  const pages = Math.max(1, Math.ceil(shown.length / PAGE));

  async function openPacket(no: number) {
    setDetailErr(null);
    try { setDetail(await fetchPacket(an.meta.id, no)); } catch (e) { setDetailErr((e as Error).message); }
  }

  const m = an.meta;
  return (
    <section className="analysis">
      <div className="panel cap-meta">
        <div className="cap-meta-main">
          <h3>{m.source === "upload" ? m.point_label : `${m.point_label} · ${m.filter_label}`}</h3>
          <p className="muted small">{clock(m.created)} · {m.seconds ? `${m.seconds}s · ` : ""}{m.packets} packets · {(m.size / 1024).toFixed(1)} KB
            {m.traffic !== "none" && ` · test traffic: ${m.traffic}`}</p>
        </div>
        <a className="btn btn-ghost" href={`/api/captures/${m.id}/pcap`} download>Download .pcap (open in Wireshark)</a>
      </div>

      <div className="columns">
        <div className="cards-col">
          <div className="panel">
            <h3>Findings</h3>
            <ul className="findings">
              {an.findings.map((f, i) => (
                <li key={i} className={`finding sev-${f.severity}`}>
                  <div className="finding-head">
                    <span className={`dstat dstat-${f.severity === "info" ? "info" : f.severity}`}>{SEV_LABEL[f.severity]}</span>
                    <strong>{f.title}</strong>
                  </div>
                  <p>{f.detail}</p>
                  {f.packets.length > 0 && (
                    <button className="btn btn-ghost btn-sm" onClick={() => { setFocus(f.packets); setPage(0); }}>
                      Show {f.packets.length} packet{f.packets.length > 1 ? "s" : ""}
                    </button>
                  )}
                </li>
              ))}
            </ul>
          </div>

          {an.conversations.length > 0 && (
            <div className="panel">
              <h3>TCP conversations</h3>
              <table className="tbl conv">
                <thead><tr><th>#</th><th>Client</th><th>Server</th><th>State</th><th>Packets</th><th>Retrans.</th><th>Duration</th><th>Protocols</th></tr></thead>
                <tbody>{an.conversations.map((c) => (
                  <tr key={c.stream} className={`${stream === c.stream ? "row-on" : ""} ${c.state === "no answer" || c.state === "refused" ? "row-bad" : ""}`}
                    onClick={() => setStream(c.stream)} style={{ cursor: "pointer" }}>
                    <td className="mono">{c.stream}</td><td className="mono">{c.client}</td><td className="mono">{c.server}</td>
                    <td><span className={`conv-state cs-${c.state.replace(" ", "-")}`}>{c.state}</span></td>
                    <td className="mono">{c.packets}</td><td className="mono">{c.retransmissions || ""}</td>
                    <td className="mono">{c.duration}s</td><td>{c.protocols.join(", ")}</td>
                  </tr>))}</tbody>
              </table>
              {stream !== null && <Ladder packets={an.packets.filter((p) => p.stream === stream)} conv={an.conversations.find((c) => c.stream === stream)!} onOpen={openPacket} />}
            </div>
          )}
        </div>
        <aside className="side-col">
          <div className="panel">
            <h3>Summary</h3>
            <dl className="facts">{an.stats.map((s) => <div key={s.label} className="fact"><dt>{s.label}</dt><dd className="mono">{s.value}</dd></div>)}</dl>
          </div>
          <div className="panel note">
            <h3>Reading a capture</h3>
            <div className="guide-item"><strong>SYN, SYN-ACK, ACK</strong><p>The TCP handshake. All three = the connection got through.</p></div>
            <div className="guide-item"><strong>SYN, SYN, SYN…</strong><p>Retransmitted SYNs with no answer: dropped (firewall) or no way back.</p></div>
            <div className="guide-item"><strong>SYN → RST</strong><p>Refused: the host is there, nothing listens on the port.</p></div>
            <div className="guide-item"><strong>TLS Alert</strong><p>Someone aborted the handshake; "bad certificate" / "unknown CA" from the client means it rejected the server's certificate.</p></div>
            <div className="guide-item"><strong>Where you capture matters</strong><p>Seeing SYNs arrive on r3 but nothing reach the server proves r3 dropped them.</p></div>
          </div>
        </aside>
      </div>

      <div className="panel">
        <div className="pk-toolbar">
          <h3>Packets</h3>
          <input className="search" placeholder="Filter: address, port, protocol, text…" value={q} onChange={(e) => { setQ(e.target.value); setPage(0); }} aria-label="Filter packets" />
          <select value={proto} onChange={(e) => { setProto(e.target.value); setPage(0); }} aria-label="Protocol">
            {protos.map((p) => <option key={p} value={p}>{p === "all" ? "All protocols" : p}</option>)}
          </select>
          {focus && <button className="btn btn-ghost btn-sm" onClick={() => setFocus(null)}>Show all packets</button>}
          <span className="muted small push-right">{shown.length} of {an.packets.length}</span>
        </div>
        {shown.length === 0 ? <p className="muted small">No packets match.</p> : (
          <div className="pk-wrap">
            <table className="tbl pk">
              <thead><tr><th>No.</th><th>Time</th><th>Source</th><th>Destination</th><th>Proto</th><th>Len</th><th>Info</th></tr></thead>
              <tbody>{shown.slice(page * PAGE, page * PAGE + PAGE).map((p) => (
                <tr key={p.no} className={rowClass(p)} onClick={() => void openPacket(p.no)} tabIndex={0}
                  onKeyDown={(e) => e.key === "Enter" && void openPacket(p.no)}>
                  <td className="mono">{p.no}</td><td className="mono">{p.time.toFixed(3)}</td>
                  <td className="mono">{p.src}{p.sport ? `:${p.sport}` : ""}</td><td className="mono">{p.dst}{p.dport ? `:${p.dport}` : ""}</td>
                  <td>{p.protocol}</td><td className="mono">{p.length}</td>
                  <td className="pk-info">{p.marks.map((k) => <span key={k} className={`mark mark-${k}`}>{MARK_LABEL[k] ?? k}</span>)}{p.info}</td>
                </tr>))}</tbody>
            </table>
          </div>
        )}
        {pages > 1 && (
          <div className="pager">
            <button className="btn btn-ghost btn-sm" disabled={page === 0} onClick={() => setPage(page - 1)}>Previous</button>
            <span className="small muted">Page {page + 1} of {pages}</span>
            <button className="btn btn-ghost btn-sm" disabled={page >= pages - 1} onClick={() => setPage(page + 1)}>Next</button>
          </div>
        )}
        {detailErr && <p className="err">{detailErr}</p>}
        {detail && (
          <div className="pk-detail">
            <div className="runbook-head"><strong>Packet {detail.no}</strong><span className="muted small">tshark -V -x</span>
              <button className="btn btn-ghost btn-sm push-right" onClick={() => setDetail(null)}>Close</button></div>
            <div className="pk-detail-cols">
              <pre className="output tree">{detail.tree}</pre>
              {detail.hex && <pre className="output hex">{detail.hex}</pre>}
            </div>
          </div>
        )}
        <Collapsible title={`How this was captured and decoded (${an.evidence.length} commands)`}>
          <EvidenceList evidence={an.evidence} />
        </Collapsible>
      </div>
    </section>
  );
}

function rowClass(p: CapturePacket): string {
  if (p.marks.includes("tls_alert") || p.marks.includes("icmp_unreach") || p.flags.includes("RST")) return "pk-bad";
  if (p.marks.includes("retransmission")) return "pk-warn";
  if (p.flags.length === 1 && p.flags[0] === "SYN") return "pk-syn";
  return "";
}

function Ladder({ packets, conv, onOpen }: { packets: CapturePacket[]; conv: { client: string; server: string; state: string }; onOpen: (n: number) => void }) {
  const rows = packets.slice(0, 24);
  const clientIp = conv.client.split(":")[0];
  const H = 30, W = 560;
  return (
    <div className="ladder">
      <div className="ladder-head"><span className="mono small">{conv.client}</span><span className="muted small">stream · {conv.state}</span><span className="mono small">{conv.server}</span></div>
      <svg viewBox={`0 0 ${W} ${rows.length * H + 16}`} className="ladder-svg" role="img" aria-label="TCP conversation ladder diagram">
        <line x1="70" y1="0" x2="70" y2={rows.length * H + 16} className="ladder-axis" />
        <line x1={W - 70} y1="0" x2={W - 70} y2={rows.length * H + 16} className="ladder-axis" />
        {rows.map((p, i) => {
          const fromClient = p.src === clientIp;
          const y = i * H + 18;
          const x1 = fromClient ? 72 : W - 72, x2 = fromClient ? W - 78 : 78;
          const label = p.flags.length ? `[${p.flags.join(", ")}]` + (p.protocol !== "TCP" ? ` ${p.protocol}` : "") : p.protocol;
          return (
            <g key={p.no} className={`ladder-row ${rowClass(p)}`} onClick={() => onOpen(p.no)} role="button" tabIndex={0}
              onKeyDown={(e) => e.key === "Enter" && onOpen(p.no)}>
              <text x="4" y={y + 4} className="ladder-time">{p.time.toFixed(3)}</text>
              <line x1={x1} y1={y} x2={x2} y2={y + 8} className="ladder-arrow" markerEnd="url(#arrow)" />
              <text x={W / 2} y={y - 2} textAnchor="middle" className="ladder-label">{label}{p.marks.includes("retransmission") ? " (retransmission)" : ""}</text>
            </g>
          );
        })}
        <defs><marker id="arrow" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto"><path d="M0,0 L8,4 L0,8 z" className="ladder-head-mark" /></marker></defs>
      </svg>
      {packets.length > rows.length && <p className="muted tiny">First {rows.length} of {packets.length} packets.</p>}
    </div>
  );
}
