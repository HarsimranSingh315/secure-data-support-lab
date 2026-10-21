import { useEffect, useState } from "react";
import { fetchDbAccess, fetchDirectory, runLoginTest, type DbAccess, type Directory, type LoginTest } from "../api";
import { clock } from "../status";
import { Collapsible, EvidenceList, TryIt } from "../components/Evidence";

const PRIVS = ["SELECT", "INSERT", "UPDATE", "DELETE"];
const SENSITIVE = new Set(["cardholders"]);

export function IdentityDb() {
  const [dir, setDir] = useState<Directory | null>(null);
  const [db, setDb] = useState<DbAccess | null>(null);
  const [err, setErr] = useState<{ dir?: string; db?: string }>({});
  const [loading, setLoading] = useState(false);

  async function load() {
    setLoading(true);
    const [d, a] = await Promise.allSettled([fetchDirectory(), fetchDbAccess()]);
    if (d.status === "fulfilled") setDir(d.value);
    if (a.status === "fulfilled") setDb(a.value);
    setErr({ dir: d.status === "rejected" ? String(d.reason?.message ?? d.reason) : undefined,
             db: a.status === "rejected" ? String(a.reason?.message ?? a.reason) : undefined });
    setLoading(false);
  }
  useEffect(() => { void load(); }, []);

  return (
    <>
      <section className="page-head">
        <div>
          <h1>Identity &amp; database</h1>
          <p className="muted">Who exists in the directory, how a login really works (database → directory over StartTLS),
            and who can read what in PostgreSQL, explained down to the role each permission comes from.</p>
        </div>
        <div className="page-actions">
          {db && <span className="muted small">Read {clock(db.read_at)}</span>}
          <button className="btn" onClick={() => void load()} disabled={loading}>{loading ? "Reading…" : "Refresh"}</button>
        </div>
      </section>

      <div className="columns">
        <div className="cards-col">
          <LoginTests />
          <section className="panel">
            <h3>Directory · OpenLDAP</h3>
            {err.dir && <p className="err">{err.dir}</p>}
            {!dir && !err.dir && <div className="skeleton block-skel" />}
            {dir && (
              <>
                <p className="muted small">Base DN <code>{dir.base_dn}</code> · {dir.entries} entries · read on the server with <code>slapcat</code>
                  (no network login; password hashes are never shown).</p>
                <table className="tbl">
                  <thead><tr><th>User</th><th>Name</th><th>Groups</th><th>Password</th><th>DN</th></tr></thead>
                  <tbody>{dir.users.map((u) => (
                    <tr key={u.dn}><td className="mono">{u.uid}</td><td>{u.cn}</td><td>{u.groups.join(", ") || "-"}</td>
                      <td>{u.has_password ? "set (hidden)" : "none"}</td><td className="mono small">{u.dn}</td></tr>))}</tbody>
                </table>
                <div className="group-cards">
                  {dir.groups.map((g) => (
                    <div key={g.dn} className="group-card"><strong>{g.cn}</strong><span className="muted small">gid {g.gid}</span>
                      <span className="small">{g.members.join(", ") || "no members"}</span></div>
                  ))}
                </div>
                <p className="muted small">Directory groups map to database roles: <code>dbadmins</code> ↔ <code>dba</code>,
                  <code> analysts</code> ↔ <code>analyst</code>. The password lives only in the directory; PostgreSQL asks the
                  directory at every login.</p>
                <Collapsible title="Evidence"><EvidenceList evidence={dir.evidence} /><TryIt evidence={dir.evidence} /></Collapsible>
              </>
            )}
          </section>

          <section className="panel">
            <h3>Database access · who can do what</h3>
            {err.db && <p className="err">{err.db}</p>}
            {!db && !err.db && <div className="skeleton block-skel" />}
            {db && <DbAccessView db={db} />}
          </section>
        </div>
        <aside className="side-col">
          <div className="panel note">
            <h3>How a database login works here</h3>
            <ol className="chain">
              <li><strong>TLS to PostgreSQL</strong><span>The client verifies the server certificate (<code>sslmode=verify-full</code>).</span></li>
              <li><strong>pg_hba.conf</strong><span>The first rule matching connection type, database, user and address decides the method.</span></li>
              <li><strong>LDAP bind</strong><span>For directory users PostgreSQL binds to OpenLDAP over StartTLS with the typed password.</span></li>
              <li><strong>Role privileges</strong><span>Once in, GRANTs on the user's roles decide what each query may touch.</span></li>
              <li><strong>Audit</strong><span>pgAudit records reads, writes, DDL and role changes; the activity monitor watches them.</span></li>
            </ol>
          </div>
          {db && (
            <div className="panel">
              <h3>Security settings</h3>
              <dl className="facts">{Object.entries(db.settings).map(([k, v]) => <div key={k} className="fact"><dt className="mono small">{k}</dt><dd className="mono">{v}</dd></div>)}</dl>
            </div>
          )}
        </aside>
      </div>
    </>
  );
}

function LoginTests() {
  const [kind, setKind] = useState<"ldap" | "db">("db");
  const [user, setUser] = useState("bob");
  const [mode, setMode] = useState("correct");
  const [busy, setBusy] = useState(false);
  const [res, setRes] = useState<LoginTest[]>([]);
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => { if (kind === "db" && mode === "no_tls") setMode("correct"); }, [kind, mode]);

  async function run() {
    setBusy(true); setErr(null);
    try { const r = await runLoginTest(kind, user, mode); setRes((x) => [r, ...x].slice(0, 6)); }
    catch (e) { setErr((e as Error).message); } finally { setBusy(false); }
  }
  const modes = kind === "ldap" ? [["correct", "Correct password"], ["wrong", "Wrong password"], ["no_tls", "Correct password, no StartTLS"]]
    : [["correct", "Correct password"], ["wrong", "Wrong password"]];
  return (
    <section className="panel">
      <h3>Login tests (real logins from Site A)</h3>
      <div className="form-row">
        <label>Test
          <select value={kind} onChange={(e) => setKind(e.target.value as "ldap" | "db")}>
            <option value="db">Database login (PostgreSQL → directory)</option>
            <option value="ldap">Directory bind only (OpenLDAP)</option>
          </select>
        </label>
        <label>User
          <select value={user} onChange={(e) => setUser(e.target.value)}>
            <option value="alice">alice (dbadmins)</option><option value="bob">bob (analysts)</option><option value="carol">carol (analysts)</option>
          </select>
        </label>
        <label>Password
          <select value={mode} onChange={(e) => setMode(e.target.value)}>{modes.map(([v, l]) => <option key={v} value={v}>{l}</option>)}</select>
        </label>
        <button className="btn" onClick={() => void run()} disabled={busy}>{busy ? "Logging in…" : "Run login"}</button>
      </div>
      {kind === "db" && mode === "wrong" && (
        <p className="warn-note small">This is a real failed login: it is logged as FATAL 28P01 and counted by the activity monitor.
          Five in a minute raise <strong>brute-force-login</strong> (try it, then check Audit &amp; alerts).</p>
      )}
      {err && <p className="err">{err}</p>}
      {res.map((r, i) => (
        <article key={r.ran_at + i} className={`result result-${r.status}`}>
          <header><span className={`dstat dstat-${r.status}`}>{r.status === "pass" ? "Pass" : "Fail"}</span>
            <span className="result-title">{r.kind === "db" ? "Database login" : "Directory bind"} · {r.user} · {r.mode.replace("_", " ")}</span>
            <span className="muted small">{clock(r.ran_at)}</span></header>
          <p className="result-sum">{r.summary}</p>
          <div className="result-body"><p>{r.meaning}</p>
            <Collapsible title="Evidence (password redacted)"><EvidenceList evidence={r.evidence} /><TryIt evidence={r.evidence} /></Collapsible>
          </div>
        </article>
      ))}
    </section>
  );
}

function DbAccessView({ db }: { db: DbAccess }) {
  const users = [...new Set(db.matrix.map((m) => m.user))].sort();
  const tables = [...new Set(db.matrix.map((m) => m.table).concat(db.tables.map((t) => t.table)))].sort();
  const cell = (u: string, t: string, p: string) => db.matrix.find((m) => m.user === u && m.table === t && m.privilege === p);
  return (
    <>
      {db.findings.length > 0 && (
        <div className="db-findings">{db.findings.map((f) => (
          <div key={f.label} className="hint"><strong>{f.label}:</strong> {f.value}</div>))}</div>
      )}
      <h4 className="sub">Effective table privileges (login roles)</h4>
      <div className="matrix-wrap">
        <table className="tbl matrix">
          <thead>
            <tr><th rowSpan={2}>User</th>{tables.map((t) => <th key={t} colSpan={PRIVS.length} className={SENSITIVE.has(t) ? "th-sensitive" : ""}>{t}{SENSITIVE.has(t) ? " (sensitive)" : ""}</th>)}</tr>
            <tr>{tables.flatMap((t) => PRIVS.map((p) => <th key={t + p} className="mono small">{p[0]}</th>))}</tr>
          </thead>
          <tbody>{users.map((u) => (
            <tr key={u}><td className="mono">{u}</td>{tables.flatMap((t) => PRIVS.map((p) => {
              const c = cell(u, t, p);
              return <td key={t + p} className={`mcell${c ? " yes" : ""}${c && SENSITIVE.has(t) && p === "SELECT" && u !== "svc_app" ? " risky" : ""}`}
                title={c ? `${u} can ${p} ${t} (${c.via})` : `${u} cannot ${p} ${t}`}>{c ? "✓" : ""}</td>;
            }))}</tr>))}</tbody>
        </table>
      </div>
      <p className="muted small">S/I/U/D = SELECT, INSERT, UPDATE, DELETE. Hover a tick to see which role grants it. Computed with
        <code> has_table_privilege()</code>, so inherited roles count.</p>

      <h4 className="sub">Roles</h4>
      <table className="tbl">
        <thead><tr><th>Role</th><th>Can log in</th><th>Member of</th></tr></thead>
        <tbody>{db.roles.map((r) => (
          <tr key={r.name}><td className="mono">{r.name}</td><td>{r.login ? "yes" : "no (group role)"}{r.superuser ? " · superuser" : ""}</td>
            <td className="mono">{r.member_of.join(", ") || "-"}</td></tr>))}</tbody>
      </table>

      <h4 className="sub">pg_hba.conf · who may connect, from where, how</h4>
      <table className="tbl">
        <thead><tr><th>Line</th><th>Type</th><th>Database</th><th>User</th><th>Address</th><th>Method</th></tr></thead>
        <tbody>{db.hba.map((h) => (
          <tr key={h.line} className={h.error ? "row-bad" : h.method === "reject" ? "row-warn" : ""}>
            <td className="mono">{h.line}</td><td className="mono">{h.type}</td><td className="mono">{h.database}</td><td className="mono">{h.user}</td>
            <td className="mono">{h.address}{h.netmask ? `/${h.netmask}` : ""}</td>
            <td className="mono" title={h.options}>{h.method}{h.error ? ` · ${h.error}` : ""}</td></tr>))}</tbody>
      </table>
      <p className="muted small">Checked top to bottom; the first matching line wins and no later line is tried. <code>hostssl</code> only
        matches TLS connections. The last line rejects everything else.</p>

      <h4 className="sub">Sessions right now</h4>
      {db.connections.length === 0 ? <p className="muted small">No client sessions besides this read.</p> : (
        <table className="tbl">
          <thead><tr><th>User</th><th>Database</th><th>From</th><th>Application</th><th>Since</th><th>TLS</th></tr></thead>
          <tbody>{db.connections.map((c) => (
            <tr key={c.pid} className={c.client !== "local" && !c.ssl ? "row-bad" : ""}><td className="mono">{c.user}</td><td className="mono">{c.database}</td>
              <td className="mono">{c.client}</td><td>{c.application || "-"}</td><td className="mono small">{clock(c.since)}</td>
              <td>{c.ssl ? c.tls_version : c.client === "local" ? "local socket" : "NO"}</td></tr>))}</tbody>
        </table>
      )}

      <h4 className="sub">Table activity</h4>
      <table className="tbl">
        <thead><tr><th>Table</th><th>Rows</th><th>Full scans</th><th>Index scans</th><th>Inserted</th></tr></thead>
        <tbody>{db.tables.map((t) => (
          <tr key={t.table}><td className="mono">{t.table}</td><td className="mono">{t.rows}</td><td className="mono">{t.seq_scans}</td>
            <td className="mono">{t.index_scans}</td><td className="mono">{t.inserted}</td></tr>))}</tbody>
      </table>
      <p className="muted small">A climbing full-scan count on a sensitive table means whole-table reads: compare with the audit trail.</p>
      <Collapsible title={`Evidence (${db.evidence.length} catalog queries, run as postgres, not audited)`}>
        <EvidenceList evidence={db.evidence} />
      </Collapsible>
    </>
  );
}
