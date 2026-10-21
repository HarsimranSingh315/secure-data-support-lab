// A small Markdown renderer for the lab's runbooks. It builds React elements directly (never raw
// HTML), so file content cannot inject markup or scripts.
import type { ReactNode } from "react";

function inline(text: string, key: string): ReactNode[] {
  const out: ReactNode[] = [];
  const re = /(`[^`]+`|\*\*[^*]+\*\*)/g;
  let last = 0;
  let m: RegExpExecArray | null;
  let i = 0;
  while ((m = re.exec(text))) {
    if (m.index > last) out.push(text.slice(last, m.index));
    const tok = m[0];
    out.push(tok.startsWith("`") ? <code key={`${key}-${i++}`}>{tok.slice(1, -1)}</code> : <strong key={`${key}-${i++}`}>{tok.slice(2, -2)}</strong>);
    last = m.index + tok.length;
  }
  if (last < text.length) out.push(text.slice(last));
  return out;
}

type Item = { text: string; children: Item[] };

export function parseBlocks(md: string): ReactNode[] {
  const lines = md.replace(/\r/g, "").split("\n");
  const out: ReactNode[] = [];
  let i = 0;
  let k = 0;
  while (i < lines.length) {
    const line = lines[i];
    if (!line.trim()) { i++; continue; }
    if (line.startsWith("```")) {
      const body: string[] = [];
      i++;
      while (i < lines.length && !lines[i].startsWith("```")) body.push(lines[i++]);
      i++;
      out.push(<pre key={k++} className="md-code">{body.join("\n")}</pre>);
      continue;
    }
    const h = /^(#{1,4})\s+(.*)$/.exec(line);
    if (h) {
      const level = Math.min(h[1].length + 1, 5);
      const Tag = `h${level}` as "h2" | "h3" | "h4" | "h5";
      out.push(<Tag key={k++}>{inline(h[2], `h${k}`)}</Tag>);
      i++;
      continue;
    }
    if (line.startsWith("|")) {
      const rows: string[][] = [];
      while (i < lines.length && lines[i].startsWith("|")) {
        const cells = lines[i].split("|").slice(1, -1).map((c) => c.trim());
        if (!cells.every((c) => /^:?-+:?$/.test(c))) rows.push(cells);
        i++;
      }
      const [head, ...body] = rows;
      out.push(
        <table key={k++} className="tbl md-table">
          <thead><tr>{head.map((c, j) => <th key={j}>{inline(c, `th${j}`)}</th>)}</tr></thead>
          <tbody>{body.map((r, a) => <tr key={a}>{r.map((c, j) => <td key={j}>{inline(c, `td${a}${j}`)}</td>)}</tr>)}</tbody>
        </table>,
      );
      continue;
    }
    const li = /^(\s*)(\d+\.|[-*])\s+(.*)$/;
    if (li.test(line)) {
      const ordered = /^\s*\d+\./.test(line);
      const items: Item[] = [];
      while (i < lines.length && (li.test(lines[i]) || /^\s{2,}\S/.test(lines[i]))) {
        const m = li.exec(lines[i]);
        if (m && m[1].length < 2) items.push({ text: m[3], children: [] });
        else if (m && items.length) items[items.length - 1].children.push({ text: m[3], children: [] });
        else if (items.length) {
          const last = items[items.length - 1];
          const target = last.children.length ? last.children[last.children.length - 1] : last;
          target.text += " " + lines[i].trim();
        }
        i++;
      }
      const List = ordered ? "ol" : "ul";
      out.push(
        <List key={k++} className="md-list">
          {items.map((it, a) => (
            <li key={a}>{inline(it.text, `li${k}${a}`)}
              {it.children.length > 0 && <ul>{it.children.map((c, b) => <li key={b}>{inline(c.text, `lc${k}${a}${b}`)}</li>)}</ul>}
            </li>
          ))}
        </List>,
      );
      continue;
    }
    const para: string[] = [];
    while (i < lines.length && lines[i].trim() && !/^(#|```|\||\s*(\d+\.|[-*])\s)/.test(lines[i])) para.push(lines[i++].trim());
    out.push(<p key={k++}>{inline(para.join(" "), `p${k}`)}</p>);
  }
  return out;
}

export function Markdown({ text }: { text: string }) {
  return <div className="md">{parseBlocks(text)}</div>;
}
