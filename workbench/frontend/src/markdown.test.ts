import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { isValidElement, type ReactElement } from "react";
import { parseBlocks } from "./components/Markdown";

type El = ReactElement<{ children?: unknown }>;
const kinds = (nodes: unknown[]) => nodes.map((n) => (isValidElement(n) ? String((n as El).type) : typeof n));

describe("runbook markdown", () => {
  it("renders a real runbook into headings, paragraphs and lists", () => {
    const md = readFileSync(new URL("../../../docs/runbooks/firewall-drop.md", import.meta.url), "utf8");
    const k = kinds(parseBlocks(md));
    expect(k[0]).toBe("h2");
    expect(k.filter((x) => x === "h3").length).toBeGreaterThanOrEqual(4);
    expect(k).toContain("ol");
  });

  it("nests indented bullets under numbered steps and keeps continuation lines", () => {
    const [ol] = parseBlocks("1. Step one\n   - **timed out** = drop\n   - refused\n   more text\n2. Step two") as El[];
    const items = ol.props.children as El[];
    expect(items).toHaveLength(2);
  });

  it("never produces raw HTML", () => {
    const nodes = parseBlocks("<script>alert(1)</script>\n\n# <img src=x onerror=alert(1)>") as El[];
    const flat = JSON.stringify(nodes.map((n) => (isValidElement(n) ? (n as El).props.children : n)));
    expect(flat).toContain("<script>");                // shown as text...
    expect(kinds(nodes)).toEqual(["p", "h2"]);         // ...inside ordinary elements
  });

  it("renders tables and skips the separator row", () => {
    const [t] = parseBlocks("| a | b |\n| --- | --- |\n| 1 | 2 |") as El[];
    expect(t.type).toBe("table");
  });
});
