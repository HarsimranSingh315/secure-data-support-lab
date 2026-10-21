import { useEffect, useRef } from "react";
import { clock } from "../status";
import { StatusDot, StatusPill } from "./StatusDot";
import { EvidenceList, FactsTable, TryIt } from "./Evidence";
import type { Status, Evidence, Fact } from "../api";

export interface DrawerContent {
  title: string;
  status: Status;
  time: string;
  summary: string;
  meaning?: string;
  facts?: Fact[];
  evidence: Evidence[];
  extra?: React.ReactNode;
}

export function Drawer({ content, onClose }: { content: DrawerContent; onClose: () => void }) {
  const closeRef = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    closeRef.current?.focus();
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  return (
    <div className="drawer-backdrop" onClick={onClose}>
      <aside className="drawer" role="dialog" aria-modal="true" aria-labelledby="drawer-title"
        onClick={(e) => e.stopPropagation()}>
        <div className="drawer-head">
          <StatusDot status={content.status} size="lg" />
          <div className="drawer-titles">
            <h2 id="drawer-title">{content.title}</h2>
            <div className="muted small"><StatusPill status={content.status} /> live · {clock(content.time)}</div>
          </div>
          <button ref={closeRef} className="btn btn-ghost" onClick={onClose} aria-label="Close">Close</button>
        </div>
        <p className="drawer-summary">{content.summary}</p>
        {content.meaning && (
          <section className="drawer-sec"><h3>What this means</h3><p>{content.meaning}</p></section>
        )}
        {content.extra}
        {content.facts && content.facts.length > 0 && (
          <section className="drawer-sec"><h3>Facts from the output</h3><FactsTable facts={content.facts} /></section>
        )}
        <section className="drawer-sec">
          <h3>Evidence</h3>
          <EvidenceList evidence={content.evidence} emptyText="The check failed before running a command." />
        </section>
        {content.evidence.length > 0 && (
          <section className="drawer-sec"><h3>Try it yourself</h3><TryIt evidence={content.evidence} /></section>
        )}
      </aside>
    </div>
  );
}
