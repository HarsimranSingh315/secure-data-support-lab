import type { Status } from "../api";
import { STATUS_LABEL } from "../status";

export function StatusDot({ status, size = "sm" }: { status: Status; size?: "sm" | "lg" }) {
  return (
    <span className={`dot dot-${status} dot-${size}`} role="img" aria-label={STATUS_LABEL[status]}>
      <span className="dot-glyph" aria-hidden="true">
        {{ ok: "✓", degraded: "!", down: "×", unknown: "?" }[status]}
      </span>
    </span>
  );
}

export function StatusPill({ status }: { status: Status }) {
  return <span className={`pill pill-${status}`}>{STATUS_LABEL[status]}</span>;
}
