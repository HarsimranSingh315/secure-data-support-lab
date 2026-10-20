import { describe, expect, it } from "vitest";
import type { Check, Status } from "./api";
import { ago, exitLabel, groupChecks, headline, statusFor, worst } from "./status";

const mk = (id: string, status: Status, group = "Network"): Check => ({
  id, status, group, title: id, target: id, summary: "", meaning: "", facts: [], evidence: [],
  checked_at: "2026-10-20T13:00:00+00:00", source: "live",
});

describe("status helpers", () => {
  it("worst status wins, and nothing known is unknown", () => {
    expect(worst(["ok", "degraded", "ok"])).toBe("degraded");
    expect(worst(["ok", "unknown"])).toBe("unknown");
    expect(worst(["unknown", "down"])).toBe("down");
    expect(worst([])).toBe("unknown");
  });

  it("a node takes the worst of its checks (r3 = routing + firewall)", () => {
    const checks = [mk("r3", "ok"), mk("firewall", "degraded"), mk("db", "down", "Data")];
    expect(statusFor(checks, ["r3", "firewall"])).toBe("degraded");
    expect(statusFor(checks, ["nope"])).toBe("unknown");
  });

  it("headline never says healthy when something is wrong", () => {
    expect(headline("ok", { ok: 9, degraded: 0, down: 0, unknown: 0 })).toBe("All lab services healthy");
    expect(headline("down", { ok: 7, degraded: 1, down: 1, unknown: 0 })).toBe("Attention: 1 down, 1 degraded");
    expect(headline("degraded", { ok: 6, degraded: 0, down: 0, unknown: 3 })).toBe("Attention: 3 not checkable");
  });

  it("groups in a fixed order", () => {
    const g = groupChecks([mk("dam", "ok", "Monitoring"), mk("db", "ok", "Data"), mk("r1", "ok")]);
    expect(g.map(([name]) => name)).toEqual(["Network", "Data", "Monitoring"]);
  });

  it("labels exit codes and errors", () => {
    expect(exitLabel(0, null)).toBe("exit 0");
    expect(exitLabel(137, "timeout")).toBe("timed out");
    expect(exitLabel(null, "container_not_running")).toBe("container stopped");
  });

  it("relative times", () => {
    const now = new Date("2026-10-20T13:02:00+00:00").getTime();
    expect(ago("2026-10-20T13:01:58+00:00", now)).toBe("just now");
    expect(ago("2026-10-20T13:01:30+00:00", now)).toBe("30s ago");
    expect(ago("2026-10-20T12:59:00+00:00", now)).toBe("3m ago");
  });
});
