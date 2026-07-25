import { describe, it, expect } from "vitest";
import { buildHealthChips, formatDurationMs } from "./flowFlags";

describe("buildHealthChips", () => {
  it("hides unknown chips rather than inventing green checks", () => {
    const chips = buildHealthChips({});
    expect(chips.find((c) => c.kind === "qualified")).toBeUndefined();
    expect(chips.find((c) => c.kind === "auth_present")).toBeUndefined();
  });

  it("surfaces truncation over body stored", () => {
    const chips = buildHealthChips({
      request_body: "x",
      request_body_truncated: true,
    });
    expect(chips.some((c) => c.kind === "body_truncated")).toBe(true);
    expect(chips.some((c) => c.kind === "body_stored")).toBe(false);
  });

  it("shows attack and diff from results", () => {
    const chips = buildHealthChips({
      method: "GET",
      host: "x",
      results: { diff: { verdict: "same" }, bac: { verdict: "likely" } },
      derived: { has_auth_material: true },
    });
    expect(chips.map((c) => c.kind)).toEqual(
      expect.arrayContaining(["diff_available", "attack_result", "auth_present", "replay_available"])
    );
  });

  it("shows qualified only from endpoint policy", () => {
    const chips = buildHealthChips({
      endpoint_policy: { qualified: 1, baseline_flow_id: "abc" },
    });
    expect(chips.some((c) => c.kind === "qualified")).toBe(true);
    expect(chips.some((c) => c.kind === "baseline")).toBe(true);
  });
});

describe("formatDurationMs", () => {
  it("formats ms and seconds", () => {
    expect(formatDurationMs(42)).toBe("42 ms");
    expect(formatDurationMs(1500)).toBe("1.50 s");
    expect(formatDurationMs(null)).toBeNull();
  });
});
