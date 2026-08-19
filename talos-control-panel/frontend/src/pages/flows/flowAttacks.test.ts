import { describe, it, expect } from "vitest";
import {
  FLOW_ATTACKS,
  availableFlowAttacks,
  defaultSelectedAttackIds,
  estimateFlowAttackJobs,
  getFlowAttack,
} from "./flowAttacks";

describe("flowAttacks catalog", () => {
  it("lists active modules; CORS/unauth/bac/auth-session/iv are runnable", () => {
    const ids = FLOW_ATTACKS.map((a) => a.id);
    expect(ids).toEqual([
      "cors",
      "sqli",
      "path-traversal",
      "ssrf",
      "open-redirect",
      "host-header",
      "smuggle",
      "unauth",
      "bac",
      "auth-session",
      "iv",
      "intruder",
    ]);
    const live = availableFlowAttacks();
    expect(live.map((a) => a.id)).toEqual([
      "cors",
      "sqli",
      "path-traversal",
      "ssrf",
      "open-redirect",
      "host-header",
      "smuggle",
      "unauth",
      "bac",
      "auth-session",
      "iv",
    ]);
    for (const item of live) {
      expect(item.run).toBeTypeOf("function");
    }
    expect(defaultSelectedAttackIds()).toEqual(["cors"]);
    expect(getFlowAttack("intruder")?.status).toBe("coming_soon");
  });

  it("estimates jobs only for selected available attacks", () => {
    expect(estimateFlowAttackJobs(3, ["cors"])).toBe(60);
    expect(estimateFlowAttackJobs(2, ["sqli"])).toBe(100);
    expect(estimateFlowAttackJobs(1, ["path-traversal"])).toBe(53);
    expect(estimateFlowAttackJobs(1, ["ssrf"])).toBe(64);
    expect(estimateFlowAttackJobs(1, ["open-redirect"])).toBe(32);
    expect(estimateFlowAttackJobs(1, ["host-header"])).toBe(42);
    expect(getFlowAttack("sqli")?.cliHint).toContain("--flow");
    expect(getFlowAttack("sqli")?.cliHint).toContain("--high-priority");
    expect(getFlowAttack("path-traversal")?.cliHint).toContain("--flow");
    expect(estimateFlowAttackJobs(2, ["unauth"])).toBe(34);
    expect(estimateFlowAttackJobs(1, ["iv"])).toBe(9);
    expect(estimateFlowAttackJobs(2, ["auth-session"])).toBe(0);
    expect(estimateFlowAttackJobs(3, ["cors", "intruder"])).toBe(60);
    expect(getFlowAttack("unauth")?.cliHint).toContain("--flow");
    expect(getFlowAttack("bac")?.cliHint).toContain("--flow");
    expect(getFlowAttack("iv")?.cliHint).toContain("--flow");
  });
});
