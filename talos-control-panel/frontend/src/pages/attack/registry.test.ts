import { describe, expect, it } from "vitest";
import { availableModulesForClass } from "./registry";

describe("availableModulesForClass", () => {
  it("lists every available active attack module in hub order", () => {
    expect(availableModulesForClass("active").map((m) => m.name)).toEqual([
      "Unauthenticated Execution",
      "BAC",
      "Auth-Session Testing",
      "Input Validation",
      "CORS Misconfiguration",
      "SQL Injection",
      "Intruder",
    ]);
  });

  it("omits coming-soon and passive modules", () => {
    const active = availableModulesForClass("active");
    expect(active.every((m) => m.class === "active" && m.status === "available")).toBe(
      true,
    );
    expect(active.some((m) => m.id === "secrets")).toBe(false);
  });
});
