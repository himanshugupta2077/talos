import { describe, expect, it } from "vitest";
import {
  findingNavFromSearch,
  findingNavSearch,
  preserveSearch,
} from "./nav";

describe("finding adjacent nav query", () => {
  it("omits default primary view and empty filters", () => {
    expect(
      findingNavSearch({
        view: "primary",
        status: "",
        attack_type: undefined,
      })
    ).toBe("");
  });

  it("keeps list filters that adjacent should honor", () => {
    expect(
      findingNavSearch({
        view: "all",
        status: "TRIAGING",
        attack_type: "passive_secret",
        verdict: "CONFIRMED_SECRET",
        role: "admin",
        module: "api",
      })
    ).toBe(
      "?view=all&status=TRIAGING&attack_type=passive_secret&verdict=CONFIRMED_SECRET&role=admin&module=api"
    );
  });

  it("round-trips search params", () => {
    const qs = findingNavSearch({ view: "linked", status: "CONFIRMED" });
    const parsed = findingNavFromSearch(new URLSearchParams(qs.slice(1)));
    expect(parsed).toEqual({ view: "linked", status: "CONFIRMED" });
    expect(preserveSearch(new URLSearchParams(parsed))).toBe(qs);
  });
});
