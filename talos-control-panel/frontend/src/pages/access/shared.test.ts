import { describe, expect, it } from "vitest";
import {
  bacReadyModuleIds,
  cellMatchesFilter,
  computeStats,
  coverageStatus,
  nextAccessValue,
  prevAccessValue,
  shortValue,
} from "./shared";
import type { AccessCell, AccessCoverageRow } from "../../types";

function cell(
  partial: Partial<AccessCell> & {
    role_id: string;
    role_name: string;
    module_id: string;
    module_name: string;
  }
): AccessCell {
  return {
    client_allowed: null,
    server_expected: null,
    flow_count: 0,
    endpoint_count: 0,
    ...partial,
  };
}

describe("access shared helpers", () => {
  it("shortValue maps tri-state", () => {
    expect(shortValue("ALLOW")).toBe("A");
    expect(shortValue("DENY")).toBe("D");
    expect(shortValue("UNKNOWN")).toBe("U");
    expect(shortValue(null)).toBe("·");
  });

  it("cycles access values forward and reverse", () => {
    expect(nextAccessValue(null)).toBe("ALLOW");
    expect(nextAccessValue("ALLOW")).toBe("DENY");
    expect(nextAccessValue("DENY")).toBe("UNKNOWN");
    expect(nextAccessValue("UNKNOWN")).toBe(null);
    expect(prevAccessValue(null)).toBe("UNKNOWN");
    expect(prevAccessValue("ALLOW")).toBe(null);
  });

  it("detects BAC-ready modules", () => {
    const cells = [
      cell({
        role_id: "1",
        role_name: "admin",
        module_id: "m1",
        module_name: "orders",
        client_allowed: "ALLOW",
        server_expected: "ALLOW",
      }),
      cell({
        role_id: "2",
        role_name: "user",
        module_id: "m1",
        module_name: "orders",
        client_allowed: "DENY",
        server_expected: "DENY",
      }),
      cell({
        role_id: "1",
        role_name: "admin",
        module_id: "m2",
        module_name: "public",
        client_allowed: "ALLOW",
        server_expected: "ALLOW",
      }),
      cell({
        role_id: "2",
        role_name: "user",
        module_id: "m2",
        module_name: "public",
        client_allowed: "ALLOW",
        server_expected: "ALLOW",
      }),
    ];
    const ready = bacReadyModuleIds(cells);
    expect(ready.has("m1")).toBe(true);
    expect(ready.has("m2")).toBe(false);
  });

  it("computeStats counts mismatch and unset", () => {
    const cells = [
      cell({
        role_id: "1",
        role_name: "a",
        module_id: "m",
        module_name: "x",
        client_allowed: "ALLOW",
        server_expected: "DENY",
      }),
      cell({
        role_id: "2",
        role_name: "b",
        module_id: "m",
        module_name: "x",
      }),
    ];
    const s = computeStats(cells);
    expect(s.mismatch).toBe(1);
    expect(s.fullyUnset).toBe(1);
    expect(s.clientSet).toBe(1);
  });

  it("cellMatchesFilter mismatch", () => {
    const c = cell({
      role_id: "1",
      role_name: "a",
      module_id: "m",
      module_name: "x",
      client_allowed: "ALLOW",
      server_expected: "DENY",
    });
    expect(cellMatchesFilter(c, "mismatch", new Set())).toBe(true);
    expect(cellMatchesFilter(c, "client_deny", new Set())).toBe(false);
  });

  it("coverageStatus classifies rows", () => {
    const base: AccessCoverageRow = {
      role_name: "user",
      module_name: "orders",
      client_allowed: "DENY",
      server_expected: "DENY",
      flow_count: 2,
      endpoint_count: 1,
    };
    expect(coverageStatus(base)).toBe("boundary");
    expect(
      coverageStatus({ ...base, server_expected: "ALLOW", client_allowed: "DENY" })
    ).toBe("unexpected");
    expect(
      coverageStatus({
        ...base,
        client_allowed: "ALLOW",
        server_expected: "ALLOW",
        flow_count: 0,
      })
    ).toBe("gap");
  });
});
