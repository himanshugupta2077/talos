import { describe, expect, it } from "vitest";
import { buildCliPreview, parseUuidList } from "./shared";

describe("parseUuidList", () => {
  it("splits on commas, whitespace, and newlines and dedupes", () => {
    expect(parseUuidList("a, b\nc a")).toEqual(["a", "b", "c"]);
    expect(parseUuidList("  ")).toEqual([]);
  });
});

describe("buildCliPreview", () => {
  it("adds --exclude-endpoint for each skipped endpoint", () => {
    const lines = buildCliPreview({
      techniques: ["session-swap"],
      module: "payments",
      excludeEndpoints: ["ep-a", "ep-b"],
    });
    expect(lines).toEqual([
      "talos attack bac session-swap --module payments --exclude-endpoint ep-a --exclude-endpoint ep-b",
    ]);
  });
});
