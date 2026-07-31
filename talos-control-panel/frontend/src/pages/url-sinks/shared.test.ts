import { describe, expect, it } from "vitest";
import {
  DEFAULT_LIMIT,
  DEFAULT_MIN_SCORE,
  DEFAULT_NRS_ONLY,
  DEFAULT_SORT,
  URL_SINKS_BASE,
  applyFiltersToSearchParams,
  defaultInventoryFilters,
  filtersFromSearchParams,
  inventoryApiParams,
  inventoryHref,
  isUrlSinkTab,
  parseBoolParam,
  parseIntParam,
  parseSortParam,
  sortedCounts,
} from "./shared";

describe("url-sinks K13 query helpers", () => {
  it("isUrlSinkTab accepts PR4 tabs only", () => {
    expect(isUrlSinkTab("overview")).toBe(true);
    expect(isUrlSinkTab("inventory")).toBe(true);
    expect(isUrlSinkTab("rollups")).toBe(false);
    expect(isUrlSinkTab("settings")).toBe(false);
    expect(isUrlSinkTab(null)).toBe(false);
  });

  it("parseBoolParam handles true/false/1/0", () => {
    expect(parseBoolParam("true", false)).toBe(true);
    expect(parseBoolParam("1", false)).toBe(true);
    expect(parseBoolParam("false", true)).toBe(false);
    expect(parseBoolParam("0", true)).toBe(false);
    expect(parseBoolParam(null, DEFAULT_NRS_ONLY)).toBe(DEFAULT_NRS_ONLY);
    expect(parseBoolParam("", true)).toBe(true);
  });

  it("parseIntParam clamps min_score range", () => {
    expect(parseIntParam("45", 0, 0, 100)).toBe(45);
    expect(parseIntParam("200", 45, 0, 100)).toBe(100);
    expect(parseIntParam("-5", 45, 0, 100)).toBe(0);
    expect(parseIntParam("nope", DEFAULT_MIN_SCORE)).toBe(DEFAULT_MIN_SCORE);
  });

  it("parseSortParam only allows canon values", () => {
    expect(parseSortParam("score_desc")).toBe("score_desc");
    expect(parseSortParam("name")).toBe("name");
    expect(parseSortParam("bogus")).toBe(DEFAULT_SORT);
    expect(parseSortParam(null)).toBe(DEFAULT_SORT);
  });

  it("filtersFromSearchParams reads K13 keys (not aliases)", () => {
    const p = new URLSearchParams(
      "min_score=60&nrs_only=false&category=webhook&looks_like=url&location=query&host=api.ex&endpoint_id=e1&search=callback&sort=name&limit=50&offset=10&include_iv=true",
    );
    const f = filtersFromSearchParams(p);
    expect(f.min_score).toBe(60);
    expect(f.nrs_only).toBe(false);
    expect(f.category).toBe("webhook");
    expect(f.looks_like).toBe("url");
    expect(f.location).toBe("query");
    expect(f.host).toBe("api.ex");
    expect(f.endpoint_id).toBe("e1");
    expect(f.search).toBe("callback");
    expect(f.sort).toBe("name");
    expect(f.limit).toBe(50);
    expect(f.offset).toBe(10);
    expect(f.include_iv).toBe(true);
  });

  it("filtersFromSearchParams applies defaults when empty", () => {
    const f = filtersFromSearchParams(new URLSearchParams());
    expect(f.min_score).toBe(DEFAULT_MIN_SCORE);
    expect(f.nrs_only).toBe(DEFAULT_NRS_ONLY);
    expect(f.sort).toBe(DEFAULT_SORT);
    expect(f.limit).toBe(DEFAULT_LIMIT);
    expect(f.offset).toBe(0);
    expect(f.include_iv).toBe(false);
  });

  it("does not treat forbidden aliases nrs/q as filters", () => {
    const p = new URLSearchParams("nrs=1&q=callback&min_score=45&nrs_only=true");
    const f = filtersFromSearchParams(p);
    expect(f.search).toBe("");
    expect(f.nrs_only).toBe(true);
    expect(f.min_score).toBe(45);
  });

  it("applyFiltersToSearchParams round-trips core keys", () => {
    const filters = defaultInventoryFilters({
      min_score: 70,
      nrs_only: false,
      category: "redirect",
      host: "api",
      search: "url",
      sort: "host",
      limit: 100,
      offset: 20,
    });
    const params = applyFiltersToSearchParams(new URLSearchParams(), filters, {
      tab: "inventory",
    });
    expect(params.get("tab")).toBe("inventory");
    expect(params.get("min_score")).toBe("70");
    expect(params.get("nrs_only")).toBe("false");
    expect(params.get("category")).toBe("redirect");
    expect(params.get("host")).toBe("api");
    expect(params.get("search")).toBe("url");
    expect(params.get("sort")).toBe("host");
    expect(params.get("limit")).toBe("100");
    expect(params.get("offset")).toBe("20");

    const back = filtersFromSearchParams(params);
    expect(back.min_score).toBe(70);
    expect(back.nrs_only).toBe(false);
    expect(back.category).toBe("redirect");
    expect(back.host).toBe("api");
    expect(back.search).toBe("url");
    expect(back.sort).toBe("host");
    expect(back.limit).toBe(100);
    expect(back.offset).toBe(20);
  });

  it("inventoryApiParams matches K13 API shape", () => {
    const f = defaultInventoryFilters({
      category: "webhook",
      host: "example",
      nrs_only: true,
    });
    const q = inventoryApiParams("proj-1", f);
    expect(q.project_id).toBe("proj-1");
    expect(q.min_score).toBe(DEFAULT_MIN_SCORE);
    expect(q.nrs_only).toBe(true);
    expect(q.category).toBe("webhook");
    expect(q.host).toBe("example");
    expect(q).not.toHaveProperty("nrs");
    expect(q).not.toHaveProperty("q");
  });

  it("inventoryHref builds inventory deep-link", () => {
    const href = inventoryHref({ nrs_only: false, min_score: 0 });
    expect(href.startsWith(`${URL_SINKS_BASE}?`)).toBe(true);
    expect(href).toContain("tab=inventory");
    expect(href).toContain("min_score=0");
    expect(href).toContain("nrs_only=false");
  });

  it("sortedCounts orders by count desc", () => {
    expect(sortedCounts({ a: 1, b: 5, c: 3 })).toEqual([
      ["b", 5],
      ["c", 3],
      ["a", 1],
    ]);
    expect(sortedCounts(null)).toEqual([]);
  });
});
