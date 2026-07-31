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
  parseOptionalBoolParam,
  parseSortParam,
  sortedCounts,
} from "./shared";

describe("url-sinks K13 query helpers", () => {
  it("isUrlSinkTab accepts all workspace tabs", () => {
    expect(isUrlSinkTab("overview")).toBe(true);
    expect(isUrlSinkTab("inventory")).toBe(true);
    expect(isUrlSinkTab("rollups")).toBe(true);
    expect(isUrlSinkTab("settings")).toBe(true);
    expect(isUrlSinkTab(null)).toBe(false);
    expect(isUrlSinkTab("bogus")).toBe(false);
  });

  it("parseBoolParam handles true/false/1/0", () => {
    expect(parseBoolParam("true", false)).toBe(true);
    expect(parseBoolParam("1", false)).toBe(true);
    expect(parseBoolParam("false", true)).toBe(false);
    expect(parseBoolParam("0", true)).toBe(false);
    expect(parseBoolParam(null, DEFAULT_NRS_ONLY)).toBe(DEFAULT_NRS_ONLY);
    expect(parseBoolParam("", true)).toBe(true);
  });

  it("parseOptionalBoolParam is tri-state", () => {
    expect(parseOptionalBoolParam(null)).toBe(null);
    expect(parseOptionalBoolParam("")).toBe(null);
    expect(parseOptionalBoolParam("true")).toBe(true);
    expect(parseOptionalBoolParam("0")).toBe(false);
    expect(parseOptionalBoolParam("maybe")).toBe(null);
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
      "min_score=60&nrs_only=false&category=webhook&looks_like=url&location=query&host=api.ex&endpoint_id=e1&search=callback&sort=name&limit=50&offset=10&include_iv=true&has_iv_profile=true&has_url_sink_obs=false",
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
    expect(f.has_iv_profile).toBe(true);
    expect(f.has_url_sink_obs).toBe(false);
  });

  it("filtersFromSearchParams applies defaults when empty", () => {
    const f = filtersFromSearchParams(new URLSearchParams());
    expect(f.min_score).toBe(DEFAULT_MIN_SCORE);
    expect(f.nrs_only).toBe(DEFAULT_NRS_ONLY);
    expect(f.sort).toBe(DEFAULT_SORT);
    expect(f.limit).toBe(DEFAULT_LIMIT);
    expect(f.offset).toBe(0);
    expect(f.include_iv).toBe(false);
    expect(f.has_iv_profile).toBe(null);
    expect(f.has_url_sink_obs).toBe(null);
  });

  it("does not treat forbidden aliases nrs/q as filters", () => {
    const p = new URLSearchParams("nrs=1&q=callback&min_score=45&nrs_only=true");
    const f = filtersFromSearchParams(p);
    expect(f.search).toBe("");
    expect(f.nrs_only).toBe(true);
    expect(f.min_score).toBe(45);
  });

  it("applyFiltersToSearchParams round-trips core keys + has_iv_*", () => {
    const filters = defaultInventoryFilters({
      min_score: 70,
      nrs_only: false,
      category: "redirect",
      host: "api",
      search: "url",
      sort: "host",
      limit: 100,
      offset: 20,
      has_iv_profile: true,
      has_url_sink_obs: false,
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
    expect(params.get("has_iv_profile")).toBe("true");
    expect(params.get("has_url_sink_obs")).toBe("false");

    const back = filtersFromSearchParams(params);
    expect(back.min_score).toBe(70);
    expect(back.nrs_only).toBe(false);
    expect(back.category).toBe("redirect");
    expect(back.host).toBe("api");
    expect(back.search).toBe("url");
    expect(back.sort).toBe("host");
    expect(back.limit).toBe(100);
    expect(back.offset).toBe(20);
    expect(back.has_iv_profile).toBe(true);
    expect(back.has_url_sink_obs).toBe(false);
  });

  it("omits has_iv_* from URL when null (any)", () => {
    const filters = defaultInventoryFilters();
    const params = applyFiltersToSearchParams(new URLSearchParams(), filters, {
      tab: "inventory",
    });
    expect(params.has("has_iv_profile")).toBe(false);
    expect(params.has("has_url_sink_obs")).toBe(false);
  });

  it("inventoryApiParams matches K13 API shape including has_iv_*", () => {
    const f = defaultInventoryFilters({
      category: "webhook",
      host: "example",
      nrs_only: true,
      has_iv_profile: true,
    });
    const q = inventoryApiParams("proj-1", f);
    expect(q.project_id).toBe("proj-1");
    expect(q.min_score).toBe(DEFAULT_MIN_SCORE);
    expect(q.nrs_only).toBe(true);
    expect(q.category).toBe("webhook");
    expect(q.host).toBe("example");
    expect(q.has_iv_profile).toBe(true);
    expect(q).not.toHaveProperty("has_url_sink_obs");
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

  it("inventoryHref includes endpoint_id for flow/endpoint cross-links", () => {
    const href = inventoryHref({ endpoint_id: "ep-abc", nrs_only: true });
    expect(href).toContain("endpoint_id=ep-abc");
    expect(href).toContain("nrs_only=true");
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
