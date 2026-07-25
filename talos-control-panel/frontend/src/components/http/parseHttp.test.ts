import { describe, it, expect } from "vitest";
import {
  buildRawMessage,
  decodeJwt,
  findJwt,
  looksLikeJwt,
  normalizeHeaders,
  parseBodyParams,
  parseCookieHeader,
  parseQueryParams,
  resolveRequestCookies,
  resolveResponseCookies,
} from "./parseHttp";
import { buildCurl } from "./buildCurl";

const SAMPLE_JWT =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
  "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4iLCJleHAiOjE3MDAwMDAwMDB9." +
  "signature";

describe("looksLikeJwt / decodeJwt", () => {
  it("detects and decodes Bearer JWT once", () => {
    const auth = `Bearer ${SAMPLE_JWT}`;
    expect(looksLikeJwt(auth)).toBe(true);
    const d = decodeJwt(auth);
    expect(d?.payload?.sub).toBe("1234567890");
    expect(d?.claimsSummary?.sub).toBe("1234567890");
  });

  it("rejects non-jwt", () => {
    expect(looksLikeJwt("Basic abc")).toBe(false);
    expect(looksLikeJwt("a.b")).toBe(false);
  });
});

describe("resolveRequestCookies — dual storage", () => {
  it("prefers request_cookies map over Cookie header (no double list)", () => {
    const cookies = resolveRequestCookies(
      { session: "abc", csrf: "tok" },
      { Cookie: "session=abc; csrf=tok; extra=from-header" }
    );
    expect(cookies).toHaveLength(2);
    expect(cookies.map((c) => c.name).sort()).toEqual(["csrf", "session"]);
    expect(cookies.every((c) => c.source === "cookies_map")).toBe(true);
  });

  it("falls back to Cookie header when map empty", () => {
    const cookies = resolveRequestCookies({}, { Cookie: "a=1; b=2" });
    expect(cookies).toHaveLength(2);
    expect(cookies[0]).toMatchObject({ name: "a", value: "1", source: "cookie_header" });
  });

  it("returns empty when neither present", () => {
    expect(resolveRequestCookies({}, {})).toEqual([]);
  });
});

describe("normalizeHeaders", () => {
  it("case-normalizes duplicate cookie keys to one group", () => {
    const headers = normalizeHeaders(
      { Cookie: "a=1", cookie: "b=2", Host: "x" },
      [{ name: "a", value: "1", source: "cookies_map" }]
    );
    const cookieRows = headers.filter((h) => h.isCookie);
    expect(cookieRows).toHaveLength(1);
    // last write wins for value under same key
    expect(headers.find((h) => h.key === "host")?.value).toBe("x");
  });

  it("keeps Authorization opaque with JWT flag, no expand", () => {
    const headers = normalizeHeaders({
      Authorization: `Bearer ${SAMPLE_JWT}`,
    });
    expect(headers[0].looksLikeJwt).toBe(true);
    expect(headers[0].value).toContain("Bearer");
  });
});

describe("buildRawMessage — no double Cookie", () => {
  it("does not synthesize Cookie when header present", () => {
    const raw = buildRawMessage({
      startLine: "GET / HTTP/1.1",
      headers: { Host: "x", Cookie: "a=1" },
      cookies: { a: "1", b: "2" },
      body: "",
    });
    const cookieLines = raw.split("\n").filter((l) => /^cookie:/i.test(l));
    expect(cookieLines).toHaveLength(1);
    expect(cookieLines[0]).toBe("Cookie: a=1");
  });

  it("synthesizes Cookie once when only map exists", () => {
    const raw = buildRawMessage({
      startLine: "GET / HTTP/1.1",
      headers: { Host: "x" },
      cookies: { a: "1", b: "2" },
      body: "hi",
    });
    const cookieLines = raw.split("\n").filter((l) => /^cookie:/i.test(l));
    expect(cookieLines).toHaveLength(1);
    expect(cookieLines[0]).toContain("a=1");
    expect(cookieLines[0]).toContain("b=2");
  });
});

describe("findJwt", () => {
  it("finds first Authorization JWT only", () => {
    const j = findJwt({
      Authorization: `Bearer ${SAMPLE_JWT}`,
      "X-Other": "nope",
    });
    expect(j?.payload?.sub).toBe("1234567890");
  });
});

describe("parseQueryParams / parseBodyParams", () => {
  it("parses query", () => {
    expect(parseQueryParams("id=1&page=2")).toEqual([
      { name: "id", value: "1" },
      { name: "page", value: "2" },
    ]);
  });

  it("parses urlencoded body", () => {
    const p = parseBodyParams("user=a&pass=b", "application/x-www-form-urlencoded");
    expect(p).toHaveLength(2);
  });

  it("skips binary body", () => {
    expect(parseBodyParams("AAAA", "application/octet-stream", "base64")).toEqual([]);
  });
});

describe("parseCookieHeader", () => {
  it("splits pairs", () => {
    expect(parseCookieHeader("a=1; b=two=2")).toEqual([
      { name: "a", value: "1", source: "cookie_header" },
      { name: "b", value: "two=2", source: "cookie_header" },
    ]);
  });
});

describe("resolveResponseCookies", () => {
  it("parses Set-Cookie", () => {
    const c = resolveResponseCookies({
      "Set-Cookie": "sid=xyz; Path=/; HttpOnly",
    });
    expect(c[0].name).toBe("sid");
    expect(c[0].attributes?.httponly).toBe(true);
  });
});

describe("buildCurl", () => {
  it("builds method + headers + body", () => {
    const c = buildCurl({
      method: "POST",
      url: "https://ex.com/api",
      headers: { "Content-Type": "application/json" },
      body: '{"a":1}',
    });
    expect(c).toContain("-X POST");
    expect(c).toContain("https://ex.com/api");
    expect(c).toContain("Content-Type");
    expect(c).toContain("--data-binary");
  });

  it("adds Cookie from map when header missing", () => {
    const c = buildCurl({
      method: "GET",
      url: "https://ex.com/",
      cookies: { s: "1" },
    });
    expect(c).toContain("Cookie: s=1");
  });
});
