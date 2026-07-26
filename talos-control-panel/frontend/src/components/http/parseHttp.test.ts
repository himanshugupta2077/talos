import { describe, it, expect } from "vitest";
import {
  buildPrettyMessage,
  buildRawMessage,
  decodeJwt,
  findEncodedArtifacts,
  findJwt,
  looksLikeBase64,
  looksLikeJwe,
  looksLikeJwt,
  normalizeHeaders,
  parseBodyParams,
  parseCookieHeader,
  parseQueryParams,
  prettyBody,
  prettyPrintCss,
  prettyPrintMarkup,
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

const SAMPLE_JWT_2 =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
  "eyJzdWIiOiJvdGhlciIsImV4cCI6MTgwMDAwMDAwMH0." +
  "sig2";

describe("findEncodedArtifacts", () => {
  it("returns separate foldable entries for two JWTs", () => {
    const arts = findEncodedArtifacts({
      side: "request",
      headers: {
        Authorization: `Bearer ${SAMPLE_JWT}`,
        "X-Id-Token": SAMPLE_JWT_2,
      },
    });
    const jwts = arts.filter((a) => a.kind === "jwt");
    expect(jwts).toHaveLength(2);
    expect(jwts.map((a) => a.location).sort()).toEqual([
      "header:Authorization",
      "header:X-Id-Token",
    ]);
    expect(jwts.find((a) => a.location === "header:Authorization")?.jwt?.payload?.sub).toBe(
      "1234567890"
    );
    expect(jwts.find((a) => a.location === "header:X-Id-Token")?.jwt?.payload?.sub).toBe(
      "other"
    );
  });

  it("finds JWT in cookie and Basic auth in header", () => {
    const arts = findEncodedArtifacts({
      side: "request",
      headers: {
        Authorization: "Basic dXNlcjpwYXNz",
      },
      cookies: { session: SAMPLE_JWT },
    });
    expect(arts.some((a) => a.kind === "basic_auth" && a.basicAuth?.username === "user")).toBe(
      true
    );
    expect(arts.some((a) => a.kind === "jwt" && a.location === "cookie:session")).toBe(true);
  });

  it("finds JWT in response Set-Cookie and body JSON", () => {
    const arts = findEncodedArtifacts({
      side: "response",
      headers: {
        "Set-Cookie": `access=${SAMPLE_JWT}; Path=/; HttpOnly`,
      },
      body: JSON.stringify({ refresh: SAMPLE_JWT_2 }),
      contentType: "application/json",
    });
    expect(arts.filter((a) => a.kind === "jwt")).toHaveLength(2);
    expect(arts.some((a) => a.location === "set-cookie:access")).toBe(true);
    expect(arts.some((a) => a.location === "body.refresh")).toBe(true);
  });

  it("decodes standalone base64", () => {
    // "hello world!!" base64
    const b64 = btoa("hello world!!");
    const arts = findEncodedArtifacts({
      side: "request",
      headers: { "X-Payload": b64 },
    });
    const a = arts.find((x) => x.kind === "base64");
    expect(a?.base64?.decoded).toContain("hello world");
  });

  it("detects JWE compact form", () => {
    // Fake JWE: header with enc + 4 more segments
    const hdr = btoa(JSON.stringify({ alg: "dir", enc: "A256GCM" }))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
    const jwe = `${hdr}.ek.iv.ct.tag`;
    expect(looksLikeJwe(jwe)).toBe(true);
    const arts = findEncodedArtifacts({
      side: "request",
      headers: { Authorization: `Bearer ${jwe}` },
    });
    expect(arts.some((a) => a.kind === "jwe")).toBe(true);
  });

  it("looksLikeBase64 rejects short junk and opaque tokens", () => {
    expect(looksLikeBase64("abcd")).toBe(false);
    expect(looksLikeBase64(SAMPLE_JWT)).toBe(false);
    // Random base64-alphabet token that does not decode to readable text
    expect(
      looksLikeBase64("2PaW3mD5oBa7Mp6PLlyrQKw2zd52S77hJeGORx1Nkeb49VvJZq8gjnEXYZr3")
    ).toBe(false);
    // Real readable payload still accepted
    expect(looksLikeBase64(btoa("hello world!!"))).toBe(true);
    expect(looksLikeBase64(btoa('{"role":"admin"}'))).toBe(true);
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

describe("prettyBody — Burp formats", () => {
  it("pretty-prints JSON with 4-space indent", () => {
    const r = prettyBody('{"a":1,"b":[true]}', "application/json");
    expect(r.kind).toBe("json");
    expect(r.prettified).toBe(true);
    expect(r.text).toContain('\n    "a"');
    expect(r.text).toContain("true");
  });

  it("pretty-prints HTML tags onto indented lines", () => {
    const r = prettyBody("<div><span>x</span></div>", "text/html");
    expect(r.kind).toBe("html");
    expect(r.prettified).toBe(true);
    expect(r.text.split("\n").length).toBeGreaterThan(1);
    expect(r.text).toContain("<div>");
    expect(r.text).toContain("</span>");
  });

  it("pretty-prints XML", () => {
    const r = prettyBody("<root><item id=\"1\"/></root>", "application/xml");
    expect(r.kind).toBe("xml");
    expect(r.prettified).toBe(true);
    expect(r.text).toContain("<root>");
  });

  it("splits form-urlencoded onto one field per line", () => {
    const r = prettyBody("a=1&b=two", "application/x-www-form-urlencoded");
    expect(r.kind).toBe("form");
    expect(r.text).toBe("a=1\nb=two");
  });

  it("pretty-prints minified CSS", () => {
    const r = prettyBody("body{color:red;margin:0}", "text/css");
    expect(r.kind).toBe("css");
    expect(r.prettified).toBe(true);
    expect(r.text).toContain("{\n");
    expect(r.text).toContain("color:red;");
  });

  it("returns empty for empty body", () => {
    expect(prettyBody("", "application/json")).toMatchObject({
      kind: "empty",
      prettified: false,
    });
  });

  it("marks base64 as binary", () => {
    const r = prettyBody("AAAA", "application/octet-stream", "base64");
    expect(r.kind).toBe("binary");
  });
});

describe("prettyPrintMarkup / prettyPrintCss helpers", () => {
  it("indents nested markup", () => {
    const p = prettyPrintMarkup("<a><b/></a>", "xml");
    expect(p).toContain("    <b");
  });

  it("breaks CSS rules", () => {
    const p = prettyPrintCss(".x{a:1}");
    expect(p).toMatch(/\.x\s*\{/);
    expect(p).toContain("}");
  });
});

describe("buildPrettyMessage", () => {
  it("keeps start-line + headers + prettified body like Burp Pretty", () => {
    const m = buildPrettyMessage({
      startLine: "POST /api?x=1 HTTP/1.1",
      headers: {
        Host: "ex.com",
        "Content-Type": "application/json",
        "Accept-Encoding": "gzip",
      },
      body: '{"ok":true}',
      side: "request",
    });
    expect(m.startLine).toContain("POST");
    expect(m.body.kind).toBe("json");
    expect(m.body.prettified).toBe(true);
    const ae = m.headers.find((h) => h.name === "Accept-Encoding");
    expect(ae?.hiddenByDefault).toBe(true);
    expect(m.headers.find((h) => h.name === "Host")?.hiddenByDefault).toBe(false);
  });

  it("synthesizes Cookie once when map only", () => {
    const m = buildPrettyMessage({
      startLine: "GET / HTTP/1.1",
      headers: { Host: "x" },
      cookies: { s: "1" },
      side: "request",
    });
    expect(m.headers.filter((h) => h.name.toLowerCase() === "cookie")).toHaveLength(1);
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
