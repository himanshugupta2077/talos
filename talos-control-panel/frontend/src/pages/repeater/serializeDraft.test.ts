import { describe, expect, it } from "vitest";
import {
  base64ToBytes,
  bytesToBase64,
  emptyDraft,
  serializeDraft,
  serializeLikePython,
  setOrRemoveCookieHeader,
  type RequestDraft,
  utf8Decode,
  utf8Encode,
} from "./serializeDraft";

function draft(partial: Partial<RequestDraft> = {}): RequestDraft {
  return { ...emptyDraft(), ...partial };
}

describe("serializeLikePython / serializeDraft", () => {
  it("serializes GET with no body (golden shape)", () => {
    const bytes = serializeLikePython(
      "GET",
      "https://api.example.com/v1/me",
      { Host: "api.example.com", Accept: "application/json" },
      null
    );
    const text = utf8Decode(bytes);
    expect(text.startsWith("GET /v1/me HTTP/1.1\r\n")).toBe(true);
    expect(text).toContain("Host: api.example.com\r\n");
    expect(text).toContain("Accept: application/json\r\n");
    expect(text.endsWith("\r\n\r\n")).toBe(true);
  });

  it("serializes JSON body", () => {
    const body = utf8Encode('{"a":1}');
    const bytes = serializeLikePython(
      "POST",
      "https://api.example.com/v1/item",
      {
        Host: "api.example.com",
        "Content-Type": "application/json",
      },
      body
    );
    const text = utf8Decode(bytes);
    expect(text.startsWith("POST /v1/item HTTP/1.1\r\n")).toBe(true);
    expect(text.endsWith('{"a":1}')).toBe(true);
  });

  it("injects Host when missing", () => {
    const bytes = serializeLikePython(
      "GET",
      "https://host.example/x",
      { Accept: "*/*" },
      null
    );
    expect(utf8Decode(bytes)).toContain("Host: host.example\r\n");
  });

  it("pretty mode: cookies table owns Cookie header", () => {
    const d = draft({
      method: "GET",
      url: "https://api.example.com/v1/me",
      host: "api.example.com",
      path: "/v1/me",
      request_headers: {
        Host: "api.example.com",
        Cookie: "stale=old",
      },
      request_cookies: { sid: "abc", role: "admin" },
    });
    const text = utf8Decode(serializeDraft(d, "pretty"));
    expect(text).toContain("Cookie: sid=abc; role=admin");
    expect(text).not.toContain("stale=old");
  });

  it("pretty mode: empty cookies removes Cookie header", () => {
    const d = draft({
      method: "GET",
      url: "https://api.example.com/",
      host: "api.example.com",
      path: "/",
      request_headers: {
        Host: "api.example.com",
        Cookie: "gone=1",
      },
      request_cookies: {},
    });
    const text = utf8Decode(serializeDraft(d, "pretty"));
    expect(text.toLowerCase()).not.toContain("cookie:");
  });

  it("raw mode uses raw_text only (ignores structured)", () => {
    const d = draft({
      method: "POST",
      url: "https://evil.example/",
      request_headers: { Host: "evil.example" },
      raw_text: "GET /ok HTTP/1.1\r\nHost: good.example\r\n\r\n",
      raw_encoding: "utf8",
    });
    const text = utf8Decode(serializeDraft(d, "raw"));
    expect(text).toBe("GET /ok HTTP/1.1\r\nHost: good.example\r\n\r\n");
  });

  it("setOrRemoveCookieHeader helpers", () => {
    const withC = setOrRemoveCookieHeader({ Host: "h" }, { a: "1" });
    expect(withC.Cookie).toBe("a=1");
    const without = setOrRemoveCookieHeader({ Host: "h", Cookie: "x=y" }, {});
    expect(without.Cookie).toBeUndefined();
  });

  it("base64 round-trip", () => {
    const src = utf8Encode("hello\0world");
    const b64 = bytesToBase64(src);
    expect(Array.from(base64ToBytes(b64))).toEqual(Array.from(src));
  });
});
