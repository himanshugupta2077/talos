import { describe, expect, it } from "vitest";
import { runnableCandidateAttack } from "./shared";

describe("runnableCandidateAttack", () => {
  it("maps dedicated engines operators can run from the candidates board", () => {
    expect(runnableCandidateAttack("xss")?.shortLabel).toBe("XSS");
    expect(runnableCandidateAttack("sqli")?.workspace).toBe("/testing/sqli");
    expect(runnableCandidateAttack("path-traversal")?.burpLabel).toBe("Path Traversal");
    expect(runnableCandidateAttack("path_traversal")?.id).toBe("path_traversal");
    expect(runnableCandidateAttack("ssrf")?.shortLabel).toBe("SSRF");
    expect(runnableCandidateAttack("open_redirect")?.shortLabel).toBe("Redirect");
  });

  it("leaves prioritization-only families without a Run action", () => {
    expect(runnableCandidateAttack("hpp")).toBeNull();
    expect(runnableCandidateAttack("webhook_abuse")).toBeNull();
    expect(runnableCandidateAttack("mass_assignment")).toBeNull();
    expect(runnableCandidateAttack("")).toBeNull();
  });
});
