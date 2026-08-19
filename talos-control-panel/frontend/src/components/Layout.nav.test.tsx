import { describe, expect, it } from "vitest";
import { MemoryRouter } from "react-router-dom";
import { render, screen } from "@testing-library/react";
import { SidebarNav } from "./Layout";

const ACTIVE_MODULES = [
  { name: "Unauthenticated Execution", path: "/testing/unauth" },
  { name: "BAC", path: "/testing/bac" },
  { name: "Auth-Session Testing", path: "/testing/auth-session" },
  { name: "Input Validation", path: "/testing/input-validation" },
  { name: "CORS Misconfiguration", path: "/testing/cors" },
  { name: "SQL Injection", path: "/testing/sqli" },
  { name: "Path Traversal", path: "/testing/path-traversal" },
  { name: "SSRF", path: "/testing/ssrf" },
  { name: "Open Redirect", path: "/testing/open-redirect" },
  { name: "Intruder", path: "/testing/intruder" },
] as const;

function renderNav(path: string, visuallyExpanded = true) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <SidebarNav visuallyExpanded={visuallyExpanded} />
    </MemoryRouter>,
  );
}

describe("SidebarNav active attack modules", () => {
  it("lists every available active module under Attack Module when expanded", () => {
    renderNav("/testing");
    expect(screen.getByRole("link", { name: "Attack Module" })).toHaveAttribute(
      "href",
      "/testing",
    );
    for (const mod of ACTIVE_MODULES) {
      expect(screen.getByRole("link", { name: mod.name })).toHaveAttribute("href", mod.path);
    }
    expect(screen.queryByRole("link", { name: "Secret Detection" })).not.toBeInTheDocument();
  });

  it("hides module children in the icon rail", () => {
    renderNav("/testing/cors", false);
    expect(screen.getByRole("link", { name: "Attack Module" })).toBeInTheDocument();
    expect(
      screen.queryByRole("link", { name: "CORS Misconfiguration" }),
    ).not.toBeInTheDocument();
  });

  it("marks the nested module active on its workspace path", () => {
    renderNav("/testing/input-validation/params/abc");
    const iv = screen.getByRole("link", { name: "Input Validation" });
    expect(iv).toHaveAttribute("aria-current", "page");
    expect(screen.getByRole("link", { name: "Attack Module" })).not.toHaveAttribute(
      "aria-current",
      "page",
    );
  });
});
