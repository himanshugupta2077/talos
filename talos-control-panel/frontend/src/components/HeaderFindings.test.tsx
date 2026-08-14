import { describe, expect, it, vi } from "vitest";
import { MemoryRouter } from "react-router-dom";
import { render, screen } from "@testing-library/react";
import HeaderFindings from "./HeaderFindings";

const { mockStatus } = vi.hoisted(() => ({
  mockStatus: {
    findingsPrimary: 3 as number | null,
    findingsTotal: 12 as number | null,
    findingsTriaging: 4 as number | null,
  },
}));

vi.mock("../state/StatusContext", () => ({
  useStatus: () => mockStatus,
}));

function renderChip() {
  return render(
    <MemoryRouter>
      <HeaderFindings />
    </MemoryRouter>,
  );
}

describe("HeaderFindings", () => {
  it("shows primary then total findings", () => {
    mockStatus.findingsPrimary = 3;
    mockStatus.findingsTotal = 12;
    mockStatus.findingsTriaging = 4;
    renderChip();
    const link = screen.getByRole("link", { name: "Findings: 3 primary, 12 total" });
    expect(link).toHaveAttribute("href", "/findings");
    expect(link).toHaveTextContent("Findings: 3 / 12");
  });

  it("idles with an em dash when no project counts are available", () => {
    mockStatus.findingsPrimary = null;
    mockStatus.findingsTotal = null;
    mockStatus.findingsTriaging = null;
    renderChip();
    expect(screen.getByText("Findings: —")).toBeInTheDocument();
    expect(screen.queryByRole("link")).not.toBeInTheDocument();
  });
});
