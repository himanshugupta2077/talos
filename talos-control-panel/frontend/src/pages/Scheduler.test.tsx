import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { MemoryRouter } from "react-router-dom";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import Scheduler from "./Scheduler";

const { apiGet, apiPost, selectedProject } = vi.hoisted(() => ({
  apiGet: vi.fn(),
  apiPost: vi.fn(),
  selectedProject: { id: "proj-1", name: "Demo" },
}));

vi.mock("../api/client", async () => {
  const actual = await vi.importActual<typeof import("../api/client")>(
    "../api/client"
  );
  return {
    ...actual,
    api: {
      get: (...args: unknown[]) => apiGet(...args),
      post: (...args: unknown[]) => apiPost(...args),
    },
  };
});

vi.mock("../state/ProjectContext", () => ({
  useProject: () => ({
    selected: selectedProject,
  }),
}));

vi.mock("../state/StatusContext", () => ({
  useStatus: () => ({ refreshStatus: vi.fn() }),
}));

vi.mock("../hooks/useAction", () => ({
  useAction: () => ({
    run: vi.fn(async () => undefined),
    running: false,
  }),
}));

const statusPayload = {
  counts: {
    pending: 1,
    running: 0,
    paused: 0,
    done: 2,
    failed: 3,
    skipped: 0,
    cancelled: 0,
  },
  config: { min_delay: 2, max_delay: 6, max_queue_size: 200 },
  state: { state: "paused", reason: null },
  process: { state: "stopped" },
  metrics: {},
  by_family: [{ family: "bac", n: 4 }],
};

const jobsPayload = {
  jobs: [
    {
      job_id: "aaaaaaaa-1111-2222-3333-444444444444",
      job_type: "bac_idor",
      status: "pending",
      priority: 100,
      role_name: "admin",
      module_name: "api",
      created_at: "2026-08-17T10:00:00Z",
    },
  ],
  total: 1,
  limit: 100,
  offset: 0,
};

const filtersPayload = {
  job_types: ["replay", "bac", "bac_idor"],
  statuses: ["pending", "running", "paused", "done", "failed", "skipped", "cancelled"],
  roles: ["admin"],
  modules: ["api"],
};

function renderPage(search = "") {
  return render(
    <MemoryRouter initialEntries={[`/scheduler${search}`]}>
      <Scheduler />
    </MemoryRouter>
  );
}

describe("Scheduler page filters", () => {
  beforeEach(() => {
    const store: Record<string, string> = {};
    vi.stubGlobal("localStorage", {
      getItem: (k: string) => store[k] ?? null,
      setItem: (k: string, v: string) => {
        store[k] = v;
      },
      removeItem: (k: string) => {
        delete store[k];
      },
      clear: () => {
        for (const k of Object.keys(store)) delete store[k];
      },
    });
    apiGet.mockImplementation(async (path: string, params?: Record<string, unknown>) => {
      if (path === "/api/scheduler/status") return statusPayload;
      if (path === "/api/scheduler/jobs") return { ...jobsPayload, _params: params };
      if (path === "/api/scheduler/filters") return filtersPayload;
      if (path === "/api/configuration/settings") return { settings: [] };
      return {};
    });
    apiPost.mockResolvedValue({ steps: [] });
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.clearAllMocks();
    vi.unstubAllGlobals();
  });

  it("does not start a periodic reload timer", async () => {
    const spy = vi.spyOn(window, "setInterval");
    renderPage();
    await screen.findByRole("heading", { name: "Scheduler" });
    const pollMs = spy.mock.calls.map((c) => c[1]);
    expect(pollMs).not.toContain(4000);
    spy.mockRestore();
  });

  it("sends the default active status filter on first load", async () => {
    renderPage();
    await waitFor(() => {
      const jobsCalls = apiGet.mock.calls.filter(
        (c) => c[0] === "/api/scheduler/jobs"
      );
      expect(jobsCalls.length).toBeGreaterThan(0);
    });
    const firstJobs = apiGet.mock.calls.find((c) => c[0] === "/api/scheduler/jobs");
    expect(firstJobs?.[1]).toMatchObject({ status: "active", project_id: "proj-1" });
  });

  it("applies status chips without resetting to failed", async () => {
    renderPage();
    await screen.findByRole("heading", { name: "Scheduler" });

    fireEvent.click(screen.getByRole("button", { name: /done/i }));

    await waitFor(() => {
      const lastJobs = [...apiGet.mock.calls]
        .reverse()
        .find((c) => c[0] === "/api/scheduler/jobs");
      expect(lastJobs?.[1]).toMatchObject({ status: "done" });
    });
    expect(screen.getByRole("button", { name: "History" })).toHaveClass(
      "tab-active"
    );
    const statusSelect = screen.getByDisplayValue("done") as HTMLSelectElement;
    expect(statusSelect.value).toBe("done");
  });

  it("applies type, role, and module dropdowns together", async () => {
    renderPage();
    await screen.findByRole("heading", { name: "Scheduler" });

    fireEvent.change(screen.getByDisplayValue("type: any"), {
      target: { value: "bac" },
    });
    fireEvent.change(screen.getByDisplayValue("role: any"), {
      target: { value: "admin" },
    });
    fireEvent.change(screen.getByDisplayValue("module: any"), {
      target: { value: "api" },
    });

    await waitFor(() => {
      const lastJobs = [...apiGet.mock.calls]
        .reverse()
        .find((c) => c[0] === "/api/scheduler/jobs");
      expect(lastJobs?.[1]).toMatchObject({
        job_type: "bac",
        role: "admin",
        module: "api",
      });
    });
  });

  it("keeps status options usable before the filters API returns", async () => {
    renderPage();
    await screen.findByRole("heading", { name: "Scheduler" });
    const statusSelect = screen.getByDisplayValue("active");
    const options = within(statusSelect).getAllByRole("option").map((o) =>
      (o as HTMLOptionElement).value
    );
    expect(options).toEqual(
      expect.arrayContaining([
        "",
        "active",
        "pending",
        "running",
        "paused",
        "done",
        "failed",
        "skipped",
        "cancelled",
      ])
    );
  });
});
