import { describe, expect, it } from "vitest";
import {
  DEFAULT_HISTORY_FILTERS,
  DEFAULT_JOBS_FILTERS,
  nextSchedulerView,
  writeSchedulerSearchParams,
} from "./shared";

describe("nextSchedulerView", () => {
  const jobsActive = {
    tab: "jobs" as const,
    filters: { ...DEFAULT_JOBS_FILTERS },
  };

  it("keeps jobs tab when picking a live status", () => {
    const next = nextSchedulerView(jobsActive, { status: "pending" });
    expect(next.tab).toBe("jobs");
    expect(next.filters.status).toBe("pending");
  });

  it("switches to history when picking a terminal status", () => {
    const next = nextSchedulerView(jobsActive, { status: "done" });
    expect(next.tab).toBe("history");
    expect(next.filters.status).toBe("done");
  });

  it("does not overwrite a terminal status when switching to history", () => {
    const current = {
      tab: "jobs" as const,
      filters: { ...DEFAULT_JOBS_FILTERS, status: "skipped" },
    };
    const next = nextSchedulerView(current, {}, "history");
    expect(next.tab).toBe("history");
    expect(next.filters.status).toBe("skipped");
  });

  it("defaults history tab to failed when current status is live", () => {
    const next = nextSchedulerView(jobsActive, {}, "history");
    expect(next.tab).toBe("history");
    expect(next.filters.status).toBe(DEFAULT_HISTORY_FILTERS.status);
  });

  it("defaults jobs tab to active when leaving a terminal history filter", () => {
    const current = {
      tab: "history" as const,
      filters: { ...DEFAULT_HISTORY_FILTERS, status: "done" },
    };
    const next = nextSchedulerView(current, {}, "jobs");
    expect(next.tab).toBe("jobs");
    expect(next.filters.status).toBe(DEFAULT_JOBS_FILTERS.status);
  });

  it("switches to jobs when picking all / active from history", () => {
    const current = {
      tab: "history" as const,
      filters: { ...DEFAULT_HISTORY_FILTERS },
    };
    expect(nextSchedulerView(current, { status: "" }).tab).toBe("jobs");
    expect(nextSchedulerView(current, { status: "active" }).tab).toBe("jobs");
  });

  it("preserves type / role / search when only status changes", () => {
    const current = {
      tab: "jobs" as const,
      filters: {
        ...DEFAULT_JOBS_FILTERS,
        jobType: "bac",
        role: "admin",
        search: "abc",
      },
    };
    const next = nextSchedulerView(current, { status: "failed" });
    expect(next.filters.jobType).toBe("bac");
    expect(next.filters.role).toBe("admin");
    expect(next.filters.search).toBe("abc");
    expect(next.tab).toBe("history");
  });
});

describe("writeSchedulerSearchParams", () => {
  it("writes tab, status, and type and keeps job", () => {
    const current = new URLSearchParams("job=abc-123");
    const next = writeSchedulerSearchParams(current, "history", {
      status: "done",
      jobType: "iv",
    });
    expect(next.get("tab")).toBe("history");
    expect(next.get("status")).toBe("done");
    expect(next.get("type")).toBe("iv");
    expect(next.get("job")).toBe("abc-123");
  });

  it("clears empty status and type", () => {
    const current = new URLSearchParams("tab=jobs&status=active&type=bac");
    const next = writeSchedulerSearchParams(current, "jobs", {
      status: "",
      jobType: "",
    });
    expect(next.get("tab")).toBe("jobs");
    expect(next.has("status")).toBe(false);
    expect(next.has("type")).toBe(false);
  });
});
