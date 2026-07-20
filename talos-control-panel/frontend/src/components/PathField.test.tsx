/**
 * PathField + open-directory client contract tests.
 *
 * Frontend must render resolved paths, copy exact strings, and open via
 * project id + predefined target only (never the rendered path in the body).
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import PathField, { openDirectoryBody } from "./PathField";
import { ApiError } from "../api/client";
import { feedbackStep } from "../hooks/useAction";

describe("openDirectoryBody", () => {
  it("sends only predefined targets — never a filesystem path", () => {
    expect(openDirectoryBody("data_dir")).toEqual({ target: "data_dir" });
    expect(openDirectoryBody("database_dir")).toEqual({
      target: "database_dir",
    });
    const body = openDirectoryBody("data_dir") as Record<string, unknown>;
    expect(body).not.toHaveProperty("path");
    expect(JSON.stringify(body)).not.toContain("/home/");
  });
});

describe("PathField", () => {
  const dataDir = "/home/user/.talos/projects/example";
  const dbPath = "/home/user/.talos/projects/example/talos.db";

  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("renders data directory path", () => {
    render(
      <PathField
        label="Data directory"
        path={dataDir}
        onCopy={() => {}}
        onOpen={() => {}}
      />
    );
    expect(screen.getByText("Data directory")).toBeInTheDocument();
    expect(screen.getByTestId("path-value")).toHaveTextContent(dataDir);
  });

  it("renders database path", () => {
    render(
      <PathField
        label="Database"
        path={dbPath}
        note="(missing)"
        onCopy={() => {}}
        onOpen={() => {}}
      />
    );
    expect(screen.getByText("Database")).toBeInTheDocument();
    expect(screen.getByTestId("path-value")).toHaveTextContent(dbPath);
    expect(screen.getByTestId("path-value")).toHaveTextContent("(missing)");
  });

  it("copy data directory copies the exact resolved path", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.assign(navigator, {
      clipboard: { writeText },
    });

    const onCopy = vi.fn(async () => {
      await navigator.clipboard.writeText(dataDir);
    });

    render(
      <PathField
        label="Data directory"
        path={dataDir}
        onCopy={onCopy}
        onOpen={() => {}}
      />
    );
    fireEvent.click(screen.getByTestId("copy-path"));
    await waitFor(() => expect(onCopy).toHaveBeenCalled());
    expect(writeText).toHaveBeenCalledWith(dataDir);
  });

  it("copy database path copies the exact resolved path", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.assign(navigator, {
      clipboard: { writeText },
    });

    const onCopy = vi.fn(async () => {
      await navigator.clipboard.writeText(dbPath);
    });

    render(
      <PathField
        label="Database"
        path={dbPath}
        onCopy={onCopy}
        onOpen={() => {}}
      />
    );
    fireEvent.click(screen.getByTestId("copy-path"));
    await waitFor(() => expect(onCopy).toHaveBeenCalled());
    expect(writeText).toHaveBeenCalledWith(dbPath);
  });

  it("open data directory invokes parent handler (project id + data_dir)", async () => {
    const onOpen = vi.fn();
    render(
      <PathField
        label="Data directory"
        path={dataDir}
        onCopy={() => {}}
        onOpen={onOpen}
      />
    );
    fireEvent.click(screen.getByTestId("open-directory"));
    expect(onOpen).toHaveBeenCalledTimes(1);
    // PathField does not pass the path into open — parent builds API body.
  });

  it("open database directory invokes parent handler", async () => {
    const onOpen = vi.fn();
    render(
      <PathField
        label="Database"
        path={dbPath}
        onCopy={() => {}}
        onOpen={onOpen}
      />
    );
    fireEvent.click(screen.getByTestId("open-directory"));
    expect(onOpen).toHaveBeenCalledTimes(1);
  });

  it("buttons have accessible labels", () => {
    render(
      <PathField
        label="Data directory"
        path={dataDir}
        onCopy={() => {}}
        onOpen={() => {}}
      />
    );
    expect(screen.getByLabelText("Copy path")).toBeInTheDocument();
    expect(screen.getByLabelText("Open directory")).toBeInTheDocument();
  });
});

describe("open-directory API contract (client)", () => {
  it("posts project id in URL and target enum only in body", async () => {
    const posts: { path: string; body: unknown }[] = [];
    const projectId = "example-proj";
    const target = "data_dir" as const;

    // Mirror Projects page contract without mounting full page providers.
    const fakePost = async (path: string, body: unknown) => {
      posts.push({ path, body });
      return {
        ok: true,
        project_id: projectId,
        target,
        path: "/resolved/server/side/only",
        message: "Directory open requested",
      };
    };

    await fakePost(
      `/api/projects/${projectId}/open-directory`,
      openDirectoryBody(target)
    );

    expect(posts).toHaveLength(1);
    expect(posts[0].path).toBe(
      `/api/projects/${projectId}/open-directory`
    );
    expect(posts[0].body).toEqual({ target: "data_dir" });
    expect(JSON.stringify(posts[0].body)).not.toContain("resolved");
    expect(JSON.stringify(posts[0].body)).not.toContain("/home/");
  });

  it("open database directory sends database_dir target", async () => {
    const body = openDirectoryBody("database_dir");
    expect(body).toEqual({ target: "database_dir" });
    expect(Object.keys(body)).toEqual(["target"]);
  });
});

describe("feedback helpers", () => {
  it("feedbackStep marks copy success", () => {
    const step = feedbackStep("clipboard data_dir", true, "/tmp/p");
    expect(step.ok).toBe(true);
    expect(step.stdout).toBe("/tmp/p");
    expect(step.stderr).toBe("");
  });

  it("ApiError detail is string-extractable for surface feedback", () => {
    const err = new ApiError(400, {
      detail: "Project data directory does not exist: /missing",
    });
    expect(err.body.detail).toContain("does not exist");
  });
});
