import { useCallback, useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { useProject } from "../state/ProjectContext";
import { feedbackStep, useAction } from "../hooks/useAction";
import { api } from "../api/client";
import {
  ConfirmButton,
  FieldHint,
  Modal,
  ModuleHelp,
  Section,
} from "../components/Common";
import AuthModeBadge from "../components/AuthModeBadge";
import PathField, {
  OpenDirectoryTarget,
  openDirectoryBody,
} from "../components/PathField";
import { useCommandLog } from "../state/CommandLogContext";
import {
  CommandResult,
  OutscopeDomain,
  Project,
  ProjectSummary,
} from "../types";

const DEFAULT_MAX_BODY = 1_048_576;

const SUMMARY_LINKS: {
  key: keyof ProjectSummary;
  label: string;
  to: string;
}[] = [
  { key: "flows", label: "Flows", to: "/flows" },
  { key: "endpoints", label: "Endpoints", to: "/endpoints" },
  { key: "findings_triaging", label: "Triaging", to: "/findings" },
  { key: "findings_confirmed", label: "Confirmed", to: "/findings" },
  { key: "scheduler_pending", label: "Jobs pending", to: "/scheduler" },
  { key: "roles", label: "Roles", to: "/roles-modules" },
  { key: "modules", label: "Modules", to: "/roles-modules" },
];

function formatBytes(n: number): string {
  if (n >= 1_048_576) return `${(n / 1_048_576).toFixed(n % 1_048_576 === 0 ? 0 : 1)} MB`;
  if (n >= 1024) return `${(n / 1024).toFixed(n % 1024 === 0 ? 0 : 1)} KB`;
  return `${n} B`;
}

function ActiveBadge({ active }: { active: boolean }) {
  if (active) {
    return (
      <span className="badge badge-success badge-sm gap-1">
        <span className="inline-block w-1.5 h-1.5 rounded-full bg-success-content" />
        active
      </span>
    );
  }
  return <span className="badge badge-ghost badge-sm">inactive</span>;
}

/** Map open-directory API result into command-log steps (not a CLI mutation). */
function openDirectorySteps(result: {
  ok?: boolean;
  message?: string;
  path?: string;
  target?: string;
}): { steps: CommandResult[] } {
  const ok = result.ok !== false;
  const detail =
    result.message ||
    (ok
      ? `Directory open requested${result.path ? `: ${result.path}` : ""}`
      : "Directory open failed");
  return {
    steps: [
      {
        cmd: ["open-directory", result.target || ""],
        cmd_str: `open-directory target=${result.target || "?"}`,
        stdout: ok ? detail : "",
        stderr: ok ? "" : detail,
        exit_code: ok ? 0 : 1,
        duration_ms: 0,
        ok,
      },
    ],
  };
}

export default function Projects() {
  const { projects, refresh, selectedId, setSelectedId, selected, loading } =
    useProject();
  const { log } = useCommandLog();

  const [showCreate, setShowCreate] = useState(false);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [scope, setScope] = useState("");
  const [authMode, setAuthMode] = useState<"artifacts" | "platform_ntlm">("artifacts");

  // Workspace local edit state (synced when selection changes)
  const [editName, setEditName] = useState("");
  const [editDescription, setEditDescription] = useState("");
  const [storeBodies, setStoreBodies] = useState(true);
  const [maxBodySize, setMaxBodySize] = useState(DEFAULT_MAX_BODY);
  const [outscope, setOutscope] = useState<OutscopeDomain[]>([]);
  const [newScopePrefix, setNewScopePrefix] = useState("");
  const [scopeBulkText, setScopeBulkText] = useState("");
  const [newOutscopePrefix, setNewOutscopePrefix] = useState("");
  const [outscopeBulkText, setOutscopeBulkText] = useState("");
  const [summary, setSummary] = useState<ProjectSummary | null>(null);
  const [filter, setFilter] = useState("");

  const syncFromProject = useCallback((p: Project | null) => {
    if (!p) {
      setEditName("");
      setEditDescription("");
      setStoreBodies(true);
      setMaxBodySize(DEFAULT_MAX_BODY);
      setOutscope([]);
      setSummary(null);
      return;
    }
    setEditName(p.name);
    setEditDescription(p.description || "");
    setStoreBodies(p.constraints?.store_bodies ?? true);
    setMaxBodySize(p.constraints?.max_body_size ?? DEFAULT_MAX_BODY);
  }, []);

  useEffect(() => {
    syncFromProject(selected);
  }, [selected, syncFromProject]);

  const loadWorkspace = useCallback(async (projectId: string) => {
    try {
      const s = await api.get<ProjectSummary>(`/api/projects/${projectId}/summary`);
      setSummary(s);
    } catch {
      setSummary(null);
    }
    try {
      const o = await api.get<{
        prefixes?: OutscopeDomain[];
        domains?: OutscopeDomain[];
      }>(`/api/projects/${projectId}/outscope`);
      setOutscope(o.prefixes || o.domains || []);
    } catch {
      setOutscope([]);
    }
  }, []);

  useEffect(() => {
    if (selectedId) loadWorkspace(selectedId);
    else {
      setSummary(null);
      setOutscope([]);
    }
  }, [selectedId, loadWorkspace]);

  const create = useAction("Create project", () =>
    api
      .post("/api/projects", {
        name,
        description,
        auth_mode: authMode,
        // One complete Basic Scope prefix per line (commas are not separators).
        scope: scope
          .split("\n")
          .map((s) => s.trim())
          .filter(Boolean),
      })
      .then((r) => ({ steps: [r] }))
  );
  const openProject = useAction("Open project", (id: string) =>
    api.post(`/api/projects/${id}/open`).then((r) => ({ steps: [r] }))
  );
  const closeProject = useAction("Close project", () =>
    api.post(`/api/projects/close`).then((r) => ({ steps: [r] }))
  );
  const deleteProject = useAction(
    "Delete project",
    (id: string, purge: boolean) =>
      api
        .del(`/api/projects/${id}`, { force: true, purge: purge || undefined })
        .then((r) => ({ steps: [r] }))
  );
  const renameProject = useAction("Rename project", (id: string, newName: string) =>
    api
      .post(`/api/projects/${id}/rename`, { new_name: newName })
      .then((r) => ({ steps: [r] }))
  );
  const saveDescription = useAction(
    "Update description",
    (id: string, text: string) =>
      api
        .post(`/api/projects/${id}/description`, { description: text })
        .then((r) => ({ steps: [r] }))
  );
  const addScope = useAction("Add in-scope prefix", (id: string, prefix: string) =>
    api.post(`/api/projects/${id}/scope/add`, { prefix })
  );
  const removeScope = useAction("Remove in-scope prefix", (id: string, prefix: string) =>
    api.del(`/api/projects/${id}/scope/entry`, { prefix })
  );
  const bulkScope = useAction(
    "Bulk paste in-scope",
    (id: string, text: string) =>
      api.post(`/api/projects/${id}/scope/bulk`, { text, replace: false })
  );
  const importScopeFile = useAction(
    "Import in-scope file",
    async (id: string, file: File) => {
      const form = new FormData();
      form.append("file", file);
      return api.postForm(`/api/projects/${id}/scope/import`, form);
    }
  );
  const saveConstraints = useAction(
    "Set capture constraints",
    (id: string, body: { store_bodies: boolean; max_body_size: number }) =>
      api
        .post(`/api/projects/${id}/constraints`, body)
        .then((r) => ({ steps: [r] }))
  );
  const addOutscope = useAction(
    "Add out-of-scope prefix",
    (id: string, prefix: string) =>
      api.post(`/api/projects/${id}/outscope`, { prefix })
  );
  const removeOutscope = useAction(
    "Remove out-of-scope prefix",
    (id: string, prefix: string) =>
      api.del(
        `/api/projects/${id}/outscope/${encodeURIComponent(prefix)}`
      )
  );
  const bulkOutscope = useAction(
    "Bulk paste out-of-scope",
    (id: string, text: string) =>
      api.post(`/api/projects/${id}/outscope/bulk`, { text, replace: false })
  );
  const importOutscopeFile = useAction(
    "Import out-of-scope file",
    async (id: string, file: File) => {
      const form = new FormData();
      form.append("file", file);
      return api.postForm(`/api/projects/${id}/outscope/import`, form);
    }
  );
  // Body is target enum only — never the rendered filesystem path.
  const openDataDirectory = useAction(
    "Open data directory",
    (id: string) =>
      api
        .post<{
          ok: boolean;
          message?: string;
          path?: string;
          target?: string;
        }>(
          `/api/projects/${id}/open-directory`,
          openDirectoryBody("data_dir" satisfies OpenDirectoryTarget)
        )
        .then(openDirectorySteps)
  );
  const openDatabaseDirectory = useAction(
    "Open database directory",
    (id: string) =>
      api
        .post<{
          ok: boolean;
          message?: string;
          path?: string;
          target?: string;
        }>(
          `/api/projects/${id}/open-directory`,
          openDirectoryBody("database_dir" satisfies OpenDirectoryTarget)
        )
        .then(openDirectorySteps)
  );

  const copyPath = useCallback(
    async (path: string, which: string) => {
      try {
        await navigator.clipboard.writeText(path);
        log("Copy path", [
          feedbackStep(`clipboard ${which}`, true, path),
        ]);
      } catch (err) {
        const msg =
          err instanceof Error ? err.message : "Clipboard write failed";
        log("Copy path", [feedbackStep(`clipboard ${which}`, false, msg)]);
      }
    },
    [log]
  );

  const filtered = useMemo(() => {
    const q = filter.trim().toLowerCase();
    if (!q) return projects;
    return projects.filter(
      (p) =>
        p.name.toLowerCase().includes(q) ||
        p.id.toLowerCase().includes(q) ||
        (p.description || "").toLowerCase().includes(q) ||
        p.scope.some((s) => s.toLowerCase().includes(q))
    );
  }, [projects, filter]);

  const scopeEntries = selected?.scope || [];

  const constraintsDirty =
    selected &&
    (storeBodies !== (selected.constraints?.store_bodies ?? true) ||
      maxBodySize !== (selected.constraints?.max_body_size ?? DEFAULT_MAX_BODY));
  const nameDirty = selected && editName.trim() && editName.trim() !== selected.name;
  const descDirty =
    selected && editDescription !== (selected.description || "");

  const afterMutation = async (preferId?: string | null) => {
    await refresh();
    if (preferId) {
      // After rename the id may change — refresh will keep selection if still valid.
      setSelectedId(preferId);
    }
    if (selectedId) await loadWorkspace(selectedId);
  };

  return (
    <div className="flex flex-col gap-4 min-h-0">
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div>
          <h1 className="text-xl font-semibold">Projects</h1>
          <p className="text-xs text-base-content/50 mt-0.5">
            Project workspace — lifecycle, Basic Scope, capture constraints, and
            out-of-scope prefixes.
          </p>
        </div>
        <button
          className="btn btn-sm btn-primary"
          onClick={() => setShowCreate(true)}
        >
          New project
        </button>
      </div>

      <ModuleHelp title="How projects work">
        <p>
          A project is one assessment workspace: its data directory, captured
          traffic, Basic Scope, and configuration. Create a project before
          capturing or running project-scoped work.
        </p>
        <p>
          <strong className="text-base-content/70">Select</strong> a project in
          the list to view and edit it in the Control Panel.{" "}
          <strong className="text-base-content/70">Open (activate)</strong> makes
          it the Talos active project so the proxy captures into this workspace
          and project-scoped actions use this data directory. Closing deactivates
          it without deleting data.
        </p>
        <p>
          <strong className="text-base-content/70">Example:</strong> create{" "}
          <span className="mono">qa-smoke</span> with in-scope{" "}
          <span className="mono">example.com</span>, Open it, start the proxy,
          then browse the app — only matching traffic is stored.
        </p>
      </ModuleHelp>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 items-start">
        {/* ── Project list ─────────────────────────────────────── */}
        <aside className="lg:col-span-4 xl:col-span-3 panel overflow-hidden flex flex-col max-h-[calc(100vh-10rem)]">
          <div className="p-3 border-b border-base-300">
            <input
              className="input input-sm input-bordered w-full"
              placeholder="Filter projects…"
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
            />
            <div className="text-[11px] text-base-content/40 mt-2">
              {loading
                ? "Loading…"
                : `${filtered.length} of ${projects.length} project${
                    projects.length === 1 ? "" : "s"
                  }`}
            </div>
          </div>
          <ul className="overflow-y-auto flex-1">
            {filtered.length === 0 && (
              <li className="p-4 text-sm text-base-content/50 text-center">
                {projects.length === 0
                  ? "No projects yet."
                  : "No matches."}
              </li>
            )}
            {filtered.map((p) => {
              const isSelected = p.id === selectedId;
              return (
                <li key={p.id}>
                  <button
                    type="button"
                    onClick={() => setSelectedId(p.id)}
                    className={`w-full text-left px-3 py-2.5 border-b border-base-300/60 transition-colors ${
                      isSelected
                        ? "bg-primary/10 border-l-2 border-l-primary"
                        : p.active
                          ? "bg-success/5 hover:bg-base-200/60"
                          : "hover:bg-base-200/60"
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-medium text-sm truncate">
                        {p.name}
                      </span>
                      <span className="flex items-center gap-1 shrink-0">
                        <AuthModeBadge mode={p.auth_mode} />
                        <ActiveBadge active={!!p.active} />
                      </span>
                    </div>
                    <div className="text-[11px] mono text-base-content/40 truncate mt-0.5">
                      {p.id}
                    </div>
                    {p.scope.length > 0 && (
                      <div className="flex gap-1 flex-wrap mt-1">
                        {p.scope.slice(0, 2).map((s) => (
                          <span
                            key={s}
                            className="badge badge-outline badge-xs mono max-w-[9rem] truncate"
                          >
                            {s}
                          </span>
                        ))}
                        {p.scope.length > 2 && (
                          <span className="badge badge-ghost badge-xs">
                            +{p.scope.length - 2}
                          </span>
                        )}
                      </div>
                    )}
                  </button>
                </li>
              );
            })}
          </ul>
        </aside>

        {/* ── Workspace ────────────────────────────────────────── */}
        <main className="lg:col-span-8 xl:col-span-9 min-w-0 space-y-4">
          {!selected ? (
            <div className="panel p-10 text-center text-base-content/50">
              Select a project from the list, or create a new one.
            </div>
          ) : (
            <>
              {/* Header / lifecycle */}
              <div className="panel p-4">
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <h2 className="text-lg font-semibold truncate">
                        {selected.name}
                      </h2>
                      <AuthModeBadge mode={selected.auth_mode} size="sm" />
                      <ActiveBadge active={!!selected.active} />
                      {selected.db_exists ? (
                        <span className="badge badge-outline badge-sm">
                          DB ready
                        </span>
                      ) : (
                        <span className="badge badge-warning badge-sm">
                          no talos.db
                        </span>
                      )}
                    </div>
                    <p className="text-xs mono text-base-content/50 mt-1 break-all">
                      id: {selected.id}
                    </p>
                    {selected.description && (
                      <p className="text-sm text-base-content/70 mt-1">
                        {selected.description}
                      </p>
                    )}
                    {!selected.active && (
                      <p className="text-xs text-warning mt-2">
                        Selected for the Control Panel, but not the Talos active
                        project. Open it to capture traffic and run project-scoped
                        CLI work against this data directory.
                      </p>
                    )}
                  </div>
                  <div className="flex flex-wrap gap-2">
                    {!selected.active ? (
                      <button
                        className="btn btn-sm btn-primary"
                        disabled={openProject.running}
                        onClick={async () => {
                          await openProject.run(selected.id);
                          setSelectedId(selected.id);
                          await afterMutation(selected.id);
                        }}
                      >
                        {openProject.running ? (
                          <span className="loading loading-spinner loading-xs" />
                        ) : (
                          "Open (activate)"
                        )}
                      </button>
                    ) : (
                      <button
                        className="btn btn-sm"
                        disabled={closeProject.running}
                        onClick={async () => {
                          await closeProject.run();
                          await afterMutation(selected.id);
                        }}
                      >
                        {closeProject.running ? (
                          <span className="loading loading-spinner loading-xs" />
                        ) : (
                          "Close"
                        )}
                      </button>
                    )}
                    <Link to="/" className="btn btn-sm btn-ghost">
                      Dashboard
                    </Link>
                  </div>
                </div>

                {/* Summary strip */}
                <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-2 mt-4">
                  {SUMMARY_LINKS.map((c) => (
                    <Link
                      key={c.key}
                      to={c.to}
                      className="rounded-md border border-base-300 bg-base-200/40 px-2 py-2 hover:border-primary transition-colors"
                    >
                      <div className="text-lg font-semibold leading-none">
                        {summary ? summary[c.key] : "—"}
                      </div>
                      <div className="text-[10px] text-base-content/50 mt-1">
                        {c.label}
                      </div>
                    </Link>
                  ))}
                </div>
              </div>

              {/* Metadata */}
              <Section title="Identity & metadata">
                <div className="panel p-4 space-y-3">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                    <label className="form-control">
                      <span className="label-text text-xs">
                        Display name
                        <FieldHint text="Rename may change the project id slug and move the data directory on disk." />
                      </span>
                      <div className="flex gap-2">
                        <input
                          className="input input-sm input-bordered flex-1"
                          value={editName}
                          onChange={(e) => setEditName(e.target.value)}
                        />
                        <button
                          className="btn btn-sm btn-primary"
                          disabled={!nameDirty || renameProject.running}
                          onClick={async () => {
                            const newName = editName.trim();
                            await renameProject.run(selected.id, newName);
                            // Rename may change the slug id and move data_dir
                            // (CLI-017). Re-list and re-select by new name.
                            await refresh();
                            const list = await api.get<{
                              projects: Project[];
                            }>("/api/projects");
                            const byName = list.projects.find(
                              (p) => p.name === newName
                            );
                            if (byName) setSelectedId(byName.id);
                          }}
                        >
                          {renameProject.running ? (
                            <span className="loading loading-spinner loading-xs" />
                          ) : (
                            "Rename"
                          )}
                        </button>
                      </div>
                      <span className="label-text-alt text-base-content/40">
                        Renaming may change the project id and move the data
                        directory.
                      </span>
                    </label>
                    <label className="form-control">
                      <span className="label-text text-xs">Created</span>
                      <input
                        className="input input-sm input-bordered mono"
                        value={selected.created_at || "—"}
                        readOnly
                      />
                    </label>
                  </div>
                  <label className="form-control">
                    <span className="label-text text-xs">Description</span>
                    <div className="flex gap-2">
                      <input
                        className="input input-sm input-bordered flex-1"
                        value={editDescription}
                        onChange={(e) => setEditDescription(e.target.value)}
                        placeholder="Assessment note…"
                      />
                      <button
                        className="btn btn-sm btn-primary"
                        disabled={!descDirty || saveDescription.running}
                        onClick={async () => {
                          await saveDescription.run(
                            selected.id,
                            editDescription
                          );
                          await afterMutation(selected.id);
                        }}
                      >
                        {saveDescription.running ? (
                          <span className="loading loading-spinner loading-xs" />
                        ) : (
                          "Save"
                        )}
                      </button>
                    </div>
                  </label>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                    <PathField
                      label="Data directory"
                      path={selected.data_dir}
                      onCopy={() =>
                        copyPath(selected.data_dir, "data_dir")
                      }
                      onOpen={async () => {
                        try {
                          await openDataDirectory.run(selected.id);
                        } catch {
                          /* failure already logged via useAction */
                        }
                      }}
                      openRunning={openDataDirectory.running}
                    />
                    <PathField
                      label="Database"
                      path={
                        selected.db_path ||
                        `${selected.data_dir}/talos.db`
                      }
                      note={selected.db_exists ? undefined : "(missing)"}
                      onCopy={() =>
                        copyPath(
                          selected.db_path ||
                            `${selected.data_dir}/talos.db`,
                          "database"
                        )
                      }
                      onOpen={async () => {
                        try {
                          // Opens parent of talos.db; file need not exist.
                          await openDatabaseDirectory.run(selected.id);
                        } catch {
                          /* failure already logged via useAction */
                        }
                      }}
                      openRunning={openDatabaseDirectory.running}
                    />
                  </div>
                </div>
              </Section>

              {/* In scope — Basic Scope URL prefixes */}
              <Section title="In scope">
                <div className="panel p-4 space-y-4">
                  <p className="text-xs text-base-content/50">
                    URL prefixes Talos is allowed to capture. Empty list means
                    nothing is captured (strict opt-in).
                  </p>

                  <ModuleHelp title="How Basic Scope works">
                    <p>
                      Basic Scope is an allow-list of URL prefixes. The proxy only
                      stores traffic that matches at least one in-scope entry and
                      is not out-of-scope. Talos uses it so capture stays limited
                      to the assessment target.
                    </p>
                    <p>
                      Enter a host or URL prefix. Protocol is optional — omitted
                      protocol matches HTTP and HTTPS. Omitted port matches any
                      port; a specified port matches only that port. Subdomains
                      are not implied (
                      <span className="mono">example.com</span> does not include{" "}
                      <span className="mono">api.example.com</span>).
                    </p>
                    <p>
                      <strong className="text-base-content/70">Example:</strong>{" "}
                      <span className="mono">example.com</span>,{" "}
                      <span className="mono">example.com/api/</span>,{" "}
                      <span className="mono">http://example.com:8000</span>,{" "}
                      <span className="mono">https://example.com:8443/admin/</span>
                    </p>
                  </ModuleHelp>

                  <div>
                    <div className="text-xs text-base-content/50 mb-1">
                      One complete prefix per entry
                    </div>
                    <div className="flex gap-2">
                      <input
                        className="input input-sm input-bordered flex-1 mono"
                        placeholder="example.com"
                        value={newScopePrefix}
                        onChange={(e) => setNewScopePrefix(e.target.value)}
                        onKeyDown={async (e) => {
                          if (e.key === "Enter" && newScopePrefix.trim()) {
                            e.preventDefault();
                            await addScope.run(selected.id, newScopePrefix.trim());
                            setNewScopePrefix("");
                            await afterMutation(selected.id);
                          }
                        }}
                      />
                      <button
                        className="btn btn-sm btn-primary"
                        disabled={!newScopePrefix.trim() || addScope.running}
                        onClick={async () => {
                          await addScope.run(selected.id, newScopePrefix.trim());
                          setNewScopePrefix("");
                          await afterMutation(selected.id);
                        }}
                      >
                        {addScope.running ? (
                          <span className="loading loading-spinner loading-xs" />
                        ) : (
                          "Add entry"
                        )}
                      </button>
                    </div>
                  </div>

                  <div>
                    <div className="text-xs font-medium mb-1">Bulk paste</div>
                    <p className="text-[11px] text-base-content/40 mb-1">
                      One prefix per line. Each non-empty line is one complete
                      entry — commas are not separators.
                    </p>
                    <textarea
                      className="textarea textarea-bordered textarea-sm w-full mono min-h-[5rem]"
                      value={scopeBulkText}
                      onChange={(e) => setScopeBulkText(e.target.value)}
                      placeholder={"example.com\napi.example.com\nhttp://10.10.10.25:8000"}
                    />
                    <button
                      className="btn btn-xs btn-outline mt-2"
                      disabled={!scopeBulkText.trim() || bulkScope.running}
                      onClick={async () => {
                        await bulkScope.run(selected.id, scopeBulkText);
                        setScopeBulkText("");
                        await afterMutation(selected.id);
                      }}
                    >
                      {bulkScope.running ? (
                        <span className="loading loading-spinner loading-xs" />
                      ) : (
                        "Import paste"
                      )}
                    </button>
                  </div>

                  <div>
                    <div className="text-xs font-medium mb-1">
                      Import file
                      <FieldHint text="UTF-8 .txt file — same rules as bulk paste (one prefix per line)." />
                    </div>
                    <p className="text-[11px] text-base-content/40 mb-1">
                      UTF-8 <span className="mono">.txt</span> — one prefix per
                      line.
                    </p>
                    <input
                      type="file"
                      accept=".txt,text/plain"
                      className="file-input file-input-bordered file-input-xs w-full max-w-md"
                      disabled={importScopeFile.running}
                      onChange={async (e) => {
                        const file = e.target.files?.[0];
                        e.target.value = "";
                        if (!file) return;
                        await importScopeFile.run(selected.id, file);
                        await afterMutation(selected.id);
                      }}
                    />
                  </div>

                  {scopeEntries.length === 0 ? (
                    <div className="text-sm text-warning">
                      No in-scope entries — capture will be empty until scope is
                      set.
                    </div>
                  ) : (
                    <ul className="divide-y divide-base-300">
                      {scopeEntries.map((s) => (
                        <li
                          key={s}
                          className="flex items-center justify-between py-2 gap-2"
                        >
                          <span className="mono text-sm break-all">{s}</span>
                          <ConfirmButton
                            className="btn btn-xs btn-ghost text-error"
                            confirmText="Remove prefix?"
                            onConfirm={async () => {
                              await removeScope.run(selected.id, s);
                              await afterMutation(selected.id);
                            }}
                          >
                            Remove
                          </ConfirmButton>
                        </li>
                      ))}
                    </ul>
                  )}
                </div>
              </Section>

              {/* Constraints */}
              <Section
                title="Capture constraints"
                action={
                  <button
                    className="btn btn-xs btn-primary"
                    disabled={!constraintsDirty || saveConstraints.running}
                    onClick={async () => {
                      await saveConstraints.run(selected.id, {
                        store_bodies: storeBodies,
                        max_body_size: maxBodySize,
                      });
                      await afterMutation(selected.id);
                    }}
                  >
                    {saveConstraints.running ? (
                      <span className="loading loading-spinner loading-xs" />
                    ) : (
                      "Apply constraints"
                    )}
                  </button>
                }
              >
                <div className="panel p-4 space-y-3">
                  <p className="text-xs text-base-content/50">
                    How much of each in-scope request/response is persisted.
                    Changes apply after you click Apply constraints. These dual-write into layered
                    capture config — full inheritance and header rules live in{" "}
                    <Link
                      className="link link-primary"
                      to="/talos-config?tab=settings&section=capture"
                    >
                      Talos Configuration → Capture
                    </Link>
                    .
                  </p>
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    <label className="flex items-start gap-2 cursor-pointer">
                      <input
                        type="checkbox"
                        className="checkbox checkbox-sm mt-0.5"
                        checked={
                          selected.constraints?.capture_in_scope_only ?? true
                        }
                        disabled
                      />
                      <span>
                        <span className="text-sm font-medium">
                          Capture in-scope only
                        </span>
                        <span className="block text-xs text-base-content/50">
                          Always on — Talos never stores out-of-scope traffic.
                        </span>
                      </span>
                    </label>
                    <label className="flex items-start gap-2 cursor-pointer">
                      <input
                        type="checkbox"
                        className="checkbox checkbox-sm mt-0.5"
                        checked={storeBodies}
                        onChange={(e) => setStoreBodies(e.target.checked)}
                      />
                      <span>
                        <span className="text-sm font-medium">
                          Store bodies
                          <FieldHint text="When off, headers and metadata still capture; bodies are dropped — useful for recon-heavy sessions." />
                        </span>
                        <span className="block text-xs text-base-content/50">
                          Persist request/response bodies. Disable for
                          recon-heavy sessions.
                        </span>
                      </span>
                    </label>
                    <label className="form-control">
                      <span className="label-text text-xs">
                        Max body size (bytes)
                      </span>
                      <input
                        type="number"
                        className="input input-sm input-bordered mono"
                        min={0}
                        step={1024}
                        value={maxBodySize}
                        onChange={(e) =>
                          setMaxBodySize(
                            Math.max(0, parseInt(e.target.value || "0", 10))
                          )
                        }
                      />
                      <span className="label-text-alt text-base-content/40">
                        {formatBytes(maxBodySize)} — bodies larger than this are
                        truncated
                      </span>
                    </label>
                  </div>
                </div>
              </Section>

              {/* Out of scope — same Basic Scope model */}
              <Section title="Out of scope">
                <div className="panel p-4 space-y-4">
                  <p className="text-xs text-base-content/50">
                    Prefixes excluded from capture even when they match in-scope.
                    Out-of-scope overrides in-scope. Same prefix syntax. Requires
                    an initialized project database (
                    <span className="mono">talos.db</span>).
                  </p>

                  <ModuleHelp title="How out-of-scope works">
                    <p>
                      Use this to drop noisy or sensitive paths that would
                      otherwise match your allow-list (CDNs, analytics, logout,
                      third-party widgets). Matching uses the same Basic Scope
                      prefix rules as in-scope; when both match, out-of-scope
                      wins and the traffic is not stored.
                    </p>
                    <p>
                      <strong className="text-base-content/70">Example:</strong>{" "}
                      in-scope <span className="mono">example.com</span> plus
                      out-of-scope{" "}
                      <span className="mono">cdn.example.com</span> and{" "}
                      <span className="mono">example.com/logout</span> keeps app
                      traffic while skipping the CDN and logout.
                    </p>
                  </ModuleHelp>

                  <div>
                    <div className="text-xs text-base-content/50 mb-1">
                      One complete prefix per entry
                    </div>
                    <div className="flex gap-2">
                      <input
                        className="input input-sm input-bordered flex-1 mono"
                        placeholder="analytics.example.com"
                        value={newOutscopePrefix}
                        onChange={(e) => setNewOutscopePrefix(e.target.value)}
                        onKeyDown={async (e) => {
                          if (e.key === "Enter" && newOutscopePrefix.trim()) {
                            e.preventDefault();
                            await addOutscope.run(
                              selected.id,
                              newOutscopePrefix.trim()
                            );
                            setNewOutscopePrefix("");
                            await loadWorkspace(selected.id);
                          }
                        }}
                      />
                      <button
                        className="btn btn-sm btn-primary"
                        disabled={
                          !newOutscopePrefix.trim() || addOutscope.running
                        }
                        onClick={async () => {
                          await addOutscope.run(
                            selected.id,
                            newOutscopePrefix.trim()
                          );
                          setNewOutscopePrefix("");
                          await loadWorkspace(selected.id);
                        }}
                      >
                        {addOutscope.running ? (
                          <span className="loading loading-spinner loading-xs" />
                        ) : (
                          "Add entry"
                        )}
                      </button>
                    </div>
                  </div>

                  <div>
                    <div className="text-xs font-medium mb-1">Bulk paste</div>
                    <p className="text-[11px] text-base-content/40 mb-1">
                      One prefix per line. Commas are not separators.
                    </p>
                    <textarea
                      className="textarea textarea-bordered textarea-sm w-full mono min-h-[4rem]"
                      value={outscopeBulkText}
                      onChange={(e) => setOutscopeBulkText(e.target.value)}
                      placeholder={"cdn.example.com\nexample.com/logout"}
                    />
                    <button
                      className="btn btn-xs btn-outline mt-2"
                      disabled={!outscopeBulkText.trim() || bulkOutscope.running}
                      onClick={async () => {
                        await bulkOutscope.run(selected.id, outscopeBulkText);
                        setOutscopeBulkText("");
                        await loadWorkspace(selected.id);
                      }}
                    >
                      {bulkOutscope.running ? (
                        <span className="loading loading-spinner loading-xs" />
                      ) : (
                        "Import paste"
                      )}
                    </button>
                  </div>

                  <div>
                    <div className="text-xs font-medium mb-1">
                      Import file
                      <FieldHint text="UTF-8 .txt file — one prefix per line, same as bulk paste." />
                    </div>
                    <p className="text-[11px] text-base-content/40 mb-1">
                      UTF-8 <span className="mono">.txt</span> — one prefix per
                      line.
                    </p>
                    <input
                      type="file"
                      accept=".txt,text/plain"
                      className="file-input file-input-bordered file-input-xs w-full max-w-md"
                      disabled={importOutscopeFile.running}
                      onChange={async (e) => {
                        const file = e.target.files?.[0];
                        e.target.value = "";
                        if (!file) return;
                        await importOutscopeFile.run(selected.id, file);
                        await loadWorkspace(selected.id);
                      }}
                    />
                  </div>

                  {outscope.length === 0 ? (
                    <div className="text-sm text-base-content/40">
                      No out-of-scope prefixes.
                    </div>
                  ) : (
                    <ul className="divide-y divide-base-300">
                      {outscope.map((d) => {
                        const label = d.prefix || d.domain;
                        return (
                          <li
                            key={String(d.id ?? label)}
                            className="flex items-center justify-between py-2 gap-2"
                          >
                            <div>
                              <span className="mono text-sm break-all">
                                {label}
                              </span>
                              {d.created_at && (
                                <span className="text-[11px] text-base-content/40 ml-2">
                                  {d.created_at}
                                </span>
                              )}
                            </div>
                            <ConfirmButton
                              className="btn btn-xs btn-ghost text-error"
                              confirmText="Remove prefix?"
                              onConfirm={async () => {
                                await removeOutscope.run(selected.id, label);
                                await loadWorkspace(selected.id);
                              }}
                            >
                              Remove
                            </ConfirmButton>
                          </li>
                        );
                      })}
                    </ul>
                  )}
                </div>
              </Section>

              {/* Danger zone */}
              <Section title="Danger zone">
                <div className="panel p-4 border-error/30 space-y-3">
                  <p className="text-xs text-base-content/50">
                    <strong className="text-base-content/70">Delete</strong>{" "}
                    removes the project from the registry only.{" "}
                    <strong className="text-base-content/70">Purge</strong> also
                    erases the data directory — irreversible.
                  </p>
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <div>
                      <div className="text-sm font-medium">
                        Delete from registry
                      </div>
                      <div className="text-xs text-base-content/50">
                        Removes the registry entry. Data on disk is preserved.
                      </div>
                    </div>
                    <ConfirmButton
                      className="btn btn-sm btn-error btn-outline"
                      confirmText={`Remove "${selected.name}" from registry?`}
                      onConfirm={async () => {
                        await deleteProject.run(selected.id, false);
                        setSelectedId(null);
                        await refresh();
                      }}
                    >
                      Delete
                    </ConfirmButton>
                  </div>
                  <div className="divider my-0" />
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <div>
                      <div className="text-sm font-medium text-error">
                        Purge project
                      </div>
                      <div className="text-xs text-base-content/50">
                        Permanently delete registry entry{" "}
                        <strong>and</strong> the data directory (DB, archive,
                        reports, sessions). Irreversible.
                      </div>
                    </div>
                    <ConfirmButton
                      className="btn btn-sm btn-error"
                      confirmText="PERMANENTLY erase all data?"
                      onConfirm={async () => {
                        await deleteProject.run(selected.id, true);
                        setSelectedId(null);
                        await refresh();
                      }}
                    >
                      Purge
                    </ConfirmButton>
                  </div>
                </div>
              </Section>
            </>
          )}
        </main>
      </div>

      <Modal
        open={showCreate}
        onClose={() => setShowCreate(false)}
        title="Create project"
      >
        <div className="flex flex-col gap-3">
          <label className="form-control">
            <span className="label-text text-xs">Name</span>
            <input
              className="input input-sm input-bordered"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="qa-smoke"
            />
          </label>
          <label className="form-control">
            <span className="label-text text-xs">Description</span>
            <input
              className="input input-sm input-bordered"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="QA smoke run"
            />
          </label>
          <div className="form-control">
            <span className="label-text text-xs mb-1">Authentication model</span>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              <button
                type="button"
                className={`btn btn-sm h-auto py-2 justify-start text-left ${
                  authMode === "artifacts" ? "btn-primary" : "btn-ghost border border-base-300"
                }`}
                onClick={() => setAuthMode("artifacts")}
              >
                <span>
                  <span className="block font-medium">Cookie / header</span>
                  <span className="block text-[11px] font-normal opacity-80">
                    Session tokens, Bearer, cookies. BAC swaps headers.
                  </span>
                </span>
              </button>
              <button
                type="button"
                className={`btn btn-sm h-auto py-2 justify-start text-left ${
                  authMode === "platform_ntlm" ? "btn-warning" : "btn-ghost border border-base-300"
                }`}
                onClick={() => setAuthMode("platform_ntlm")}
              >
                <span>
                  <span className="block font-medium">Windows / NTLM</span>
                  <span className="block text-[11px] font-normal opacity-80">
                    Platform-auth profiles per role. No header swap.
                  </span>
                </span>
              </button>
            </div>
          </div>
          <label className="form-control">
            <span className="label-text text-xs">
              In-scope prefixes (optional)
            </span>
            <p className="text-[11px] text-base-content/40 mb-1">
              One prefix per line. Empty means nothing is captured until you add
              scope later.
            </p>
            <textarea
              className="textarea textarea-bordered textarea-sm mono min-h-[4rem]"
              value={scope}
              onChange={(e) => setScope(e.target.value)}
              placeholder={"example.com\nhttp://api.example.com:8000"}
            />
          </label>
          <p className="text-[11px] text-base-content/40">
            Create & open registers the project and activates it as the Talos
            active project.
          </p>
          <button
            className="btn btn-primary btn-sm mt-2"
            disabled={!name || create.running}
            onClick={async () => {
              await create.run();
              setShowCreate(false);
              const createdName = name;
              setName("");
              setDescription("");
              setScope("");
              setAuthMode("artifacts");
              // New projects are activated via project open; Talos core owns
              // any proxy reconcile that follows the active-project change.
              const list = await api.get<{ projects: Project[] }>(
                "/api/projects"
              );
              const created = list.projects.find((p) => p.name === createdName);
              if (created) {
                await openProject.run(created.id);
                setSelectedId(created.id);
              }
              await refresh();
            }}
          >
            {create.running ? (
              <span className="loading loading-spinner loading-xs" />
            ) : (
              "Create & open"
            )}
          </button>
        </div>
      </Modal>
    </div>
  );
}
