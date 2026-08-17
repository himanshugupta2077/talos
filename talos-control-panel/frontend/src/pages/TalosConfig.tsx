/**
 * Talos Configuration workspace — UI for EffectiveConfig.
 *
 * Tabs: Overview | Settings | Files
 * Scope: Project (selected) | Global
 *
 * HTTP rules are managed on the HTTP Rules workspace (/mutations) and via
 * `talos config http`. This page owns scalar layered settings only.
 *
 * All reads/writes go through /api/configuration → talos config CLI.
 * Does not edit YAML or SQLite directly.
 */

import { useCallback, useEffect, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api } from "../api/client";
import { useAction, feedbackStep } from "../hooks/useAction";
import { useProject } from "../state/ProjectContext";
import { useCommandLog } from "../state/CommandLogContext";
import { ModuleHelp, ConfirmButton, Modal } from "../components/Common";

type ConfigScope = "project" | "global";
type TabId = "overview" | "settings" | "files";

interface ConfigContext {
  talos_home: string;
  global_config_path: string | null;
  global_exists: boolean;
  project_id: string | null;
  project_config_path: string | null;
  project_exists: boolean;
  project_bound: boolean;
  precedence: string[];
  sections: string[];
}

interface SettingRow {
  key: string;
  section: string;
  label: string;
  type: string;
  description: string;
  unit?: string | null;
  minimum?: number | null;
  default?: unknown;
  effective_value: unknown;
  source: string;
}

interface SectionCard {
  section: string;
  label: string;
  summary: string;
  source: string;
}

interface EffectivePayload {
  values: Record<string, unknown>;
  sources: Record<string, string>;
  global_path?: string | null;
  project_path?: string | null;
  source_counts: Record<string, number>;
  section_cards: SectionCard[];
}

const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "settings", label: "Settings" },
  { id: "files", label: "Files" },
];

const SECTION_FILTERS = [
  { id: "all", label: "All" },
  { id: "proxy", label: "Proxy" },
  { id: "capture", label: "Capture" },
  { id: "scheduler", label: "Scheduler" },
  { id: "attack", label: "Attack" },
  { id: "http", label: "HTTP" },
  { id: "parameter_intel", label: "Parameter intel" },
  { id: "url_sink", label: "URL Sink" },
  { id: "burp", label: "Burp Suite" },
];

/** Complex keys managed on dedicated workspaces (not generic leaf table). */
const COMPLEX_SETTING_KEYS = new Set([
  "http.rules",
  "proxy.platform_auth.entries",
]);

const SOURCE_BADGE: Record<string, string> = {
  default: "badge-ghost",
  global: "badge-info",
  legacy: "badge-warning",
  project: "badge-primary",
  cli: "badge-secondary",
};

function SourceBadge({ source }: { source: string }) {
  const s = (source || "default").toLowerCase();
  const cls = SOURCE_BADGE[s] || "badge-ghost";
  return (
    <span className={`badge badge-sm ${cls} uppercase tracking-wide font-medium`}>
      {s}
    </span>
  );
}

function formatValue(value: unknown): string {
  if (value === null || value === undefined) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "object") {
    try {
      return JSON.stringify(value);
    } catch {
      return String(value);
    }
  }
  return String(value);
}

function parseEditorValue(raw: string, type: string): unknown {
  const trimmed = raw.trim();
  if (type === "bool") {
    const lower = trimmed.toLowerCase();
    if (["true", "yes", "on", "1"].includes(lower)) return true;
    if (["false", "no", "off", "0"].includes(lower)) return false;
    return trimmed;
  }
  if (type === "int") {
    const n = Number.parseInt(trimmed, 10);
    if (Number.isNaN(n)) throw new Error("Expected an integer");
    return n;
  }
  if (type === "float") {
    const n = Number.parseFloat(trimmed);
    if (Number.isNaN(n)) throw new Error("Expected a number");
    return n;
  }
  if (type === "nullable_string") {
    if (trimmed === "" || trimmed.toLowerCase() === "null") return null;
    return trimmed;
  }
  if (type === "string_list" || type === "string_map") {
    if (!trimmed) return type === "string_list" ? [] : {};
    return JSON.parse(trimmed);
  }
  return trimmed;
}

export default function TalosConfig() {
  const { selected } = useProject();
  const { log } = useCommandLog();
  const [searchParams, setSearchParams] = useSearchParams();

  const tabParam = (searchParams.get("tab") as TabId) || "overview";
  const sectionParam = searchParams.get("section") || "all";
  const scopeParam = (searchParams.get("scope") as ConfigScope) || "project";

  const tab: TabId = TABS.some((t) => t.id === tabParam) ? tabParam : "overview";
  const sectionFilter = SECTION_FILTERS.some((s) => s.id === sectionParam)
    ? sectionParam
    : "all";
  const scope: ConfigScope =
    scopeParam === "global" || scopeParam === "project" ? scopeParam : "project";

  const [ctx, setCtx] = useState<ConfigContext | null>(null);
  const [effective, setEffective] = useState<EffectivePayload | null>(null);
  const [settings, setSettings] = useState<SettingRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [editRow, setEditRow] = useState<SettingRow | null>(null);
  const [editRaw, setEditRaw] = useState("");
  const [editError, setEditError] = useState<string | null>(null);

  // Header rules local draft (full leaf replacement)
  const projectId = selected?.id;
  const canUseProjectScope = Boolean(projectId);

  // If project scope selected but no project, force global for display.
  const effectiveScope: ConfigScope =
    scope === "project" && !canUseProjectScope ? "global" : scope;

  const setTab = (id: TabId) => {
    const next = new URLSearchParams(searchParams);
    next.set("tab", id);
    setSearchParams(next, { replace: true });
  };

  const setScope = (s: ConfigScope) => {
    const next = new URLSearchParams(searchParams);
    next.set("scope", s);
    setSearchParams(next, { replace: true });
  };

  const setSection = (s: string) => {
    const next = new URLSearchParams(searchParams);
    next.set("section", s);
    next.set("tab", "settings");
    setSearchParams(next, { replace: true });
  };

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const params: Record<string, string> = {};
      if (projectId) params.project_id = projectId;

      const [c, eff, sets] = await Promise.all([
        api.get<ConfigContext>("/api/configuration/context", params),
        api.get<EffectivePayload>("/api/configuration/effective", params),
        api.get<{ settings: SettingRow[] }>("/api/configuration/settings", params),
      ]);
      setCtx(c);
      setEffective(eff);
      setSettings(sets.settings || []);
    } catch (e: unknown) {
      const msg =
        e && typeof e === "object" && "body" in e
          ? String((e as { body?: { detail?: string } }).body?.detail || "Failed to load configuration")
          : "Failed to load configuration";
      setError(msg);
    } finally {
      setLoading(false);
    }
  }, [projectId]);

  useEffect(() => {
    void load();
  }, [load]);

  // Deep-link ?section=scheduler opens Settings filtered to that section.
  useEffect(() => {
    if (searchParams.get("section") && tab === "overview" && !searchParams.get("tab")) {
      setTab("settings");
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const setValue = useAction(
    "Set configuration",
    (key: string, value: unknown, sc: ConfigScope) =>
      api.post(
        "/api/configuration/value",
        { key, value, scope: sc },
        sc === "project" && projectId ? { project_id: projectId } : undefined
      )
  );

  const unsetValue = useAction(
    "Remove override",
    (key: string, sc: ConfigScope) =>
      api.post(
        "/api/configuration/unset",
        { key, scope: sc },
        sc === "project" && projectId ? { project_id: projectId } : undefined
      )
  );

  const openDir = useAction(
    "Open config directory",
    (target: "global_config" | "project_config") =>
      api
        .post(
          "/api/configuration/open-directory",
          { target },
          projectId ? { project_id: projectId } : undefined
        )
        .then((r) => ({
          steps: [
            {
              cmd: [],
              cmd_str: `open ${target}`,
              stdout: (r as { message?: string }).message || "Opened",
              stderr: "",
              exit_code: 0,
              duration_ms: 0,
              ok: true,
            },
          ],
        }))
  );

  const filteredSettings = useMemo(() => {
    return settings.filter((row) => {
      if (COMPLEX_SETTING_KEYS.has(row.key)) return false;
      if (sectionFilter !== "all" && row.section !== sectionFilter) return false;
      return true;
    });
  }, [settings, sectionFilter]);

  const openEdit = (row: SettingRow) => {
    setEditRow(row);
    setEditError(null);
    if (row.type === "string_list" || row.type === "string_map") {
      setEditRaw(JSON.stringify(row.effective_value ?? (row.type === "string_list" ? [] : {}), null, 2));
    } else if (row.effective_value === null || row.effective_value === undefined) {
      setEditRaw("");
    } else {
      setEditRaw(String(row.effective_value));
    }
  };

  const saveEdit = async () => {
    if (!editRow) return;
    setEditError(null);
    try {
      let value: unknown;
      if (editRow.type === "bool") {
        value = parseEditorValue(editRaw, "bool");
      } else {
        value = parseEditorValue(editRaw, editRow.type);
      }
      await setValue.run(editRow.key, value, effectiveScope);
      setEditRow(null);
      await load();
    } catch (e: unknown) {
      setEditError(e instanceof Error ? e.message : "Invalid value");
    }
  };

  const copyPath = async (path: string) => {
    try {
      await navigator.clipboard.writeText(path);
      log("Copy path", [feedbackStep("clipboard", true, path)]);
    } catch {
      log("Copy path", [feedbackStep("clipboard", false, "Clipboard unavailable")]);
    }
  };

  const copyJson = async () => {
    if (!effective) return;
    const text = JSON.stringify(
      { values: effective.values, sources: effective.sources },
      null,
      2
    );
    try {
      await navigator.clipboard.writeText(text);
      log("Copy effective JSON", [feedbackStep("clipboard", true, "Copied effective config JSON")]);
    } catch {
      log("Copy effective JSON", [feedbackStep("clipboard", false, "Clipboard unavailable")]);
    }
  };

  const headerSource = (key: string) =>
    (effective?.sources?.[key] || "default").toLowerCase();

  return (
    <div className="max-w-6xl">
      <div className="flex flex-wrap items-start justify-between gap-3 mb-2">
        <div>
          <h1 className="text-xl font-semibold">Talos Configuration</h1>
          <p className="text-sm text-base-content/60 mt-0.5 max-w-2xl">
            Manage Talos runtime and execution configuration across global and project layers.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <div className="join border border-base-300 rounded-lg overflow-hidden">
            <button
              type="button"
              className={`btn btn-sm join-item ${
                effectiveScope === "project" ? "btn-primary" : "btn-ghost"
              }`}
              disabled={!canUseProjectScope}
              onClick={() => setScope("project")}
            >
              Project{selected ? `: ${selected.name}` : ""}
            </button>
            <button
              type="button"
              className={`btn btn-sm join-item ${
                effectiveScope === "global" ? "btn-primary" : "btn-ghost"
              }`}
              onClick={() => setScope("global")}
            >
              Global
            </button>
          </div>
          <button className="btn btn-sm btn-ghost" onClick={() => void load()} disabled={loading}>
            {loading ? <span className="loading loading-spinner loading-xs" /> : "Refresh"}
          </button>
        </div>
      </div>

      <ModuleHelp title="How layered configuration works">
        <p className="mb-2">
          Effective values merge{" "}
          <span className="mono">defaults → global → legacy → project → CLI</span>. Setting a
          value writes an override at the active scope (Project or Global).{" "}
          <strong>Remove override</strong> deletes that layer so inheritance resumes — it does not
          always restore the built-in default (global may still apply).
        </p>
        <p>
          Drop-header lists replace the entire leaf when overridden (they are not item-merged).
          HTTP request/response rules live on the{" "}
          <Link className="link link-primary" to="/mutations">
            HTTP Rules
          </Link>{" "}
          workspace and are managed via <span className="mono">talos config http</span>. Master
          switch: <span className="mono">http.enabled</span>.
        </p>
      </ModuleHelp>

      {scope === "project" && !canUseProjectScope && (
        <div className="alert alert-info text-sm mt-3 mb-2">
          <span>
            No project selected — showing global/default effective configuration. Select a project
            in the header to manage project overrides, or switch to Global.
          </span>
        </div>
      )}

      {error && (
        <div className="alert alert-error text-sm mt-3 mb-2">
          <span>{error}</span>
        </div>
      )}

      <div className="tabs tabs-boxed bg-base-200/50 p-1 mt-4 mb-4 w-fit flex-wrap">
        {TABS.map((t) => (
          <button
            key={t.id}
            type="button"
            className={`tab ${tab === t.id ? "tab-active" : ""}`}
            onClick={() => setTab(t.id)}
          >
            {t.label}
          </button>
        ))}
      </div>

      {loading && !effective ? (
        <div className="panel p-8 text-center text-base-content/50">
          <span className="loading loading-spinner loading-md" /> Loading configuration…
        </div>
      ) : (
        <>
          {tab === "overview" && (
            <OverviewTab
              ctx={ctx}
              effective={effective}
              selectedName={selected?.name}
              onOpenSection={(s) => setSection(s)}
            />
          )}
          {tab === "settings" && (
            <SettingsTab
              rows={filteredSettings}
              sectionFilter={sectionFilter}
              onSection={setSection}
              scope={effectiveScope}
              onEdit={openEdit}
              onUnset={async (key) => {
                await unsetValue.run(key, effectiveScope);
                await load();
              }}
              running={setValue.running || unsetValue.running}
            />
          )}
          {tab === "files" && (
            <FilesTab
              ctx={ctx}
              effective={effective}
              onCopyPath={copyPath}
              onOpenDir={(t) => void openDir.run(t)}
              openRunning={openDir.running}
              onCopyJson={copyJson}
            />
          )}
        </>
      )}

      <Modal
        open={!!editRow}
        onClose={() => setEditRow(null)}
        title={editRow ? `Edit ${editRow.key}` : "Edit"}
        wide
      >
        {editRow && (
          <div className="space-y-3">
            <div className="text-sm text-base-content/60">{editRow.description}</div>
            <div className="flex flex-wrap gap-2 items-center text-xs">
              <span>
                Scope: <strong className="uppercase">{effectiveScope}</strong>
              </span>
              <SourceBadge source={editRow.source} />
              <span className="mono text-base-content/50">type={editRow.type}</span>
              {editRow.unit && (
                <span className="text-base-content/50">unit={editRow.unit}</span>
              )}
            </div>
            {editRow.type === "bool" ? (
              <div className="flex gap-2">
                <button
                  type="button"
                  className={`btn btn-sm ${editRaw === "true" || editRaw === "True" ? "btn-primary" : ""}`}
                  onClick={() => setEditRaw("true")}
                >
                  true
                </button>
                <button
                  type="button"
                  className={`btn btn-sm ${editRaw === "false" || editRaw === "False" ? "btn-primary" : ""}`}
                  onClick={() => setEditRaw("false")}
                >
                  false
                </button>
              </div>
            ) : (
              <textarea
                className="textarea textarea-bordered mono w-full text-sm min-h-[6rem]"
                value={editRaw}
                onChange={(e) => setEditRaw(e.target.value)}
                placeholder={
                  editRow.type === "string_list"
                    ? '["Header-A", "Header-B"]'
                    : editRow.type === "string_map"
                      ? '{"X-Name": "value"}'
                      : ""
                }
              />
            )}
            {editError && <div className="text-error text-sm">{editError}</div>}
            <div className="flex justify-end gap-2">
              <button type="button" className="btn btn-sm" onClick={() => setEditRow(null)}>
                Cancel
              </button>
              <button
                type="button"
                className="btn btn-sm btn-primary"
                disabled={setValue.running}
                onClick={() => void saveEdit()}
              >
                {setValue.running ? (
                  <span className="loading loading-spinner loading-xs" />
                ) : effectiveScope === "global" ? (
                  "Set global"
                ) : (
                  "Set project override"
                )}
              </button>
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
}

function OverviewTab({
  ctx,
  effective,
  selectedName,
  onOpenSection,
}: {
  ctx: ConfigContext | null;
  effective: EffectivePayload | null;
  selectedName?: string;
  onOpenSection: (section: string) => void;
}) {
  const counts = effective?.source_counts || {};
  return (
    <div className="space-y-6">
      <div className="panel p-4">
        <h2 className="font-semibold mb-3">Configuration context</h2>
        <dl className="grid grid-cols-1 md:grid-cols-2 gap-x-8 gap-y-2 text-sm">
          <div>
            <dt className="text-xs text-base-content/50">Talos home</dt>
            <dd className="mono break-all">{ctx?.talos_home || "—"}</dd>
          </div>
          <div>
            <dt className="text-xs text-base-content/50">Global config</dt>
            <dd className="mono break-all">
              {ctx?.global_config_path || "—"}
              <span className="text-base-content/40 ml-2">
                {ctx?.global_exists ? "(present)" : "(not created)"}
              </span>
            </dd>
          </div>
          <div>
            <dt className="text-xs text-base-content/50">Selected project</dt>
            <dd>{selectedName || ctx?.project_id || "—"}</dd>
          </div>
          <div>
            <dt className="text-xs text-base-content/50">Project config</dt>
            <dd className="mono break-all">
              {ctx?.project_config_path || "—"}
              {ctx?.project_config_path && (
                <span className="text-base-content/40 ml-2">
                  {ctx.project_exists ? "(present)" : "(not created)"}
                </span>
              )}
            </dd>
          </div>
        </dl>
      </div>

      <div className="panel p-4">
        <h2 className="font-semibold mb-3">Inheritance</h2>
        <div className="flex flex-col sm:flex-row sm:items-center gap-2 sm:gap-1 text-sm mono mb-4">
          {(
            [
              ["DEFAULT", counts.default ?? 0],
              ["GLOBAL", counts.global ?? 0],
              ["LEGACY", counts.legacy ?? 0],
              ["PROJECT", counts.project ?? 0],
              ["CLI", counts.cli ?? 0],
            ] as const
          ).map(([label, n], i, arr) => (
            <div key={label} className="flex items-center gap-1">
              <div className="rounded-md border border-base-300 bg-base-200/40 px-3 py-2 text-center min-w-[5.5rem]">
                <div className="text-[10px] uppercase tracking-wider text-base-content/50">
                  {label}
                </div>
                <div className="font-semibold">{n}</div>
                <div className="text-[10px] text-base-content/40">values</div>
              </div>
              {i < arr.length - 1 && (
                <span className="hidden sm:inline text-base-content/30 px-1">↓</span>
              )}
            </div>
          ))}
        </div>
        <p className="text-xs text-base-content/50">
          Built-in defaults → global <span className="mono">config.yaml</span> → legacy project
          stores → <span className="mono">project.yaml</span> → CLI one-shot overrides → effective.
        </p>
      </div>

      <div>
        <h2 className="font-semibold mb-3">Sections</h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
          {(effective?.section_cards || []).map((card) => (
            <button
              key={card.section}
              type="button"
              className="panel p-4 text-left hover:border-primary/40 transition-colors"
              onClick={() => onOpenSection(card.section)}
            >
              <div className="flex items-center justify-between mb-1">
                <span className="font-medium">{card.label}</span>
                <SourceBadge source={card.source} />
              </div>
              <div className="text-sm text-base-content/70">{card.summary}</div>
              <div className="text-[11px] text-primary mt-2">Open in Settings →</div>
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}

function SettingsTab({
  rows,
  sectionFilter,
  onSection,
  scope,
  onEdit,
  onUnset,
  running,
}: {
  rows: SettingRow[];
  sectionFilter: string;
  onSection: (s: string) => void;
  scope: ConfigScope;
  onEdit: (row: SettingRow) => void;
  onUnset: (key: string) => Promise<void>;
  running: boolean;
}) {
  return (
    <div className="flex flex-col md:flex-row gap-4">
      <aside className="md:w-40 shrink-0">
        <div className="panel p-2 sticky top-2">
          {SECTION_FILTERS.map((s) => (
            <button
              key={s.id}
              type="button"
              className={`btn btn-sm btn-ghost w-full justify-start mb-0.5 ${
                sectionFilter === s.id ? "btn-active bg-primary/10 text-primary" : ""
              }`}
              onClick={() => onSection(s.id)}
            >
              {s.label}
            </button>
          ))}
        </div>
      </aside>

      <div className="flex-1 min-w-0 panel overflow-x-auto">
        <table className="table table-sm table-tight w-full">
          <thead>
            <tr>
              <th>Setting</th>
              <th>Effective</th>
              <th>Source</th>
              <th className="text-right">Actions</th>
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 && (
              <tr>
                <td colSpan={4} className="text-center text-base-content/50 py-8">
                  No settings in this filter.
                </td>
              </tr>
            )}
            {rows.map((row) => {
              const src = (row.source || "default").toLowerCase();
              const canRemove =
                (scope === "project" && src === "project") ||
                (scope === "global" && src === "global");
              const overrideLabel =
                scope === "global"
                  ? src === "global"
                    ? "Edit global"
                    : "Set global"
                  : src === "project"
                    ? "Edit"
                    : "Override for project";

              return (
                <tr key={row.key} className="hover">
                  <td>
                    <div className="mono text-xs font-medium">{row.key}</div>
                    <div className="text-[11px] text-base-content/50 max-w-xs">
                      {row.label}
                      {row.unit ? ` · ${row.unit}` : ""}
                    </div>
                  </td>
                  <td>
                    <span className="mono text-xs break-all">
                      {formatValue(row.effective_value)}
                    </span>
                  </td>
                  <td>
                    <SourceBadge source={src} />
                  </td>
                  <td className="text-right whitespace-nowrap">
                    <button
                      type="button"
                      className="btn btn-xs btn-ghost"
                      disabled={running}
                      onClick={() => onEdit(row)}
                    >
                      {overrideLabel}
                    </button>
                    {canRemove && (
                      <ConfirmButton
                        className="btn btn-xs btn-ghost text-warning"
                        confirmText="Remove override?"
                        onConfirm={() => onUnset(row.key)}
                      >
                        {scope === "global" ? "Remove global" : "Remove override"}
                      </ConfirmButton>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
        <div className="px-3 py-2 text-[11px] text-base-content/45 border-t border-base-300">
          HTTP rules are managed on the{" "}
          <Link className="link link-primary" to="/mutations">
            HTTP Rules
          </Link>{" "}
          workspace (<span className="mono">talos config http</span>). Scalar writes use{" "}
          <span className="mono">
            talos config set/unset{scope === "global" ? " --global" : ""}
          </span>
          .
        </div>
      </div>
    </div>
  );
}


function FilesTab({
  ctx,
  effective,
  onCopyPath,
  onOpenDir,
  openRunning,
  onCopyJson,
}: {
  ctx: ConfigContext | null;
  effective: EffectivePayload | null;
  onCopyPath: (path: string) => void;
  onOpenDir: (t: "global_config" | "project_config") => void;
  openRunning: boolean;
  onCopyJson: () => void;
}) {
  const [showJson, setShowJson] = useState(false);
  const jsonText = effective
    ? JSON.stringify(
        {
          values: effective.values,
          sources: effective.sources,
          global_path: effective.global_path,
          project_path: effective.project_path,
        },
        null,
        2
      )
    : "";

  return (
    <div className="space-y-4">
      <div className="panel p-4">
        <h2 className="font-semibold mb-3">Global configuration</h2>
        <div className="mono text-sm break-all bg-base-200/40 rounded px-3 py-2 mb-3">
          {ctx?.global_config_path || "—"}
          <span className="text-base-content/40 ml-2">
            {ctx?.global_exists ? "(present)" : "(not created yet)"}
          </span>
        </div>
        <div className="flex flex-wrap gap-2">
          {ctx?.global_config_path && (
            <button
              type="button"
              className="btn btn-sm"
              onClick={() => onCopyPath(ctx.global_config_path!)}
            >
              Copy path
            </button>
          )}
          <button
            type="button"
            className="btn btn-sm"
            disabled={openRunning || !ctx?.global_config_path}
            onClick={() => onOpenDir("global_config")}
          >
            Open directory
          </button>
        </div>
        <p className="text-xs text-base-content/50 mt-3">
          Raw YAML editing is intentionally omitted in the Control Panel. Use typed Settings, or{" "}
          <span className="mono">talos config edit --global</span> in a terminal.
        </p>
      </div>

      <div className="panel p-4">
        <h2 className="font-semibold mb-3">Project configuration</h2>
        <div className="mono text-sm break-all bg-base-200/40 rounded px-3 py-2 mb-3">
          {ctx?.project_config_path || "(no project bound)"}
          {ctx?.project_config_path && (
            <span className="text-base-content/40 ml-2">
              {ctx.project_exists ? "(present)" : "(not created yet)"}
            </span>
          )}
        </div>
        <div className="flex flex-wrap gap-2">
          {ctx?.project_config_path && (
            <button
              type="button"
              className="btn btn-sm"
              onClick={() => onCopyPath(ctx.project_config_path!)}
            >
              Copy path
            </button>
          )}
          <button
            type="button"
            className="btn btn-sm"
            disabled={openRunning || !ctx?.project_config_path}
            onClick={() => onOpenDir("project_config")}
          >
            Open directory
          </button>
        </div>
      </div>

      <div className="panel p-4">
        <div className="flex items-center justify-between mb-3">
          <h2 className="font-semibold">Effective configuration</h2>
          <div className="flex gap-2">
            <button type="button" className="btn btn-sm" onClick={() => setShowJson((v) => !v)}>
              {showJson ? "Hide JSON" : "View JSON"}
            </button>
            <button type="button" className="btn btn-sm" onClick={onCopyJson}>
              Copy JSON
            </button>
          </div>
        </div>
        {showJson ? (
          <pre className="mono text-xs bg-base-200/50 rounded p-3 overflow-auto max-h-96 whitespace-pre-wrap">
            {jsonText}
          </pre>
        ) : (
          <div className="overflow-x-auto">
            <table className="table table-xs table-tight w-full">
              <thead>
                <tr>
                  <th>Key</th>
                  <th>Value</th>
                  <th>Source</th>
                </tr>
              </thead>
              <tbody>
                {Object.entries(effective?.values || {}).map(([key, val]) => (
                  <tr key={key}>
                    <td className="mono text-xs">{key}</td>
                    <td className="mono text-xs break-all max-w-md">
                      {formatValue(val)}
                    </td>
                    <td>
                      <SourceBadge source={effective?.sources?.[key] || "default"} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
