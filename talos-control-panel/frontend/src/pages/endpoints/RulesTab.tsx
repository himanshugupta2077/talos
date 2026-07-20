import { useCallback, useEffect, useState } from "react";
import { api } from "../../api/client";
import DataTable, { Column } from "../../components/DataTable";
import SideDrawer from "../../components/SideDrawer";
import { UuidChip } from "../../components/Common";
import { useAction } from "../../hooks/useAction";
import { BulkMutationResult, PolicyRule } from "../../types";
import { formatRelativeAge, PRIORITIES, selectClass, inputClass } from "./shared";

interface PreviewResult {
  pattern: string;
  matching_count: number;
  current?: {
    total?: number;
    by_priority?: Record<string, number>;
    excluded?: number;
  };
  proposed?: {
    priority?: string | null;
    excluded?: boolean | null;
    newly_excluded?: number;
    already_excluded?: number;
    priority_changes?: number;
  };
  endpoints?: {
    id: string;
    method: string;
    path: string;
    origin?: string;
    effective_level?: string;
    excluded?: boolean;
  }[];
}

export default function RulesTab({
  projectId,
  focusRuleId,
  seedPattern,
  onConsumedSeed,
}: {
  projectId: string;
  focusRuleId?: string | null;
  seedPattern?: string | null;
  onConsumedSeed?: () => void;
}) {
  const [rules, setRules] = useState<PolicyRule[]>([]);
  const [loading, setLoading] = useState(false);
  const [selectedId, setSelectedId] = useState<string | null>(focusRuleId || null);
  const [drawer, setDrawer] = useState<"create" | "edit" | null>(null);
  const [editRule, setEditRule] = useState<PolicyRule | null>(null);

  // Form state
  const [pattern, setPattern] = useState("");
  const [priority, setPriority] = useState("");
  const [exclusion, setExclusion] = useState<"none" | "include" | "exclude">("none");
  const [preview, setPreview] = useState<PreviewResult | null>(null);
  const [previewLoading, setPreviewLoading] = useState(false);

  const load = useCallback(() => {
    setLoading(true);
    api
      .get<{ rules: PolicyRule[] }>("/api/endpoints/rules", { project_id: projectId })
      .then((r) => setRules(r.rules))
      .finally(() => setLoading(false));
  }, [projectId]);

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    if (focusRuleId) setSelectedId(focusRuleId);
  }, [focusRuleId]);

  useEffect(() => {
    if (seedPattern) {
      setDrawer("create");
      setEditRule(null);
      setPattern(seedPattern);
      setPriority("HIGH");
      setExclusion("none");
      onConsumedSeed?.();
    }
  }, [seedPattern, onConsumedSeed]);

  const mutate = useAction("Endpoint rule", (path: string, body?: object, method: "post" | "del" = "post") => {
    if (method === "del") {
      return api.del<BulkMutationResult>(path, { project_id: projectId });
    }
    return api.post<BulkMutationResult>(path, body ?? {}, { project_id: projectId });
  });

  const runPreview = useCallback(async () => {
    if (!pattern.trim()) {
      setPreview(null);
      return;
    }
    setPreviewLoading(true);
    try {
      const res = await api.post<PreviewResult>(
        "/api/endpoints/rules/preview",
        {
          pattern: pattern.trim(),
          priority: priority || null,
          exclude: exclusion === "exclude",
        },
        { project_id: projectId }
      );
      setPreview(res);
    } catch {
      setPreview(null);
    } finally {
      setPreviewLoading(false);
    }
  }, [pattern, priority, exclusion, projectId]);

  useEffect(() => {
    if (drawer !== "create" && drawer !== "edit") return;
    const t = setTimeout(runPreview, 350);
    return () => clearTimeout(t);
  }, [drawer, runPreview]);

  const openCreate = () => {
    setEditRule(null);
    setPattern("");
    setPriority("HIGH");
    setExclusion("none");
    setPreview(null);
    setDrawer("create");
  };

  const openEdit = (rule: PolicyRule) => {
    setEditRule(rule);
    setPattern(rule.pattern);
    setPriority(rule.priority || "");
    setExclusion(rule.excluded ? "exclude" : "none");
    setPreview(null);
    setDrawer("edit");
    setSelectedId(rule.id);
  };

  const columns: Column<PolicyRule>[] = [
    {
      key: "pattern",
      header: "Pattern",
      className: "mono text-xs",
      render: (r) => (
        <div>
          <div className="mono text-xs font-medium">{r.pattern}</div>
          <div className="text-[10px] text-base-content/40">
            <UuidChip value={r.id} />
          </div>
        </div>
      ),
    },
    {
      key: "priority",
      header: "Priority",
      render: (r) =>
        r.priority ? (
          <span className="badge badge-sm badge-outline">{r.priority}</span>
        ) : (
          <span className="text-base-content/40">—</span>
        ),
    },
    {
      key: "exclusion",
      header: "Exclusion",
      render: (r) =>
        r.excluded ? (
          <span className="badge badge-ghost badge-xs">EXCLUDE</span>
        ) : (
          <span className="text-base-content/40">—</span>
        ),
    },
    {
      key: "matches",
      header: "Matches",
      sortValue: (r) => r.matches ?? 0,
      render: (r) => (
        <div className="text-xs">
          <div className="tabular-nums font-medium">{r.matches ?? 0}</div>
          {(r.multi_rule_matches ?? 0) > 0 && (
            <div className="text-warning text-[10px]">
              {r.multi_rule_matches} also match another rule
            </div>
          )}
        </div>
      ),
    },
    {
      key: "effect",
      header: "Effect",
      render: (r) => {
        const parts: string[] = [];
        if (r.priority_changes) parts.push(`${r.priority_changes} priority changes`);
        if (r.newly_excluded) parts.push(`${r.newly_excluded} excluded`);
        if (!parts.length && r.effect) parts.push(r.effect);
        return <span className="text-xs">{parts.join(" · ") || "—"}</span>;
      },
    },
    {
      key: "created_at",
      header: "Updated",
      render: (r) => (
        <span className="text-xs">
          {formatRelativeAge(r.created_at)}
        </span>
      ),
    },
    {
      key: "actions",
      header: "",
      sortable: false,
      alwaysVisible: true,
      render: (r) => (
        <div className="flex gap-1" onClick={(e) => e.stopPropagation()}>
          <button className="btn btn-xs btn-ghost" onClick={() => openEdit(r)}>
            Edit
          </button>
          <button
            className="btn btn-xs btn-ghost text-error"
            onClick={async () => {
              if (!confirm(`Delete rule ${r.pattern}?`)) return;
              await mutate.run(`/api/endpoints/rules/${r.id}`, undefined, "del");
              load();
            }}
          >
            Delete
          </button>
        </div>
      ),
    },
  ];

  const selected = rules.find((r) => r.id === selectedId);

  return (
    <div>
      <div className="flex items-center justify-between mb-3">
        <p className="text-sm text-base-content/60 max-w-xl">
          Path-level policy configuration. Rules are the canonical resource
          (<span className="mono text-xs"> talos endpoint rule </span>
          ). Preview uses the same matcher as live policy.
        </p>
        <button className="btn btn-sm btn-primary" onClick={openCreate}>
          Create rule
        </button>
      </div>

      <DataTable
        columns={columns}
        rows={rules}
        rowKey={(r) => r.id}
        loading={loading}
        storageKey="endpoints-rules"
        onRowClick={(r) => {
          setSelectedId(r.id);
          openEdit(r);
        }}
        rowClassName={(r) => (r.id === selectedId ? "bg-primary/5" : "")}
        emptyLabel="No path rules yet. Create one to control priority or exclusion for path patterns."
      />

      {selected && (
        <div className="panel p-3 mt-3 text-sm">
          <div className="font-medium mono">{selected.pattern}</div>
          <div className="text-xs text-base-content/60 mt-1">
            {selected.matches ?? 0} matches
            {(selected.multi_rule_matches ?? 0) > 0 && (
              <> · {selected.multi_rule_matches} also match another policy rule</>
            )}
          </div>
          <div className="text-xs mt-1">
            Effective decisions come from core resolution (manual → rule → auto).
            The UI does not re-order rule precedence in React.
          </div>
        </div>
      )}

      <SideDrawer
        open={drawer !== null}
        onClose={() => setDrawer(null)}
        title={drawer === "edit" ? "Edit endpoint rule" : "Create endpoint rule"}
        wide
      >
        <div className="space-y-4">
          {drawer === "edit" && editRule && (
            <div className="text-xs panel p-2 bg-base-200/40">
              <div className="text-base-content/50">Current rule</div>
              <div className="mono">
                {editRule.pattern} → {editRule.priority || "—"}
                {editRule.excluded ? " · EXCLUDE" : ""}
              </div>
            </div>
          )}

          <label className="form-control">
            <span className="label-text text-xs">Path pattern</span>
            <input
              className={`${inputClass} mono w-full`}
              value={pattern}
              onChange={(e) => setPattern(e.target.value)}
              placeholder="/api/admin/*"
              disabled={drawer === "edit"}
            />
            {drawer === "edit" && (
              <span className="label-text-alt text-base-content/50">
                Pattern is immutable; delete and recreate to change it.
              </span>
            )}
          </label>

          <label className="form-control">
            <span className="label-text text-xs">Priority</span>
            <select
              className={selectClass}
              value={priority}
              onChange={(e) => setPriority(e.target.value)}
            >
              <option value="">No priority override</option>
              {PRIORITIES.map((p) => (
                <option key={p} value={p}>{p}</option>
              ))}
            </select>
          </label>

          <label className="form-control">
            <span className="label-text text-xs">Exclusion</span>
            <select
              className={selectClass}
              value={exclusion}
              onChange={(e) => setExclusion(e.target.value as typeof exclusion)}
            >
              <option value="none">No override / Included</option>
              <option value="exclude">Excluded</option>
              {drawer === "edit" && <option value="include">Clear exclusion (include)</option>}
            </select>
          </label>

          <div className="panel p-3">
            <div className="text-[10px] uppercase tracking-wide text-base-content/50 font-semibold mb-2">
              Live impact preview
            </div>
            {previewLoading && <span className="loading loading-spinner loading-xs" />}
            {preview && !previewLoading && (
              <div className="text-sm space-y-2">
                <div className="font-semibold tabular-nums">
                  {preview.matching_count} endpoints match
                </div>
                {(priority || exclusion === "exclude") && (
                  <div className="text-xs space-y-1">
                    <div className="text-base-content/50">Current → Proposed</div>
                    {preview.proposed?.priority_changes != null && (
                      <div>
                        Priority changes:{" "}
                        <strong>{preview.proposed.priority_changes}</strong>
                      </div>
                    )}
                    {exclusion === "exclude" && (
                      <div>
                        Newly excluded:{" "}
                        <strong>{preview.proposed?.newly_excluded ?? 0}</strong>
                        {" · "}
                        Already excluded:{" "}
                        <strong>{preview.proposed?.already_excluded ?? 0}</strong>
                      </div>
                    )}
                  </div>
                )}
                <div className="text-xs max-h-48 overflow-y-auto">
                  <div className="text-base-content/50 mb-1">Affected endpoints</div>
                  {(preview.endpoints || []).slice(0, 40).map((ep) => (
                    <div key={ep.id} className="mono py-0.5 flex gap-2">
                      <span className="badge badge-ghost badge-xs">{ep.method}</span>
                      <span className="truncate">{ep.path}</span>
                      <span className="text-base-content/40 ml-auto">
                        {ep.effective_level}
                      </span>
                    </div>
                  ))}
                  {(preview.endpoints?.length || 0) > 40 && (
                    <div className="text-base-content/40">
                      …and {(preview.endpoints?.length || 0) - 40} more
                    </div>
                  )}
                </div>
              </div>
            )}
            {!preview && !previewLoading && (
              <div className="text-xs text-base-content/50">
                Enter a pattern to preview impact via Talos core.
              </div>
            )}
          </div>

          <div className="flex justify-end gap-2 pt-2">
            <button className="btn btn-sm" onClick={() => setDrawer(null)}>
              Cancel
            </button>
            {drawer === "create" ? (
              <button
                className="btn btn-sm btn-primary"
                disabled={!pattern.trim() || (!priority && exclusion !== "exclude")}
                onClick={async () => {
                  await mutate.run("/api/endpoints/rules", {
                    pattern: pattern.trim(),
                    priority: priority || null,
                    exclude: exclusion === "exclude",
                  });
                  setDrawer(null);
                  load();
                }}
              >
                Create rule
              </button>
            ) : (
              <button
                className="btn btn-sm btn-primary"
                onClick={async () => {
                  if (!editRule) return;
                  const body: Record<string, unknown> = {};
                  if (priority) body.priority = priority;
                  else body.clear_priority = true;
                  if (exclusion === "exclude") body.exclude = true;
                  else if (exclusion === "include" || exclusion === "none") {
                    body.exclude = false;
                  }
                  await mutate.run(`/api/endpoints/rules/${editRule.id}`, body);
                  setDrawer(null);
                  load();
                }}
              >
                Update rule
              </button>
            )}
          </div>
        </div>
      </SideDrawer>
    </div>
  );
}
