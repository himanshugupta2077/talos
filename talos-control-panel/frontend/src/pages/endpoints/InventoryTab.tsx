import { useCallback, useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../../api/client";
import DataTable, { Column } from "../../components/DataTable";
import SideDrawer from "../../components/SideDrawer";
import PolicyExplain from "../../components/PolicyExplain";
import { useAction } from "../../hooks/useAction";
import {
  BulkMutationResult,
  EndpointInventorySummary,
  EndpointPolicyExplanation,
  EndpointRow,
} from "../../types";
import {
  BulkResultBanner,
  EndpointFilters,
  EndpointLabel,
  EMPTY_FILTERS,
  FilterBar,
  FilterState,
  filtersToParams,
  formatRelativeAge,
  PAGE_SIZE,
  PrioritySourceBadge,
  PRIORITIES,
  RolesCell,
  StateBadge,
  SummaryChip,
  suggestPathPattern,
} from "./shared";

export default function InventoryTab({
  projectId,
  filterOptions,
  initialFilters,
  onOpenRules,
  onCreateRuleFromSelection,
}: {
  projectId: string;
  filterOptions: EndpointFilters;
  initialFilters?: Partial<FilterState>;
  onOpenRules: (ruleId?: string) => void;
  onCreateRuleFromSelection: (pattern: string, paths: string[]) => void;
}) {
  const navigate = useNavigate();
  const [filters, setFilters] = useState<FilterState>({
    ...EMPTY_FILTERS,
    ...initialFilters,
  });
  const [rows, setRows] = useState<EndpointRow[]>([]);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [loading, setLoading] = useState(false);
  const [summary, setSummary] = useState<EndpointInventorySummary | null>(null);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [selectAllMatching, setSelectAllMatching] = useState(false);
  const [matchingIds, setMatchingIds] = useState<string[]>([]);
  const [menuId, setMenuId] = useState<string | null>(null);
  const [bulkResult, setBulkResult] = useState<BulkMutationResult | null>(null);
  const [explainId, setExplainId] = useState<string | null>(null);
  const [explain, setExplain] = useState<EndpointPolicyExplanation | null>(null);
  const [tagInput, setTagInput] = useState("");
  const [showTagPrompt, setShowTagPrompt] = useState<"add" | "remove" | null>(null);

  const load = useCallback(() => {
    setLoading(true);
    const params = {
      project_id: projectId,
      limit: PAGE_SIZE,
      offset,
      ...filtersToParams(filters),
    };
    Promise.all([
      api.get<{ endpoints: EndpointRow[]; total: number }>("/api/endpoints", params),
      api.get<EndpointInventorySummary>("/api/endpoints/summary", { project_id: projectId }),
    ])
      .then(([list, sum]) => {
        setRows(list.endpoints);
        setTotal(list.total);
        setSummary(sum);
      })
      .finally(() => setLoading(false));
  }, [projectId, offset, filters]);

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    setOffset(0);
    setSelected(new Set());
    setSelectAllMatching(false);
    setMatchingIds([]);
  }, [filters, projectId]);

  useEffect(() => {
    if (initialFilters) setFilters((f) => ({ ...f, ...initialFilters }));
  }, [initialFilters]);

  const patchFilters = (patch: Partial<FilterState>) => {
    if (Object.keys(patch).length > 5 && "search" in patch) {
      // full replace from clear
      setFilters(patch as FilterState);
    } else {
      setFilters((f) => ({ ...f, ...patch }));
    }
  };

  const pageIds = useMemo(() => rows.map((r) => r.id), [rows]);
  const selectedCount = selectAllMatching ? total : selected.size;
  const selectedIds = useMemo(() => {
    if (selectAllMatching) return matchingIds.length ? matchingIds : pageIds;
    return Array.from(selected);
  }, [selectAllMatching, matchingIds, selected, pageIds]);

  const toggleRow = (id: string) => {
    setSelectAllMatching(false);
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const togglePage = () => {
    setSelectAllMatching(false);
    const allOnPage = pageIds.every((id) => selected.has(id));
    setSelected((prev) => {
      const next = new Set(prev);
      if (allOnPage) pageIds.forEach((id) => next.delete(id));
      else pageIds.forEach((id) => next.add(id));
      return next;
    });
  };

  const selectAllMatchingAction = async () => {
    const res = await api.get<{ ids: string[]; total: number }>("/api/endpoints", {
      project_id: projectId,
      ids_only: "1",
      ...filtersToParams(filters),
    });
    setMatchingIds(res.ids);
    setSelectAllMatching(true);
    setSelected(new Set(res.ids));
  };

  const clearSelection = () => {
    setSelected(new Set());
    setSelectAllMatching(false);
    setMatchingIds([]);
  };

  const runBulk = useAction("Endpoint bulk", async (path: string, body: object) => {
    const res = await api.post<BulkMutationResult>(path, body, { project_id: projectId });
    setBulkResult(res);
    return res;
  });

  const afterBulk = async () => {
    clearSelection();
    load();
  };

  const openExplain = async (id: string) => {
    setExplainId(id);
    const data = await api.get<EndpointPolicyExplanation>(`/api/endpoints/${id}/policy`, {
      project_id: projectId,
    });
    setExplain(data);
  };

  const columns: Column<EndpointRow>[] = [
    {
      key: "select",
      header: "",
      sortable: false,
      alwaysVisible: true,
      render: (r) => (
        <input
          type="checkbox"
          className="checkbox checkbox-xs"
          checked={selected.has(r.id)}
          onChange={() => toggleRow(r.id)}
          onClick={(e) => e.stopPropagation()}
        />
      ),
    },
    {
      key: "method",
      header: "Method",
      render: (r) => <span className="badge badge-sm badge-outline mono">{r.method}</span>,
    },
    {
      key: "endpoint",
      header: "Endpoint",
      sortValue: (r) => r.normalized_path,
      render: (r) => <EndpointLabel row={r} />,
    },
    {
      key: "priority",
      header: "Priority",
      sortValue: (r) => r.effective_priority || "",
      render: (r) => (
        <PrioritySourceBadge row={r} onRuleClick={(id) => onOpenRules(id)} />
      ),
    },
    {
      key: "state",
      header: "State",
      render: (r) => <StateBadge state={r.state} />,
    },
    {
      key: "roles",
      header: "Roles",
      render: (r) => <RolesCell roles={r.roles} />,
    },
    {
      key: "parameter_count",
      header: "Params",
      sortValue: (r) => r.parameter_count ?? 0,
    },
    {
      key: "hit_count",
      header: "Hits",
      sortValue: (r) => r.hit_count ?? 0,
    },
    {
      key: "last_seen",
      header: "Last seen",
      sortValue: (r) => r.last_seen || "",
      render: (r) => (
        <span className="text-xs whitespace-nowrap">
          {formatRelativeAge(r.last_seen)}
        </span>
      ),
    },
    {
      key: "actions",
      header: "",
      sortable: false,
      alwaysVisible: true,
      render: (r) => (
        <div className="dropdown dropdown-end" onClick={(e) => e.stopPropagation()}>
          <button
            tabIndex={0}
            className="btn btn-xs btn-ghost"
            onClick={() => setMenuId(menuId === r.id ? null : r.id)}
          >
            ⋮
          </button>
          {menuId === r.id && (
            <ul className="dropdown-content z-30 menu p-2 shadow bg-base-200 rounded-box w-52 border border-base-300 text-sm">
              <li>
                <button onClick={() => { setMenuId(null); navigate(`/endpoints/${r.id}`); }}>
                  View endpoint
                </button>
              </li>
              <li>
                <button onClick={() => { setMenuId(null); openExplain(r.id); }}>
                  Explain policy
                </button>
              </li>
              <li>
                <button
                  onClick={async () => {
                    setMenuId(null);
                    setSelected(new Set([r.id]));
                  }}
                >
                  Set priority…
                </button>
              </li>
              <li>
                <button
                  onClick={async () => {
                    setMenuId(null);
                    await runBulk.run("/api/endpoints/bulk/mark", {
                      endpoint_ids: [r.id],
                      tag: "dangerous",
                    });
                    afterBulk();
                  }}
                >
                  Mark dangerous
                </button>
              </li>
              <li>
                <button
                  onClick={async () => {
                    setMenuId(null);
                    await runBulk.run("/api/endpoints/bulk/mark", {
                      endpoint_ids: [r.id],
                      tag: "logout",
                    });
                    afterBulk();
                  }}
                >
                  Mark logout
                </button>
              </li>
              <li>
                <button
                  onClick={async () => {
                    setMenuId(null);
                    await runBulk.run("/api/endpoints/bulk/exclude", {
                      endpoint_ids: [r.id],
                    });
                    afterBulk();
                  }}
                >
                  Exclude
                </button>
              </li>
              <li>
                <button
                  onClick={async () => {
                    setMenuId(null);
                    await runBulk.run("/api/endpoints/bulk/test", {
                      endpoint_ids: [r.id],
                      action: "replay_now",
                    });
                    afterBulk();
                  }}
                >
                  Replay now
                </button>
              </li>
              <li>
                <button
                  onClick={async () => {
                    setMenuId(null);
                    await runBulk.run("/api/endpoints/bulk/test", {
                      endpoint_ids: [r.id],
                      action: "enqueue_replay",
                    });
                    afterBulk();
                  }}
                >
                  Enqueue replay
                </button>
              </li>
              <li>
                <button
                  onClick={() => {
                    setMenuId(null);
                    navigator.clipboard.writeText(r.id);
                  }}
                >
                  Copy endpoint ID
                </button>
              </li>
            </ul>
          )}
        </div>
      ),
    },
  ];

  const sum = summary || {
    total: 0,
    testable: 0,
    excluded: 0,
    dangerous: 0,
    logout: 0,
    unqualified: 0,
  };

  return (
    <div className="pb-20">
      <div className="flex flex-wrap items-center gap-1 mb-3">
        <SummaryChip
          label="Endpoints"
          value={sum.total}
          active={!filters.state && !filters.excluded && !filters.dangerous && !filters.logout && !filters.qualified}
          onClick={() => patchFilters({ ...EMPTY_FILTERS })}
        />
        <span className="text-base-content/30">·</span>
        <SummaryChip
          label="Testable"
          value={sum.testable}
          active={filters.decision === "TESTABLE"}
          onClick={() => patchFilters({ ...EMPTY_FILTERS, decision: "TESTABLE" })}
        />
        <span className="text-base-content/30">·</span>
        <SummaryChip
          label="Excluded"
          value={sum.excluded}
          active={filters.excluded === "1"}
          onClick={() => patchFilters({ ...EMPTY_FILTERS, excluded: "1", state: "EXCLUDED" })}
        />
        <span className="text-base-content/30">·</span>
        <SummaryChip
          label="Dangerous"
          value={sum.dangerous}
          active={filters.dangerous === "1"}
          onClick={() => patchFilters({ ...EMPTY_FILTERS, dangerous: "1" })}
        />
        <span className="text-base-content/30">·</span>
        <SummaryChip
          label="Logout"
          value={sum.logout}
          active={filters.logout === "1"}
          onClick={() => patchFilters({ ...EMPTY_FILTERS, logout: "1" })}
        />
        <span className="text-base-content/30">·</span>
        <SummaryChip
          label="Unqualified"
          value={sum.unqualified}
          active={filters.qualified === "0"}
          onClick={() => patchFilters({ ...EMPTY_FILTERS, qualified: "0" })}
        />
      </div>

      {(filters.excluded === "1" || filters.dangerous === "1" || filters.state) && (
        <div className="text-xs text-base-content/60 mb-2">
          Active strip filter:{" "}
          {filters.excluded === "1" && <span className="badge badge-ghost badge-xs">Policy: Excluded</span>}
          {filters.dangerous === "1" && <span className="badge badge-warning badge-xs ml-1">Safety: Dangerous</span>}
          {filters.logout === "1" && <span className="badge badge-error badge-xs ml-1">Safety: Logout</span>}
          {filters.decision === "TESTABLE" && <span className="badge badge-success badge-xs ml-1">Decision: Testable</span>}
        </div>
      )}

      <FilterBar filters={filters} options={filterOptions} onChange={patchFilters} />

      <BulkResultBanner result={bulkResult} />

      {selectedCount > 0 && !selectAllMatching && total > pageIds.length && selected.size === pageIds.length && (
        <div className="alert alert-info text-sm py-2 mb-2">
          <div>
            <span className="font-medium">{selected.size} endpoints selected</span>
            <button className="btn btn-xs btn-link" onClick={selectAllMatchingAction}>
              Select all {total} endpoints matching current filters
            </button>
          </div>
        </div>
      )}
      {selectAllMatching && (
        <div className="alert alert-info text-sm py-2 mb-2">
          All {total} matching endpoints selected.{" "}
          <button className="btn btn-xs btn-link" onClick={clearSelection}>Clear selection</button>
        </div>
      )}

      <div className="flex items-center gap-2 mb-2 text-xs text-base-content/60">
        <label className="flex items-center gap-1 cursor-pointer">
          <input
            type="checkbox"
            className="checkbox checkbox-xs"
            checked={pageIds.length > 0 && pageIds.every((id) => selected.has(id))}
            onChange={togglePage}
          />
          Select page
        </label>
        <span>·</span>
        <button className="btn btn-xs btn-ghost" onClick={selectAllMatchingAction} disabled={total === 0}>
          Select all {total} matching
        </button>
        <button className="btn btn-xs btn-ghost" onClick={clearSelection}>Clear selection</button>
        <span className="ml-auto">{total} matching · page {Math.floor(offset / PAGE_SIZE) + 1}</span>
      </div>

      <DataTable
        columns={columns}
        rows={rows}
        rowKey={(r) => r.id}
        loading={loading}
        storageKey="endpoints-inventory"
        onRowClick={(r) => navigate(`/endpoints/${r.id}`)}
        emptyLabel="No endpoints captured yet. Start the proxy and browse the target with traffic routed through it."
      />

      {total > PAGE_SIZE && (
        <div className="flex justify-center gap-2 mt-3">
          <button
            className="btn btn-xs"
            disabled={offset === 0}
            onClick={() => setOffset((o) => Math.max(0, o - PAGE_SIZE))}
          >
            Prev
          </button>
          <button
            className="btn btn-xs"
            disabled={offset + PAGE_SIZE >= total}
            onClick={() => setOffset((o) => o + PAGE_SIZE)}
          >
            Next
          </button>
        </div>
      )}

      {selectedCount > 0 && (
        <div className="fixed bottom-4 left-1/2 -translate-x-1/2 z-30 panel shadow-lg px-4 py-3 flex flex-wrap items-center gap-2 max-w-[95vw]">
          <span className="font-semibold text-sm tabular-nums mr-2">{selectedCount} selected</span>

          <div className="dropdown dropdown-top">
            <button tabIndex={0} className="btn btn-xs">Mark ▾</button>
            <ul className="dropdown-content menu p-2 shadow bg-base-200 rounded-box w-44 border border-base-300 z-40">
              {[
                ["dangerous", "Dangerous"],
                ["logout", "Logout"],
                ["safe", "Safe"],
              ].map(([tag, label]) => (
                <li key={tag}>
                  <button
                    onClick={async () => {
                      await runBulk.run("/api/endpoints/bulk/mark", {
                        endpoint_ids: selectedIds,
                        tag,
                      });
                      afterBulk();
                    }}
                  >
                    {label}
                  </button>
                </li>
              ))}
              <li>
                <button
                  onClick={async () => {
                    await runBulk.run("/api/endpoints/bulk/unmark", {
                      endpoint_ids: selectedIds,
                      tag: "dangerous",
                    });
                    afterBulk();
                  }}
                >
                  Unmark dangerous
                </button>
              </li>
              <li>
                <button
                  onClick={async () => {
                    await runBulk.run("/api/endpoints/bulk/unmark", {
                      endpoint_ids: selectedIds,
                      tag: "logout",
                    });
                    afterBulk();
                  }}
                >
                  Unmark logout
                </button>
              </li>
            </ul>
          </div>

          <div className="dropdown dropdown-top">
            <button tabIndex={0} className="btn btn-xs">Priority ▾</button>
            <ul className="dropdown-content menu p-2 shadow bg-base-200 rounded-box w-44 border border-base-300 z-40">
              {PRIORITIES.map((p) => (
                <li key={p}>
                  <button
                    onClick={async () => {
                      await runBulk.run("/api/endpoints/bulk/priority", {
                        endpoint_ids: selectedIds,
                        priority: p,
                      });
                      afterBulk();
                    }}
                  >
                    {p}
                  </button>
                </li>
              ))}
              <li>
                <button
                  onClick={async () => {
                    await runBulk.run("/api/endpoints/bulk/priority", {
                      endpoint_ids: selectedIds,
                      clear: true,
                    });
                    afterBulk();
                  }}
                >
                  Clear manual priority
                </button>
              </li>
            </ul>
          </div>

          <div className="dropdown dropdown-top">
            <button tabIndex={0} className="btn btn-xs">Exclusion ▾</button>
            <ul className="dropdown-content menu p-2 shadow bg-base-200 rounded-box w-36 border border-base-300 z-40">
              <li>
                <button
                  onClick={async () => {
                    await runBulk.run("/api/endpoints/bulk/exclude", {
                      endpoint_ids: selectedIds,
                    });
                    afterBulk();
                  }}
                >
                  Exclude
                </button>
              </li>
              <li>
                <button
                  onClick={async () => {
                    await runBulk.run("/api/endpoints/bulk/include", {
                      endpoint_ids: selectedIds,
                    });
                    afterBulk();
                  }}
                >
                  Include
                </button>
              </li>
            </ul>
          </div>

          <div className="dropdown dropdown-top">
            <button tabIndex={0} className="btn btn-xs">Tags ▾</button>
            <ul className="dropdown-content menu p-2 shadow bg-base-200 rounded-box w-40 border border-base-300 z-40">
              <li>
                <button onClick={() => setShowTagPrompt("add")}>Add tag…</button>
              </li>
              <li>
                <button onClick={() => setShowTagPrompt("remove")}>Remove tag…</button>
              </li>
            </ul>
          </div>

          <div className="dropdown dropdown-top">
            <button tabIndex={0} className="btn btn-xs">Test ▾</button>
            <ul className="dropdown-content menu p-2 shadow bg-base-200 rounded-box w-48 border border-base-300 z-40">
              <li>
                <button
                  onClick={async () => {
                    await runBulk.run("/api/endpoints/bulk/test", {
                      endpoint_ids: selectedIds,
                      action: "enqueue_replay",
                    });
                    afterBulk();
                  }}
                >
                  Enqueue replay
                </button>
              </li>
              <li>
                <button
                  disabled={selectedCount !== 1}
                  onClick={async () => {
                    await runBulk.run("/api/endpoints/bulk/test", {
                      endpoint_ids: selectedIds,
                      action: "replay_now",
                    });
                    afterBulk();
                  }}
                >
                  Replay now {selectedCount !== 1 ? "(1 only)" : ""}
                </button>
              </li>
              <li>
                <button
                  onClick={async () => {
                    await runBulk.run("/api/endpoints/bulk/test", {
                      endpoint_ids: selectedIds,
                      action: "enqueue_auth",
                    });
                    afterBulk();
                  }}
                >
                  Enqueue auth test
                </button>
              </li>
            </ul>
          </div>

          <button
            className="btn btn-xs btn-outline"
            onClick={() => {
              const paths = rows
                .filter((r) => selectedIds.includes(r.id))
                .map((r) => r.normalized_path);
              // When select-all-matching, use matching paths from current page + pattern suggestion
              const pattern = suggestPathPattern(
                paths.length ? paths : rows.map((r) => r.normalized_path)
              );
              onCreateRuleFromSelection(pattern, paths);
            }}
          >
            Create path rule from selection
          </button>

          <button className="btn btn-xs btn-ghost ml-auto" onClick={clearSelection}>
            Clear
          </button>
        </div>
      )}

      {showTagPrompt && (
        <div className="modal modal-open">
          <div className="modal-box">
            <h3 className="font-bold mb-2">{showTagPrompt === "add" ? "Add tag" : "Remove tag"}</h3>
            <input
              className="input input-sm input-bordered w-full"
              value={tagInput}
              onChange={(e) => setTagInput(e.target.value)}
              placeholder="tag label"
            />
            <div className="modal-action">
              <button className="btn btn-sm" onClick={() => setShowTagPrompt(null)}>Cancel</button>
              <button
                className="btn btn-sm btn-primary"
                disabled={!tagInput.trim()}
                onClick={async () => {
                  await runBulk.run("/api/endpoints/bulk/tags", {
                    endpoint_ids: selectedIds,
                    action: showTagPrompt,
                    tags: [tagInput.trim()],
                  });
                  setShowTagPrompt(null);
                  setTagInput("");
                  afterBulk();
                }}
              >
                Apply
              </button>
            </div>
          </div>
          <div className="modal-backdrop" onClick={() => setShowTagPrompt(null)} />
        </div>
      )}

      <SideDrawer
        open={!!explainId}
        onClose={() => { setExplainId(null); setExplain(null); }}
        title="Explain policy"
        wide
      >
        <PolicyExplain data={explain} />
      </SideDrawer>
    </div>
  );
}
