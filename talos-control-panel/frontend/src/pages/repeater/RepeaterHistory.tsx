import { Link } from "react-router-dom";
import StatusBadge from "../../components/StatusBadge";
import { UuidChip } from "../../components/Common";
import { formatIST } from "../../lib/time";
import type { SendHistoryRow, SendTreeNode } from "../../types";
import { HistoryEmpty } from "./emptyStates";

interface Props {
  rows: SendHistoryRow[];
  treeNodes: SendTreeNode[];
  view: "list" | "tree";
  onViewChange: (v: "list" | "tree") => void;
  sessionFilter: string | null;
  sessions: string[];
  onSessionFilter: (s: string | null) => void;
  selectedId: string | null;
  onSelect: (row: SendHistoryRow) => void;
  onFork: (row: SendHistoryRow) => void;
  collapsed: boolean;
  onToggleCollapse: () => void;
  loading?: boolean;
}

function TreeRows({
  nodes,
  selectedId,
  onSelect,
  onFork,
  rowById,
}: {
  nodes: SendTreeNode[];
  selectedId: string | null;
  onSelect: (row: SendHistoryRow) => void;
  onFork: (row: SendHistoryRow) => void;
  rowById: Map<string, SendHistoryRow>;
}) {
  return (
    <ul className="space-y-0.5">
      {nodes.map((n) => {
        const row = rowById.get(n.id);
        return (
          <li key={n.id} style={{ paddingLeft: n.depth * 12 }}>
            <div
              className={`flex flex-wrap items-center gap-1 text-xs py-0.5 px-1 rounded cursor-pointer ${
                selectedId === n.id ? "bg-primary/10" : "hover:bg-base-200"
              }`}
              onClick={() => row && onSelect(row)}
            >
              <span className="mono">
                {n.method} {n.status_code ?? "—"}
              </span>
              {n.verdict && <StatusBadge value={n.verdict} />}
              <UuidChip value={n.id} />
              {row && (
                <button
                  type="button"
                  className="btn btn-ghost btn-xs"
                  onClick={(e) => {
                    e.stopPropagation();
                    onFork(row);
                  }}
                >
                  Fork
                </button>
              )}
            </div>
            {n.children?.length > 0 && (
              <TreeRows
                nodes={n.children}
                selectedId={selectedId}
                onSelect={onSelect}
                onFork={onFork}
                rowById={rowById}
              />
            )}
          </li>
        );
      })}
    </ul>
  );
}

export default function RepeaterHistory({
  rows,
  treeNodes,
  view,
  onViewChange,
  sessionFilter,
  sessions,
  onSessionFilter,
  selectedId,
  onSelect,
  onFork,
  collapsed,
  onToggleCollapse,
  loading,
}: Props) {
  const rowById = new Map(rows.map((r) => [r.id, r]));

  return (
    <div className="border-t border-base-300 bg-base-200/20 shrink-0">
      <div className="flex items-center gap-2 px-3 py-1.5 flex-wrap">
        <button
          type="button"
          className="btn btn-ghost btn-xs"
          onClick={onToggleCollapse}
        >
          History {collapsed ? "▸" : "▾"}
        </button>
        {!collapsed && (
          <>
            <div className="join">
              <button
                type="button"
                className={`btn btn-xs join-item ${view === "list" ? "btn-active" : ""}`}
                onClick={() => onViewChange("list")}
              >
                List
              </button>
              <button
                type="button"
                className={`btn btn-xs join-item ${view === "tree" ? "btn-active" : ""}`}
                onClick={() => onViewChange("tree")}
              >
                Tree
              </button>
            </div>
            {sessions.length > 0 && (
              <select
                className="select select-bordered select-xs max-w-[140px]"
                value={sessionFilter || ""}
                onChange={(e) =>
                  onSessionFilter(e.target.value || null)
                }
              >
                <option value="">All sessions</option>
                {sessions.map((s) => (
                  <option key={s} value={s}>
                    {s.slice(0, 8)}
                  </option>
                ))}
              </select>
            )}
            <span className="text-[10px] text-base-content/40">
              Click = response only · Fork = load as parent
            </span>
          </>
        )}
      </div>
      {!collapsed && (
        <div className="max-h-48 overflow-auto px-2 pb-2">
          {loading && (
            <div className="loading loading-spinner loading-xs m-2" />
          )}
          {!loading && rows.length === 0 && <HistoryEmpty />}
          {!loading && view === "list" && rows.length > 0 && (
            <table className="table table-xs">
              <thead>
                <tr>
                  <th>When</th>
                  <th>Status</th>
                  <th>Verdict</th>
                  <th>Id</th>
                  <th>ms</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {[...rows].reverse().map((r) => (
                  <tr
                    key={r.id}
                    className={`cursor-pointer ${
                      selectedId === r.id ? "bg-primary/10" : ""
                    }`}
                    onClick={() => onSelect(r)}
                  >
                    <td className="text-[10px] whitespace-nowrap">
                      {formatIST(r.captured_at)}
                    </td>
                    <td>
                      {r.status_code != null ? (
                        <StatusBadge value={r.status_code} />
                      ) : (
                        "—"
                      )}
                    </td>
                    <td>
                      {r.verdict ? <StatusBadge value={r.verdict} /> : "—"}
                    </td>
                    <td>
                      <Link
                        to={`/flows/${r.id}`}
                        className="link"
                        onClick={(e) => e.stopPropagation()}
                      >
                        <UuidChip value={r.id} />
                      </Link>
                    </td>
                    <td className="mono text-[10px]">
                      {r.duration_ms ?? "—"}
                    </td>
                    <td>
                      <button
                        type="button"
                        className="btn btn-ghost btn-xs"
                        onClick={(e) => {
                          e.stopPropagation();
                          onFork(r);
                        }}
                      >
                        Fork
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          {!loading && view === "tree" && treeNodes.length > 0 && (
            <TreeRows
              nodes={treeNodes}
              selectedId={selectedId}
              onSelect={onSelect}
              onFork={onFork}
              rowById={rowById}
            />
          )}
        </div>
      )}
    </div>
  );
}
