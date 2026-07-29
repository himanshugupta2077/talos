/**
 * Structured access coverage — expected vs observed traffic per map row.
 */

import { useEffect, useMemo, useState } from "react";
import { api } from "../../api/client";
import type { AccessCoverageRow } from "../../types";
import {
  coverageStatus,
  coverageStatusClass,
  coverageStatusLabel,
  valueBadgeClass,
} from "./shared";

type SortKey =
  | "role_name"
  | "module_name"
  | "flow_count"
  | "endpoint_count"
  | "status";

export default function CoverageTab({ projectId }: { projectId: string }) {
  const [rows, setRows] = useState<AccessCoverageRow[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [q, setQ] = useState("");
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [sortKey, setSortKey] = useState<SortKey>("role_name");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("asc");

  const load = () => {
    setLoading(true);
    setError(null);
    api
      .get<{ rows: AccessCoverageRow[] }>("/api/access/coverage", {
        project_id: projectId,
      })
      .then((r) => setRows(r.rows || []))
      .catch((e) => setError(e?.message || "Failed to load coverage"))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    load();
  }, [projectId]);

  const enriched = useMemo(
    () =>
      rows.map((r) => ({
        ...r,
        status: coverageStatus(r),
      })),
    [rows]
  );

  const filtered = useMemo(() => {
    let list = enriched;
    const needle = q.trim().toLowerCase();
    if (needle) {
      list = list.filter(
        (r) =>
          r.role_name.toLowerCase().includes(needle) ||
          r.module_name.toLowerCase().includes(needle)
      );
    }
    if (statusFilter !== "all") {
      list = list.filter((r) => r.status === statusFilter);
    }
    list = [...list].sort((a, b) => {
      let av: string | number = "";
      let bv: string | number = "";
      if (sortKey === "status") {
        av = a.status;
        bv = b.status;
      } else if (sortKey === "flow_count" || sortKey === "endpoint_count") {
        av = a[sortKey] ?? 0;
        bv = b[sortKey] ?? 0;
      } else {
        av = a[sortKey] ?? "";
        bv = b[sortKey] ?? "";
      }
      if (av < bv) return sortDir === "asc" ? -1 : 1;
      if (av > bv) return sortDir === "asc" ? 1 : -1;
      return 0;
    });
    return list;
  }, [enriched, q, statusFilter, sortKey, sortDir]);

  const counts = useMemo(() => {
    const c = {
      observed: 0,
      gap: 0,
      unexpected: 0,
      boundary: 0,
      empty: 0,
    };
    for (const r of enriched) c[r.status]++;
    return c;
  }, [enriched]);

  const toggleSort = (key: SortKey) => {
    if (sortKey === key) setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    else {
      setSortKey(key);
      setSortDir(key === "flow_count" || key === "endpoint_count" ? "desc" : "asc");
    }
  };

  if (loading && !rows.length) {
    return (
      <div className="py-12 text-center">
        <span className="loading loading-spinner" />
      </div>
    );
  }

  if (error) {
    return (
      <div className="panel p-4 text-sm text-error">
        {error}{" "}
        <button type="button" className="btn btn-xs ml-2" onClick={load}>
          Retry
        </button>
      </div>
    );
  }

  if (!rows.length) {
    return (
      <div className="panel p-8 text-center text-sm text-base-content/50">
        No coverage data yet. Set at least one access_map entry on the Matrix
        tab, then capture traffic with matching role/module tags.
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <p className="text-xs text-base-content/50">
        Expected-vs-observed for each access_map row (same data as{" "}
        <span className="mono">talos access coverage</span>). Status chips are
        UI helpers — they do not change the matrix.
      </p>

      <div className="flex flex-wrap gap-2 text-xs">
        <span className="badge badge-outline">{rows.length} pairs</span>
        <span className={`badge ${coverageStatusClass("observed")}`}>
          observed {counts.observed}
        </span>
        <span className={`badge ${coverageStatusClass("gap")}`}>
          gaps {counts.gap}
        </span>
        <span className={`badge ${coverageStatusClass("unexpected")}`}>
          unexpected {counts.unexpected}
        </span>
        <span className={`badge ${coverageStatusClass("boundary")}`}>
          boundary {counts.boundary}
        </span>
      </div>

      <div className="flex flex-wrap gap-2">
        <input
          className="input input-xs input-bordered w-48"
          placeholder="Filter role or module…"
          value={q}
          onChange={(e) => setQ(e.target.value)}
        />
        <select
          className="select select-xs select-bordered"
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
        >
          <option value="all">All statuses</option>
          <option value="observed">Observed</option>
          <option value="gap">Coverage gap</option>
          <option value="unexpected">Client DENY + traffic</option>
          <option value="boundary">Server DENY + traffic</option>
          <option value="empty">No traffic</option>
        </select>
        <button type="button" className="btn btn-xs btn-ghost" onClick={load}>
          Refresh
        </button>
      </div>

      <div className="panel overflow-x-auto">
        <table className="table table-xs">
          <thead>
            <tr>
              <Th label="Role" k="role_name" sortKey={sortKey} sortDir={sortDir} onSort={toggleSort} />
              <Th label="Module" k="module_name" sortKey={sortKey} sortDir={sortDir} onSort={toggleSort} />
              <th>Client</th>
              <th>Server</th>
              <Th label="Flows" k="flow_count" sortKey={sortKey} sortDir={sortDir} onSort={toggleSort} />
              <Th label="Endpoints" k="endpoint_count" sortKey={sortKey} sortDir={sortDir} onSort={toggleSort} />
              <Th label="Status" k="status" sortKey={sortKey} sortDir={sortDir} onSort={toggleSort} />
            </tr>
          </thead>
          <tbody>
            {filtered.map((r) => (
              <tr key={`${r.role_name}::${r.module_name}`}>
                <td className="font-medium">{r.role_name}</td>
                <td>{r.module_name}</td>
                <td>
                  <span className={`badge badge-xs ${valueBadgeClass(r.client_allowed)}`}>
                    {r.client_allowed || "—"}
                  </span>
                </td>
                <td>
                  <span className={`badge badge-xs ${valueBadgeClass(r.server_expected)}`}>
                    {r.server_expected || "—"}
                  </span>
                </td>
                <td className="tabular-nums">{r.flow_count}</td>
                <td className="tabular-nums">{r.endpoint_count}</td>
                <td>
                  <span className={`badge badge-xs ${coverageStatusClass(r.status)}`}>
                    {coverageStatusLabel(r.status)}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {!filtered.length && (
          <div className="p-4 text-center text-xs text-base-content/40">
            No rows match this filter.
          </div>
        )}
      </div>
    </div>
  );
}

function Th({
  label,
  k,
  sortKey,
  sortDir,
  onSort,
}: {
  label: string;
  k: SortKey;
  sortKey: SortKey;
  sortDir: "asc" | "desc";
  onSort: (k: SortKey) => void;
}) {
  const active = sortKey === k;
  return (
    <th>
      <button
        type="button"
        className="font-semibold hover:text-primary"
        onClick={() => onSort(k)}
      >
        {label}
        {active ? (sortDir === "asc" ? " ↑" : " ↓") : ""}
      </button>
    </th>
  );
}
