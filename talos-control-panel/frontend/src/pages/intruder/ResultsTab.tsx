import { useCallback, useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { API_BASE, api } from "../../api/client";
import DataTable, { type Column } from "../../components/DataTable";
import ResultDetailDrawer from "./components/ResultDetailDrawer";
import type { IntruderResultRow, IntruderSessionDetail } from "./types";

export default function ResultsTab({
  projectId,
  session,
}: {
  projectId: string;
  session: IntruderSessionDetail;
}) {
  const [rows, setRows] = useState<IntruderResultRow[]>([]);
  const [loading, setLoading] = useState(false);
  const [total, setTotal] = useState(0);
  const [totalAll, setTotalAll] = useState(0);
  const [totalInteresting, setTotalInteresting] = useState(0);
  const [interestingOnly, setInterestingOnly] = useState(true);
  const [statusCode, setStatusCode] = useState<string>("");
  const [offset, setOffset] = useState(0);
  const [selected, setSelected] = useState<IntruderResultRow | null>(null);
  const [summary, setSummary] = useState<Record<string, number>>({});
  const limit = 100;

  // Smart default: interesting if any exist
  useEffect(() => {
    if (totalInteresting > 0) setInterestingOnly(true);
    else if (totalAll > 0 && totalInteresting === 0) setInterestingOnly(false);
  }, [totalInteresting, totalAll]);

  const load = useCallback(() => {
    setLoading(true);
    const params: Record<string, unknown> = {
      project_id: projectId,
      limit,
      offset,
    };
    if (interestingOnly) params.interesting = true;
    if (statusCode.trim()) {
      const n = Number(statusCode);
      if (!Number.isNaN(n)) params.status_code = n;
    }
    api
      .get<{
        results: IntruderResultRow[];
        total: number;
        total_all: number;
        total_interesting: number;
      }>(`/api/intruder/sessions/${session.id}/results`, params)
      .then((r) => {
        setRows(r.results || []);
        setTotal(r.total ?? 0);
        setTotalAll(r.total_all ?? 0);
        setTotalInteresting(r.total_interesting ?? 0);
      })
      .catch(() => {
        setRows([]);
      })
      .finally(() => setLoading(false));

    api
      .get<{ by_status: Record<string, number> }>(
        `/api/intruder/sessions/${session.id}/results/summary`,
        { project_id: projectId }
      )
      .then((r) => setSummary(r.by_status || {}))
      .catch(() => setSummary({}));
  }, [projectId, session.id, interestingOnly, statusCode, offset]);

  useEffect(() => {
    load();
  }, [load]);

  // Poll lightly while running
  useEffect(() => {
    if (session.status !== "running" && session.status !== "queued") return;
    const id = window.setInterval(load, 3000);
    return () => window.clearInterval(id);
  }, [session.status, load]);

  const downloadExport = async (format: "jsonl" | "csv") => {
    const url = new URL(
      `${API_BASE}/api/intruder/sessions/${session.id}/results/export`
    );
    url.searchParams.set("project_id", projectId);
    url.searchParams.set("format", format);
    if (interestingOnly) url.searchParams.set("interesting", "true");
    const res = await fetch(url.toString());
    if (!res.ok) {
      const text = await res.text();
      window.alert(`Export failed: ${text.slice(0, 200)}`);
      return;
    }
    const blob = await res.blob();
    const disp = res.headers.get("Content-Disposition") || "";
    const m = disp.match(/filename="?([^"]+)"?/);
    const filename = m?.[1] || `intruder-${session.id.slice(0, 8)}.${format}`;
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    a.click();
    URL.revokeObjectURL(a.href);
  };

  const columns: Column<IntruderResultRow>[] = useMemo(
    () => [
      {
        key: "attempt_index",
        header: "#",
        defaultWidth: 56,
        render: (r) => (
          <span className="mono text-xs">{r.attempt_index}</span>
        ),
      },
      {
        key: "status_code",
        header: "Status",
        defaultWidth: 80,
        render: (r) => (
          <span
            className={
              r.success ? "text-success" : "text-error"
            }
          >
            {r.status_code ?? "—"}
          </span>
        ),
      },
      {
        key: "body_length",
        header: "Length",
        defaultWidth: 80,
        render: (r) =>
          r.body_length != null ? r.body_length.toLocaleString() : "—",
      },
      {
        key: "duration_ms",
        header: "Time",
        defaultWidth: 72,
        render: (r) =>
          r.duration_ms != null ? `${r.duration_ms}ms` : "—",
      },
      {
        key: "variables",
        header: "Payloads",
        defaultWidth: 200,
        render: (r) => (
          <span className="mono text-[11px] truncate max-w-[220px] inline-block">
            {Object.entries(r.variables || {})
              .map(([k, v]) => `${k}=${v}`)
              .join(" · ") || "—"}
          </span>
        ),
      },
      {
        key: "match_tags",
        header: "Tags",
        defaultWidth: 100,
        render: (r) =>
          (r.match_tags || []).length ? (
            <span className="text-[11px]">{r.match_tags.join(", ")}</span>
          ) : (
            "—"
          ),
      },
      {
        key: "interesting",
        header: "★",
        defaultWidth: 40,
        render: (r) => (r.interesting ? "★" : ""),
      },
      {
        key: "flow_id",
        header: "Flow",
        defaultWidth: 72,
        render: (r) =>
          r.flow_id ? (
            <Link
              to={`/flows/${r.flow_id}`}
              className="link link-hover mono text-[11px]"
              onClick={(e) => e.stopPropagation()}
            >
              {r.flow_id.slice(0, 8)}
            </Link>
          ) : (
            "—"
          ),
      },
    ],
    []
  );

  const statusEntries = Object.entries(summary).sort(
    (a, b) => b[1] - a[1]
  );

  const page = Math.floor(offset / limit) + 1;
  const pageCount = Math.max(1, Math.ceil(total / limit));

  return (
    <div className="space-y-3">
      {totalAll === 0 &&
        (session.status === "draft" || session.status === "configured") && (
          <div className="rounded-md border border-dashed border-base-300 px-4 py-6 text-center text-xs text-base-content/50">
            No results yet. Configure payloads, <strong>Save</strong>, then{" "}
            <strong>Validate / Run</strong> on the Run tab.
          </div>
        )}

      <div className="flex flex-wrap items-center gap-2">
        <label className="flex items-center gap-1.5 text-xs cursor-pointer">
          <input
            type="checkbox"
            className="checkbox checkbox-xs"
            checked={interestingOnly}
            onChange={(e) => {
              setOffset(0);
              setInterestingOnly(e.target.checked);
            }}
          />
          Interesting only
          {totalInteresting > 0 && (
            <span className="text-base-content/40">
              ({totalInteresting})
            </span>
          )}
        </label>
        <label className="flex items-center gap-1 text-xs">
          Status
          <input
            className="input input-bordered input-xs w-20 mono"
            placeholder="all"
            value={statusCode}
            onChange={(e) => {
              setOffset(0);
              setStatusCode(e.target.value);
            }}
          />
        </label>
        <button
          type="button"
          className="btn btn-ghost btn-xs"
          onClick={() => load()}
        >
          Refresh
        </button>
        <div className="dropdown dropdown-end">
          <button
            type="button"
            tabIndex={0}
            className="btn btn-ghost btn-xs"
            disabled={totalAll === 0}
          >
            Export ▾
          </button>
          <ul
            tabIndex={0}
            className="dropdown-content z-20 menu p-2 shadow bg-base-100 rounded-box w-44 border border-base-300 text-xs"
          >
            <li>
              <button type="button" onClick={() => void downloadExport("jsonl")}>
                JSONL {interestingOnly ? "(interesting)" : "(all)"}
              </button>
            </li>
            <li>
              <button type="button" onClick={() => void downloadExport("csv")}>
                CSV {interestingOnly ? "(interesting)" : "(all)"}
              </button>
            </li>
          </ul>
        </div>
        <span className="text-xs text-base-content/50 ml-auto">
          Showing {rows.length} of {total}
          {totalAll !== total ? ` (filtered; ${totalAll} total)` : ""}
          {totalInteresting > 0 && !interestingOnly
            ? ` · ${totalInteresting} interesting`
            : ""}
        </span>
      </div>

      {statusEntries.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {statusEntries.map(([code, n]) => (
            <button
              key={code}
              type="button"
              className={`badge badge-sm cursor-pointer ${
                statusCode === code ? "badge-primary" : "badge-outline"
              }`}
              onClick={() => {
                setOffset(0);
                setStatusCode(statusCode === code ? "" : code);
              }}
            >
              {code}: {n}
            </button>
          ))}
        </div>
      )}

      <DataTable
        columns={columns}
        rows={rows}
        rowKey={(r) => r.id}
        loading={loading}
        emptyLabel={
          totalAll === 0
            ? "No results yet — run the session first."
            : "No rows match filters."
        }
        onRowClick={(r) => setSelected(r)}
        storageKey="intruder-results"
      />

      {total > 0 && (
        <div className="flex items-center gap-2 justify-end">
          <button
            type="button"
            className="btn btn-xs"
            disabled={offset === 0}
            onClick={() => setOffset(Math.max(0, offset - limit))}
          >
            Prev
          </button>
          <span className="text-xs text-base-content/50">
            Page {page} / {pageCount}
          </span>
          <button
            type="button"
            className="btn btn-xs"
            disabled={offset + limit >= total}
            onClick={() => setOffset(offset + limit)}
          >
            Next
          </button>
        </div>
      )}

      <ResultDetailDrawer row={selected} onClose={() => setSelected(null)} />
    </div>
  );
}
