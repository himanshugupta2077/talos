import { useCallback, useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../../api/client";
import DataTable, { Column } from "../../components/DataTable";
import { formatIST } from "../../lib/time";
import SeverityBadge from "./components/SeverityBadge";
import CategoryBadge from "./components/CategoryBadge";
import TechFlags from "./components/TechFlags";
import {
  DEFAULT_SEVERITY_FILTER,
  ERROR_CATEGORIES,
  ERROR_SEVERITIES,
  ERRORS_BASE,
  ErrorClusterRow,
  ErrorSeverity,
  clusterTitle,
  inputClass,
  selectClass,
  severityParam,
  shortId,
} from "./shared";

export default function ErrorsTab({
  projectId,
  scannerVersion,
}: {
  projectId: string;
  scannerVersion?: string;
}) {
  const navigate = useNavigate();
  const [rows, setRows] = useState<ErrorClusterRow[]>([]);
  const [total, setTotal] = useState(0);
  const [severities, setSeverities] = useState<ErrorSeverity[] | null>(
    DEFAULT_SEVERITY_FILTER,
  );
  const [category, setCategory] = useState("");
  const [q, setQ] = useState("");
  const [qDraft, setQDraft] = useState("");
  const [hasStack, setHasStack] = useState(false);
  const [hasPath, setHasPath] = useState(false);
  const [hasHost, setHasHost] = useState(false);
  const [hasVersion, setHasVersion] = useState(false);
  const [hideLowNoise, setHideLowNoise] = useState(false);
  const [minObs, setMinObs] = useState("");
  const [groupByException, setGroupByException] = useState(false);
  const [limit, setLimit] = useState(50);
  const [offset, setOffset] = useState(0);
  const [loading, setLoading] = useState(false);

  const load = useCallback(() => {
    setLoading(true);
    const params: Record<string, string | number | boolean> = {
      project_id: projectId,
      limit,
      offset,
    };
    const sev = severityParam(severities);
    if (sev) params.severity = sev;
    if (category) params.category = category;
    if (q.trim()) params.q = q.trim();
    if (hasStack) params.has_stack_trace = true;
    if (hasPath) params.has_path_leak = true;
    if (hasHost) params.has_internal_host = true;
    if (hasVersion) params.has_version_leak = true;
    if (hideLowNoise) params.hide_low_noise = true;
    const min = Number(minObs);
    if (minObs && !Number.isNaN(min) && min >= 1) params.min_observations = min;

    api
      .get<{ errors: ErrorClusterRow[]; total: number }>(
        "/api/error-intel/errors",
        params,
      )
      .then((r) => {
        setRows(r.errors || []);
        setTotal(r.total ?? (r.errors || []).length);
      })
      .catch(() => {
        setRows([]);
        setTotal(0);
      })
      .finally(() => setLoading(false));
  }, [
    projectId,
    severities,
    category,
    q,
    hasStack,
    hasPath,
    hasHost,
    hasVersion,
    hideLowNoise,
    minObs,
    limit,
    offset,
  ]);

  useEffect(() => {
    load();
  }, [load]);

  // Reset page when filters change (except offset itself)
  useEffect(() => {
    setOffset(0);
  }, [
    severities,
    category,
    q,
    hasStack,
    hasPath,
    hasHost,
    hasVersion,
    hideLowNoise,
    minObs,
    limit,
  ]);

  const displayRows = useMemo(() => {
    if (!groupByException) return rows;
    // Client-side group on current page only (BUG-01 mitigation; not project-wide)
    const sorted = [...rows].sort((a, b) => {
      const ea = (a.exception_type || "").toLowerCase();
      const eb = (b.exception_type || "").toLowerCase();
      if (ea !== eb) return ea.localeCompare(eb);
      return (b.last_seen || "").localeCompare(a.last_seen || "");
    });
    return sorted;
  }, [rows, groupByException]);

  const toggleSeverity = (s: ErrorSeverity) => {
    if (severities === null) {
      // Coming from "all" — start with just this one
      setSeverities([s]);
      return;
    }
    if (severities.includes(s)) {
      const next = severities.filter((x) => x !== s);
      setSeverities(next.length === 0 ? null : next);
    } else {
      const next = [...severities, s];
      if (next.length === ERROR_SEVERITIES.length) setSeverities(null);
      else setSeverities(next);
    }
  };

  const columns: Column<ErrorClusterRow>[] = [
    {
      key: "severity",
      header: "Severity",
      render: (c) => <SeverityBadge severity={c.severity} />,
    },
    {
      key: "category",
      header: "Category",
      render: (c) => <CategoryBadge category={c.category} />,
    },
    {
      key: "exception_type",
      header: "Exception / message",
      render: (c) => (
        <div>
          <div className="text-sm">{clusterTitle(c)}</div>
          <div className="text-[10px] text-base-content/40 mono">
            {shortId(c.id)}
            {c.scanner_version &&
              scannerVersion &&
              c.scanner_version !== scannerVersion && (
                <span className="badge badge-warning badge-xs ml-1">
                  scanner {c.scanner_version}
                </span>
              )}
          </div>
        </div>
      ),
    },
    {
      key: "language",
      header: "Stack",
      render: (c) => (
        <span className="text-xs text-base-content/70">
          {[c.language, c.framework, c.database].filter(Boolean).join(" · ") ||
            "—"}
        </span>
      ),
    },
    {
      key: "has_stack_trace",
      header: "Flags",
      render: (c) => <TechFlags cluster={c} compact />,
    },
    {
      key: "observation_count",
      header: "Obs",
      className: "mono",
      sortValue: (c) => c.observation_count,
      render: (c) => c.observation_count,
    },
    {
      key: "first_seen",
      header: "First",
      className: "text-xs",
      sortValue: (c) => c.first_seen || "",
      render: (c) => (c.first_seen ? formatIST(c.first_seen) : "—"),
    },
    {
      key: "last_seen",
      header: "Last",
      className: "text-xs",
      sortValue: (c) => c.last_seen || "",
      render: (c) => (c.last_seen ? formatIST(c.last_seen) : "—"),
    },
  ];

  const pageStart = total === 0 ? 0 : offset + 1;
  const pageEnd = Math.min(offset + rows.length, total);

  return (
    <div>
      <div className="alert alert-ghost border border-base-300 text-xs py-2 mb-3">
        <span>
          Same exception may appear as multiple clusters (fingerprint includes
          status bucket). Group-by on this page is page-local only — open a
          cluster for sibling links.
        </span>
      </div>

      <div className="flex flex-wrap gap-2 mb-3 items-center">
        <span className="text-xs text-base-content/50">Severity:</span>
        <button
          type="button"
          className={`btn btn-xs ${severities === null ? "btn-primary" : "btn-ghost"}`}
          onClick={() => setSeverities(null)}
        >
          All
        </button>
        {ERROR_SEVERITIES.map((s) => {
          const active =
            severities !== null && severities.includes(s);
          return (
            <button
              key={s}
              type="button"
              className={`btn btn-xs capitalize ${active ? "btn-primary" : "btn-ghost"}`}
              onClick={() => toggleSeverity(s)}
            >
              {s}
            </button>
          );
        })}
        <button
          type="button"
          className="btn btn-xs btn-outline"
          onClick={() => setSeverities([...DEFAULT_SEVERITY_FILTER])}
          title="Reset to medium+"
        >
          medium+
        </button>
      </div>

      <div className="flex flex-wrap gap-2 mb-4 items-center">
        <select
          className={selectClass}
          value={category}
          onChange={(e) => setCategory(e.target.value)}
        >
          <option value="">category: any</option>
          {ERROR_CATEGORIES.map((c) => (
            <option key={c} value={c}>
              {c}
            </option>
          ))}
        </select>
        <input
          className={`${inputClass} w-48`}
          placeholder="search exception / message"
          value={qDraft}
          onChange={(e) => setQDraft(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") setQ(qDraft);
          }}
        />
        <button className="btn btn-xs" onClick={() => setQ(qDraft)}>
          Search
        </button>
        <input
          className={`${inputClass} w-24`}
          placeholder="min obs"
          value={minObs}
          onChange={(e) => setMinObs(e.target.value)}
        />
        <label className="label cursor-pointer gap-1 py-0">
          <input
            type="checkbox"
            className="checkbox checkbox-xs"
            checked={hasStack}
            onChange={(e) => setHasStack(e.target.checked)}
          />
          <span className="label-text text-xs">stack</span>
        </label>
        <label className="label cursor-pointer gap-1 py-0">
          <input
            type="checkbox"
            className="checkbox checkbox-xs"
            checked={hasPath}
            onChange={(e) => setHasPath(e.target.checked)}
          />
          <span className="label-text text-xs">path leak</span>
        </label>
        <label className="label cursor-pointer gap-1 py-0">
          <input
            type="checkbox"
            className="checkbox checkbox-xs"
            checked={hasHost}
            onChange={(e) => setHasHost(e.target.checked)}
          />
          <span className="label-text text-xs">internal host</span>
        </label>
        <label className="label cursor-pointer gap-1 py-0">
          <input
            type="checkbox"
            className="checkbox checkbox-xs"
            checked={hasVersion}
            onChange={(e) => setHasVersion(e.target.checked)}
          />
          <span className="label-text text-xs">version</span>
        </label>
        <label className="label cursor-pointer gap-1 py-0" title="Exclude infrastructure/http + low">
          <input
            type="checkbox"
            className="checkbox checkbox-xs"
            checked={hideLowNoise}
            onChange={(e) => setHideLowNoise(e.target.checked)}
          />
          <span className="label-text text-xs">hide low infra/http</span>
        </label>
        <label className="label cursor-pointer gap-1 py-0">
          <input
            type="checkbox"
            className="checkbox checkbox-xs"
            checked={groupByException}
            onChange={(e) => setGroupByException(e.target.checked)}
          />
          <span className="label-text text-xs">group by exception (page)</span>
        </label>
        <select
          className={selectClass}
          value={limit}
          onChange={(e) => setLimit(Number(e.target.value))}
        >
          {[25, 50, 100, 200].map((n) => (
            <option key={n} value={n}>
              limit {n}
            </option>
          ))}
        </select>
        <button className="btn btn-xs" onClick={load} disabled={loading}>
          Refresh
        </button>
        <span className="text-xs text-base-content/50">
          {loading
            ? "Loading…"
            : total > 0
              ? `Showing ${pageStart}–${pageEnd} of ${total}`
              : "0 rows"}
        </span>
      </div>

      <DataTable
        columns={columns}
        rows={displayRows}
        rowKey={(c) => c.id}
        onRowClick={(c) => navigate(`${ERRORS_BASE}/${c.id}`)}
        emptyLabel="No error clusters match filters."
        storageKey="error-intel-errors"
      />

      {total > limit && (
        <div className="flex gap-2 mt-3 items-center">
          <button
            className="btn btn-xs"
            disabled={offset <= 0 || loading}
            onClick={() => setOffset(Math.max(0, offset - limit))}
          >
            ← Prev
          </button>
          <button
            className="btn btn-xs"
            disabled={offset + limit >= total || loading}
            onClick={() => setOffset(offset + limit)}
          >
            Next →
          </button>
        </div>
      )}
    </div>
  );
}
