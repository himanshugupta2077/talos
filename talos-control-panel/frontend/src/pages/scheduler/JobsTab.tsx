import { useMemo, useState, type MouseEvent } from "react";
import { Link } from "react-router-dom";
import { ConfirmButton, UuidChip } from "../../components/Common";
import DataTable, { Column } from "../../components/DataTable";
import StatusBadge from "../../components/StatusBadge";
import { formatIST } from "../../lib/time";
import type { SchedulerJob } from "../../types";
import {
  FAMILY_OPTIONS,
  LIMIT_OPTIONS,
  familyBadgeClass,
  filterJobsClient,
  isCancellable,
  jobFamily,
  selectClass,
  inputClass,
  type JobFilterState,
  type SchedulerFiltersApi,
} from "./shared";

export default function JobsTab({
  jobs,
  total,
  loading,
  filters,
  filterOptions,
  onFiltersChange,
  onOpenJob,
  onCancelOne,
  onBulkCancel,
  emptyHint,
  showBulkCancel = true,
}: {
  jobs: SchedulerJob[];
  total: number;
  loading?: boolean;
  filters: JobFilterState;
  filterOptions: SchedulerFiltersApi;
  onFiltersChange: (patch: Partial<JobFilterState>) => void;
  onOpenJob: (job: SchedulerJob) => void;
  onCancelOne: (jobId: string) => void;
  onBulkCancel: (jobIds: string[]) => Promise<void>;
  emptyHint?: string;
  showBulkCancel?: boolean;
}) {
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [menuId, setMenuId] = useState<string | null>(null);
  const [bulkBusy, setBulkBusy] = useState(false);

  const visible = useMemo(
    () => filterJobsClient(jobs, filters.search),
    [jobs, filters.search]
  );

  const cancellableSelected = useMemo(() => {
    return visible.filter(
      (j) => selected.has(j.job_id) && isCancellable(j.status)
    );
  }, [visible, selected]);

  const toggleRow = (id: string, e?: MouseEvent) => {
    e?.stopPropagation();
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const togglePage = () => {
    const pageIds = visible.map((j) => j.job_id);
    const allOn = pageIds.every((id) => selected.has(id));
    setSelected((prev) => {
      const next = new Set(prev);
      if (allOn) pageIds.forEach((id) => next.delete(id));
      else pageIds.forEach((id) => next.add(id));
      return next;
    });
  };

  const columns: Column<SchedulerJob>[] = [
    {
      key: "select",
      header: (
        <input
          type="checkbox"
          className="checkbox checkbox-xs"
          checked={
            visible.length > 0 && visible.every((j) => selected.has(j.job_id))
          }
          onChange={togglePage}
          onClick={(e) => e.stopPropagation()}
          aria-label="Select all on page"
        />
      ),
      sortable: false,
      alwaysVisible: true,
      render: (j) => (
        <input
          type="checkbox"
          className="checkbox checkbox-xs"
          checked={selected.has(j.job_id)}
          onChange={() => toggleRow(j.job_id)}
          onClick={(e) => e.stopPropagation()}
          aria-label="Select job"
        />
      ),
    },
    {
      key: "job_id",
      header: "Job ID",
      alwaysVisible: true,
      render: (j) => <UuidChip value={j.job_id} />,
    },
    {
      key: "status",
      header: "Status",
      render: (j) => <StatusBadge value={j.status} />,
    },
    {
      key: "job_type",
      header: "Type",
      render: (j) => {
        const fam = jobFamily(j.job_type);
        return (
          <span className="inline-flex items-center gap-1 flex-wrap">
            <span
              className={`badge badge-xs ${familyBadgeClass(fam)} uppercase`}
            >
              {fam}
            </span>
            <span className="mono text-[11px]">{j.job_type}</span>
          </span>
        );
      },
    },
    {
      key: "priority",
      header: "Pri",
      className: "mono text-xs",
      render: (j) => j.priority,
    },
    {
      key: "role_name",
      header: "Role",
      render: (j) =>
        j.role_name || <span className="text-base-content/30">—</span>,
    },
    {
      key: "module_name",
      header: "Module",
      render: (j) =>
        j.module_name || <span className="text-base-content/30">—</span>,
    },
    {
      key: "target",
      header: "Target",
      sortable: false,
      render: (j) => {
        const ep = j.resolved_endpoint_id || j.endpoint_id;
        if (j.flow_id) return <UuidChip value={j.flow_id} />;
        if (ep) return <UuidChip value={ep} />;
        return <span className="text-base-content/30">—</span>;
      },
    },
    {
      key: "verdict",
      header: "Verdict",
      render: (j) => <StatusBadge value={j.verdict} />,
    },
    {
      key: "failure_reason",
      header: "Reason",
      className: "text-xs max-w-[12rem] truncate",
      render: (j) =>
        j.failure_reason || (
          <span className="text-base-content/30">—</span>
        ),
    },
    {
      key: "created_at",
      header: "Created",
      className: "text-xs whitespace-nowrap",
      sortValue: (j) => j.created_at,
      render: (j) => formatIST(j.created_at),
    },
    {
      key: "finished_at",
      header: "Finished",
      className: "text-xs whitespace-nowrap",
      sortValue: (j) => j.finished_at,
      render: (j) =>
        j.finished_at ? (
          formatIST(j.finished_at)
        ) : (
          <span className="text-base-content/30">—</span>
        ),
    },
    {
      key: "actions",
      header: "Actions",
      sortable: false,
      alwaysVisible: true,
      defaultWidth: 72,
      minWidth: 56,
      render: (j) => (
        <div
          className="dropdown dropdown-end"
          onClick={(e) => e.stopPropagation()}
        >
          <button
            type="button"
            tabIndex={0}
            className="btn btn-xs btn-ghost"
            onClick={() =>
              setMenuId(menuId === j.job_id ? null : j.job_id)
            }
          >
            ⋮
          </button>
          {menuId === j.job_id && (
            <ul className="dropdown-content z-30 menu p-2 shadow bg-base-200 rounded-box w-48 border border-base-300 text-sm">
              <li>
                <button
                  type="button"
                  onClick={() => {
                    setMenuId(null);
                    onOpenJob(j);
                  }}
                >
                  Show detail
                </button>
              </li>
              {isCancellable(j.status) && (
                <li>
                  <button
                    type="button"
                    onClick={() => {
                      setMenuId(null);
                      onCancelOne(j.job_id);
                    }}
                  >
                    Cancel
                  </button>
                </li>
              )}
              {j.flow_id && (
                <li>
                  <Link
                    to={`/flows/${j.flow_id}`}
                    target="_blank"
                    onClick={() => setMenuId(null)}
                  >
                    Open flow
                  </Link>
                </li>
              )}
              {(j.resolved_endpoint_id || j.endpoint_id) && (
                <li>
                  <Link
                    to={`/endpoints/${j.resolved_endpoint_id || j.endpoint_id}`}
                    target="_blank"
                    onClick={() => setMenuId(null)}
                  >
                    Open endpoint
                  </Link>
                </li>
              )}
              {j.replayed_flow_id && (
                <li>
                  <Link
                    to={`/flows/${j.replayed_flow_id}`}
                    target="_blank"
                    onClick={() => setMenuId(null)}
                  >
                    Open replayed flow
                  </Link>
                </li>
              )}
            </ul>
          )}
        </div>
      ),
    },
  ];

  // Type options: families + discovered extras from API
  const typeOptions = useMemo(() => {
    const fams = new Set(FAMILY_OPTIONS.map((f) => f.value));
    const extras = (filterOptions.job_types || []).filter(
      (t) => !fams.has(t as (typeof FAMILY_OPTIONS)[number]["value"])
    );
    return [
      ...FAMILY_OPTIONS.map((f) => f.value),
      ...extras,
    ];
  }, [filterOptions.job_types]);

  return (
    <div>
      <div className="flex flex-wrap items-center gap-2 mb-3">
        <select
          className={selectClass}
          value={filters.jobType}
          onChange={(e) => onFiltersChange({ jobType: e.target.value })}
        >
          <option value="">type: any</option>
          {typeOptions.map((t) => (
            <option key={t} value={t}>
              {t}
            </option>
          ))}
        </select>
        <select
          className={selectClass}
          value={filters.status}
          onChange={(e) => onFiltersChange({ status: e.target.value })}
        >
          <option value="">status: all</option>
          <option value="active">active</option>
          {(filterOptions.statuses || []).map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
        <select
          className={selectClass}
          value={filters.role}
          onChange={(e) => onFiltersChange({ role: e.target.value })}
        >
          <option value="">role: any</option>
          {filterOptions.roles.map((r) => (
            <option key={r} value={r}>
              {r}
            </option>
          ))}
        </select>
        <select
          className={selectClass}
          value={filters.module}
          onChange={(e) => onFiltersChange({ module: e.target.value })}
        >
          <option value="">module: any</option>
          {filterOptions.modules.map((m) => (
            <option key={m} value={m}>
              {m}
            </option>
          ))}
        </select>
        <select
          className={selectClass}
          value={filters.limit}
          onChange={(e) =>
            onFiltersChange({ limit: Number(e.target.value) || 100 })
          }
        >
          {LIMIT_OPTIONS.map((n) => (
            <option key={n} value={n}>
              limit {n}
            </option>
          ))}
        </select>
        <input
          className={`${inputClass} w-40`}
          placeholder="search id/type/reason"
          value={filters.search}
          onChange={(e) => onFiltersChange({ search: e.target.value })}
        />
        <span className="text-xs text-base-content/50 ml-auto">
          {visible.length}
          {filters.search ? ` filtered` : ""} / {total} total
        </span>
      </div>

      {showBulkCancel && cancellableSelected.length > 0 && (
        <div className="flex items-center gap-2 mb-2 panel p-2">
          <span className="text-xs">
            {cancellableSelected.length} cancellable selected
          </span>
          <ConfirmButton
            className="btn btn-xs btn-error"
            confirmText={`Cancel ${cancellableSelected.length} job(s)?`}
            onConfirm={async () => {
              setBulkBusy(true);
              try {
                await onBulkCancel(
                  cancellableSelected.map((j) => j.job_id)
                );
                setSelected(new Set());
              } finally {
                setBulkBusy(false);
              }
            }}
          >
            {bulkBusy
              ? "Cancelling…"
              : `Cancel ${cancellableSelected.length}`}
          </ConfirmButton>
          <button
            type="button"
            className="btn btn-xs btn-ghost"
            onClick={() => setSelected(new Set())}
          >
            Clear selection
          </button>
        </div>
      )}

      <DataTable
        columns={columns}
        rows={visible}
        rowKey={(j) => j.job_id}
        storageKey="scheduler-jobs-v2"
        loading={loading}
        onRowClick={(j) => onOpenJob(j)}
        emptyLabel={emptyHint || "No jobs match filters."}
      />
    </div>
  );
}
