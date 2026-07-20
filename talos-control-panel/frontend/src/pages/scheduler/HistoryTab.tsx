import type { SchedulerJob } from "../../types";
import JobsTab from "./JobsTab";
import type { JobFilterState, SchedulerFiltersApi } from "./shared";

/**
 * Terminal-focused inventory: same table, history defaults.
 * Prune is on the page toolbar (not duplicated here).
 */
export default function HistoryTab({
  jobs,
  total,
  loading,
  filters,
  filterOptions,
  onFiltersChange,
  onOpenJob,
  onCancelOne,
  onBulkCancel,
}: {
  jobs: SchedulerJob[];
  total: number;
  loading?: boolean;
  filters: JobFilterState;
  filterOptions: SchedulerFiltersApi;
  counts?: Record<string, number>;
  onFiltersChange: (patch: Partial<JobFilterState>) => void;
  onOpenJob: (job: SchedulerJob) => void;
  onCancelOne: (jobId: string) => void;
  onBulkCancel: (jobIds: string[]) => Promise<void>;
  onPrune?: (status: string) => Promise<void>;
  pruneBusy?: boolean;
}) {
  return (
    <JobsTab
      jobs={jobs}
      total={total}
      loading={loading}
      filters={filters}
      filterOptions={filterOptions}
      onFiltersChange={onFiltersChange}
      onOpenJob={onOpenJob}
      onCancelOne={onCancelOne}
      onBulkCancel={onBulkCancel}
      emptyHint={`No ${filters.status || "terminal"} jobs.`}
      showBulkCancel={false}
    />
  );
}
