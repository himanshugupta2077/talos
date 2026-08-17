import { Link } from "react-router-dom";
import type { SchedulerStatus } from "../../api/client";
import { attackModuleShortLabel } from "../../lib/attackDisplay";
import { formatIST } from "../../lib/time";
import { COUNT_CHIP_KEYS, familyBadgeClass } from "./shared";

export default function MetricsStrip({
  status,
  selectedStatus,
  selectedJobType,
  onStatusChip,
  onTypeChip,
  rateConfig,
}: {
  status: SchedulerStatus | null;
  selectedStatus: string;
  selectedJobType: string;
  onStatusChip: (status: string) => void;
  onTypeChip: (jobType: string) => void;
  rateConfig: {
    min_delay: unknown;
    max_delay: unknown;
    max_queue_size: unknown;
    sources: Record<string, string>;
  } | null;
}) {
  const counts = status?.counts || {};
  const active =
    Number(counts.pending || 0) +
    Number(counts.running || 0) +
    Number(counts.paused || 0);
  const all = Object.values(counts).reduce((s, n) => s + (Number(n) || 0), 0);

  const chipCount = (key: string): number => {
    if (key === "active") return active;
    if (key === "all") return all;
    return Number(counts[key] || 0);
  };

  const chipFilterValue = (key: string): string => {
    if (key === "all") return "";
    return key;
  };

  const isSelected = (key: string): boolean => {
    if (key === "all") return selectedStatus === "";
    return selectedStatus === key;
  };

  const metrics = status?.metrics;
  const avg = metrics?.avg_execution_delay_s;
  const last = metrics?.last_executed_at;
  const fill = status?.queue_fill_pct ?? 0;
  const maxQ =
    rateConfig?.max_queue_size ?? status?.config?.max_queue_size ?? "—";
  const minD = rateConfig?.min_delay ?? status?.config?.min_delay ?? "—";
  const maxD = rateConfig?.max_delay ?? status?.config?.max_delay ?? "—";
  const src =
    rateConfig?.sources?.max_delay ||
    rateConfig?.sources?.min_delay ||
    "default";

  const families = (status?.by_family || []).filter((row) => row.n > 0);

  return (
    <div className="space-y-3 mb-4">
      <div className="flex flex-wrap gap-1.5">
        {COUNT_CHIP_KEYS.map((key) => {
          const n = chipCount(key);
          const selected = isSelected(key);
          return (
            <button
              key={key}
              type="button"
              className={[
                "btn btn-xs gap-1.5 font-normal",
                selected ? "btn-primary" : "btn-ghost border border-base-300",
              ].join(" ")}
              onClick={() => onStatusChip(chipFilterValue(key))}
            >
              <span className="capitalize">{key}</span>
              <span className="mono font-medium opacity-80">{n}</span>
            </button>
          );
        })}
      </div>

      {families.length > 0 && (
        <div>
          <div className="text-[10px] uppercase tracking-wide text-base-content/45 mb-1.5">
            Requests by type
          </div>
          <div className="flex flex-wrap gap-1.5">
            {families.map((row) => {
              const selected = selectedJobType === row.family;
              return (
                <button
                  key={row.family}
                  type="button"
                  className={[
                    "btn btn-xs gap-1.5 font-normal",
                    selected
                      ? "btn-primary"
                      : "btn-ghost border border-base-300",
                  ].join(" ")}
                  title={`${row.family}: ${row.n} job${row.n === 1 ? "" : "s"}`}
                  onClick={() =>
                    onTypeChip(selected ? "" : row.family)
                  }
                >
                  <span
                    className={`badge badge-xs ${familyBadgeClass(row.family)}`}
                  >
                    {attackModuleShortLabel(row.family)}
                  </span>
                  <span className="mono font-medium opacity-80">{row.n}</span>
                </button>
              );
            })}
          </div>
        </div>
      )}

      <div className="panel p-3 flex flex-wrap items-center justify-between gap-3 text-sm">
        <div className="flex flex-wrap gap-4">
          <div>
            <span className="text-base-content/50 text-[10px] uppercase block">
              Avg delay
            </span>
            <span className="mono text-xs">
              {avg != null && Number.isFinite(Number(avg))
                ? `${Number(avg).toFixed(1)}s`
                : "—"}
            </span>
          </div>
          <div>
            <span className="text-base-content/50 text-[10px] uppercase block">
              Last executed
            </span>
            <span className="mono text-xs whitespace-nowrap">
              {last ? formatIST(last) : "—"}
            </span>
          </div>
          <div>
            <span className="text-base-content/50 text-[10px] uppercase block">
              Queue fill
            </span>
            <span className="mono text-xs">
              {fill}% · limit {String(maxQ)}
            </span>
          </div>
          <div>
            <span className="text-base-content/50 text-[10px] uppercase block">
              Delay range
            </span>
            <span className="mono text-xs">
              {String(minD)}–{String(maxD)} s
            </span>
          </div>
          <div>
            <span className="text-base-content/50 text-[10px] uppercase block">
              Config source
            </span>
            <span className="badge badge-sm badge-ghost uppercase">{src}</span>
          </div>
          <div>
            <span className="text-base-content/50 text-[10px] uppercase block">
              Testing windows (IST)
            </span>
            <span className="mono text-xs">
              {status?.testing_windows?.enabled
                ? `${status.testing_windows.allows_execution ? "sending" : "holding"} · ${status.testing_windows.now_ist} IST`
                : "off"}
            </span>
          </div>
        </div>
        <Link
          className="link link-primary text-xs shrink-0"
          to="/talos-config?tab=settings&section=scheduler"
        >
          Talos Config →
        </Link>
      </div>
    </div>
  );
}
