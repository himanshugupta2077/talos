import { formatRelative, shortId } from "./shared";
import SessionStatusBadge from "./components/SessionStatusBadge";
import type { IntruderSessionSummary } from "./types";

const STATUS_FILTERS = [
  { id: "", label: "All" },
  { id: "running", label: "Running" },
  { id: "paused", label: "Paused" },
  { id: "draft", label: "Draft" },
  { id: "configured", label: "Configured" },
  { id: "completed", label: "Done" },
  { id: "failed", label: "Failed" },
];

export default function SessionList({
  sessions,
  loading,
  selectedId,
  statusFilter,
  onStatusFilter,
  onSelect,
  onNew,
}: {
  sessions: IntruderSessionSummary[];
  loading: boolean;
  selectedId: string | null;
  statusFilter: string;
  onStatusFilter: (s: string) => void;
  onSelect: (id: string) => void;
  onNew?: () => void;
}) {
  return (
    <div className="flex flex-col h-full min-h-0 border-r border-base-300 bg-base-200/20">
      <div className="px-3 py-2 border-b border-base-300 flex items-center justify-between gap-2">
        <span className="text-sm font-semibold">Sessions</span>
        {onNew && (
          <button type="button" className="btn btn-xs btn-primary" onClick={onNew}>
            + New
          </button>
        )}
      </div>
      <div className="px-2 py-1.5 flex flex-wrap gap-1 border-b border-base-300">
        {STATUS_FILTERS.map((f) => (
          <button
            key={f.id || "all"}
            type="button"
            className={`badge badge-sm cursor-pointer ${
              statusFilter === f.id ? "badge-primary" : "badge-ghost"
            }`}
            onClick={() => onStatusFilter(f.id)}
          >
            {f.label}
          </button>
        ))}
      </div>
      <div className="flex-1 overflow-y-auto">
        {loading && (
          <div className="p-4 text-xs text-base-content/50">Loading…</div>
        )}
        {!loading && sessions.length === 0 && (
          <div className="p-4 text-xs text-base-content/50 space-y-2">
            <p>No sessions yet.</p>
            <p>
              Send a flow from <strong>Flows</strong> or{" "}
              <strong>Repeater</strong> → Send to Intruder.
            </p>
          </div>
        )}
        <ul className="divide-y divide-base-300">
          {sessions.map((s) => {
            const sent = s.progress?.sent;
            const est = s.progress?.estimate_total ?? s.estimate_attempts;
            const active = s.status === "running" || s.status === "queued";
            const interesting = Number(s.progress?.interesting ?? 0);
            return (
              <li key={s.id}>
                <button
                  type="button"
                  className={`w-full text-left px-3 py-2.5 hover:bg-base-200/80 transition-colors ${
                    selectedId === s.id
                      ? "bg-primary/10 border-l-2 border-primary"
                      : ""
                  }`}
                  onClick={() => onSelect(s.id)}
                >
                  <div className="flex items-center justify-between gap-1 mb-0.5">
                    <span className="text-sm font-medium truncate">
                      {s.name || shortId(s.id)}
                    </span>
                    <SessionStatusBadge status={s.status} />
                  </div>
                  {s.baseline_label && (
                    <div
                      className="text-[11px] mono text-base-content/45 truncate mb-0.5"
                      title={s.baseline_label}
                    >
                      {s.baseline_label}
                    </div>
                  )}
                  <div className="text-[11px] text-base-content/50 flex flex-wrap gap-x-2">
                    <span className="mono">{shortId(s.id)}</span>
                    <span>{formatRelative(s.updated_at)}</span>
                    {interesting > 0 && (
                      <span className="text-warning">★ {interesting}</span>
                    )}
                  </div>
                  {active && (
                    <div className="text-[11px] text-info mt-0.5 mono">
                      {sent ?? 0}
                      {est != null ? ` / ${est}` : ""} sent
                    </div>
                  )}
                  {s.failure_reason && s.status === "failed" && (
                    <div className="text-[10px] text-error mt-0.5 truncate">
                      {s.failure_reason}
                    </div>
                  )}
                </button>
              </li>
            );
          })}
        </ul>
      </div>
    </div>
  );
}
