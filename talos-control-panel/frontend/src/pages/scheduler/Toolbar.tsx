/**
 * Compact scheduler action bar:
 * Play/Pause | Refresh | Clear Queue | Prune (confirm panel) | Process switch
 */

import { useEffect, useRef, useState } from "react";
import { ConfirmButton } from "../../components/Common";
import type { SchedulerStatus } from "../../api/client";
import { isProcessLive, PRUNEABLE_STATUSES } from "./shared";

function PlayIcon({ className = "h-4 w-4" }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="currentColor" aria-hidden>
      <path d="M8 5.14v13.72a1 1 0 0 0 1.5.86l11-6.86a1 1 0 0 0 0-1.72l-11-6.86a1 1 0 0 0-1.5.86z" />
    </svg>
  );
}

function PauseIcon({ className = "h-4 w-4" }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="currentColor" aria-hidden>
      <rect x="6" y="5" width="4" height="14" rx="1.2" />
      <rect x="14" y="5" width="4" height="14" rx="1.2" />
    </svg>
  );
}

export default function Toolbar({
  status,
  busy,
  onPlay,
  onPause,
  onRefresh,
  onClear,
  onPrune,
  onStart,
  onStop,
}: {
  status: SchedulerStatus | null;
  busy: boolean;
  onPlay: () => void;
  onPause: () => void;
  onRefresh: () => void;
  onClear: () => Promise<void>;
  onPrune: (status: string) => Promise<void>;
  onStart: () => void;
  onStop: () => void;
}) {
  const queueRunning = (status?.state?.state || "").toLowerCase() === "running";
  const processLive = isProcessLive(status?.process);
  const pendingCount = Number(status?.counts?.pending || 0);
  const counts = status?.counts || {};

  const [pruneOpen, setPruneOpen] = useState(false);
  const [pruneStatus, setPruneStatus] = useState<string>("done");
  const [pruneBusy, setPruneBusy] = useState(false);
  const pruneRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!pruneOpen) return;
    const onDoc = (e: MouseEvent) => {
      if (pruneRef.current && !pruneRef.current.contains(e.target as Node)) {
        setPruneOpen(false);
      }
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setPruneOpen(false);
    };
    document.addEventListener("mousedown", onDoc);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDoc);
      document.removeEventListener("keydown", onKey);
    };
  }, [pruneOpen]);

  const pruneCount = Number(counts[pruneStatus] || 0);

  return (
    <div className="flex items-center gap-2 flex-wrap">
      {/* Play / Pause — queue execution */}
      {queueRunning ? (
        <button
          type="button"
          className="btn btn-sm btn-warning gap-1.5"
          disabled={busy}
          aria-label="Pause queue"
          title="Pause queue execution"
          onClick={onPause}
        >
          <PauseIcon className="h-3.5 w-3.5" />
          Pause
        </button>
      ) : (
        <button
          type="button"
          className="btn btn-sm btn-success gap-1.5"
          disabled={busy}
          aria-label="Resume queue"
          title="Resume queue execution"
          onClick={onPlay}
        >
          <PlayIcon className="h-3.5 w-3.5" />
          Play
        </button>
      )}

      <button
        type="button"
        className="btn btn-sm btn-ghost"
        disabled={busy}
        onClick={onRefresh}
      >
        Refresh
      </button>

      <ConfirmButton
        className="btn btn-sm btn-ghost text-error"
        confirmText={`Clear ${pendingCount} pending?`}
        onConfirm={onClear}
      >
        Clear queue
        {pendingCount > 0 ? ` (${pendingCount})` : ""}
      </ConfirmButton>

      {/* Prune: click opens confirm panel */}
      <div className="relative" ref={pruneRef}>
        <button
          type="button"
          className="btn btn-sm btn-ghost"
          disabled={busy}
          onClick={() => setPruneOpen((o) => !o)}
        >
          Prune
        </button>

        {pruneOpen && (
          <div className="absolute right-0 top-full mt-1 z-30 w-64 rounded-lg border border-base-300 bg-base-100 shadow-lg p-3">
            <div className="text-xs font-medium mb-2">Prune terminal jobs</div>
            <p className="text-[11px] text-base-content/50 mb-2">
              Deletes history for one status. Active jobs are not touched.
            </p>
            <div className="flex flex-col gap-1 mb-3">
              {PRUNEABLE_STATUSES.map((s) => {
                const n = Number(counts[s] || 0);
                return (
                  <label
                    key={s}
                    className={[
                      "flex items-center justify-between gap-2 px-2 py-1.5 rounded cursor-pointer text-sm",
                      pruneStatus === s
                        ? "bg-primary/10 border border-primary/30"
                        : "hover:bg-base-200 border border-transparent",
                    ].join(" ")}
                  >
                    <span className="inline-flex items-center gap-2">
                      <input
                        type="radio"
                        name="prune-status"
                        className="radio radio-xs radio-primary"
                        checked={pruneStatus === s}
                        onChange={() => setPruneStatus(s)}
                      />
                      <span className="capitalize">{s}</span>
                    </span>
                    <span className="mono text-xs text-base-content/60">{n}</span>
                  </label>
                );
              })}
            </div>
            <div className="flex items-center justify-end gap-2">
              <button
                type="button"
                className="btn btn-xs btn-ghost"
                onClick={() => setPruneOpen(false)}
              >
                Cancel
              </button>
              <button
                type="button"
                className="btn btn-xs btn-error"
                disabled={pruneBusy || pruneCount <= 0}
                onClick={async () => {
                  setPruneBusy(true);
                  try {
                    await onPrune(pruneStatus);
                    setPruneOpen(false);
                  } finally {
                    setPruneBusy(false);
                  }
                }}
              >
                {pruneBusy
                  ? "Pruning…"
                  : `Prune ${pruneCount} ${pruneStatus}`}
              </button>
            </div>
          </div>
        )}
      </div>

      <div className="w-px h-5 bg-base-300 mx-0.5 hidden sm:block" />

      {/* Process start/stop switch */}
      <label
        className={[
          "inline-flex items-center gap-2 cursor-pointer select-none pl-0.5",
          busy ? "opacity-60 pointer-events-none" : "",
        ].join(" ")}
        title={
          processLive
            ? "Scheduler process is running — turn off to stop"
            : "Scheduler process is stopped — turn on to start"
        }
      >
        <span className="text-xs text-base-content/50 whitespace-nowrap">
          Process
        </span>
        <input
          type="checkbox"
          className="toggle toggle-sm toggle-success"
          checked={processLive}
          disabled={busy}
          onChange={() => {
            if (processLive) onStop();
            else onStart();
          }}
        />
        <span
          className={[
            "text-xs font-medium mono w-8",
            processLive ? "text-success" : "text-base-content/40",
          ].join(" ")}
        >
          {processLive ? "ON" : "OFF"}
        </span>
      </label>
    </div>
  );
}
