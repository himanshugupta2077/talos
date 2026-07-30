import { FieldHint } from "../../../components/Common";
import {
  DEFAULT_MAX_CONCURRENCY,
  DEFAULT_RPS,
  TIMING_MODES,
} from "../shared";
import type { IntruderTimingMode } from "../types";

export interface TimingValues {
  mode: IntruderTimingMode | string;
  rps: number;
  max_concurrency: number;
  jitter_ms?: number;
  timeout_s?: number;
  burst_size?: number;
  min_rps?: number;
  max_rps?: number;
  slow_ms?: number;
  max_concurrency_per_host?: number | null;
}

export default function TimingPanel({
  value,
  onChange,
  compact = false,
}: {
  value: TimingValues;
  onChange: (p: TimingValues) => void;
  /** MVP strip: only RPS + concurrency with fixed mode. */
  compact?: boolean;
}) {
  const mode = (value.mode || "fixed") as string;
  const rps = value.rps ?? DEFAULT_RPS;
  const concurrency = value.max_concurrency ?? DEFAULT_MAX_CONCURRENCY;
  const highRps = rps > DEFAULT_RPS;
  const highConc = concurrency > DEFAULT_MAX_CONCURRENCY;

  const patch = (partial: Partial<TimingValues>) =>
    onChange({ ...value, ...partial });

  return (
    <div className="space-y-2">
      <div className="text-sm font-medium">
        Timing
        <FieldHint text="Unlimited mode stays CLI-only. Adaptive/token_bucket available here." />
      </div>
      <div className="text-xs text-base-content/60">
        Default 1 concurrency / 2 RPS for stealth.
      </div>

      {!compact && (
        <div className="flex flex-wrap gap-1.5">
          {TIMING_MODES.map((m) => (
            <button
              key={m}
              type="button"
              className={`btn btn-xs ${mode === m ? "btn-primary" : "btn-ghost"}`}
              onClick={() => patch({ mode: m })}
            >
              {m}
            </button>
          ))}
        </div>
      )}
      {compact && (
        <div className="text-xs text-base-content/50">
          Mode: <span className="mono">{mode}</span> (expand Advanced for
          token_bucket / adaptive)
        </div>
      )}

      <div className="grid grid-cols-2 gap-2 max-w-md">
        <label className="form-control">
          <span className="label-text text-xs">
            {mode === "adaptive" ? "Initial RPS" : "RPS"}
          </span>
          <input
            type="number"
            min={0.1}
            step={0.5}
            className="input input-bordered input-sm"
            value={rps}
            onChange={(e) =>
              patch({ rps: Number(e.target.value) || DEFAULT_RPS })
            }
          />
        </label>
        <label className="form-control">
          <span className="label-text text-xs">Max concurrency</span>
          <input
            type="number"
            min={1}
            step={1}
            className="input input-bordered input-sm"
            value={concurrency}
            onChange={(e) =>
              patch({
                max_concurrency: Math.max(
                  1,
                  Math.floor(Number(e.target.value) || 1)
                ),
              })
            }
          />
        </label>
      </div>

      {!compact && mode === "token_bucket" && (
        <label className="form-control max-w-[10rem]">
          <span className="label-text text-xs">Burst size</span>
          <input
            type="number"
            min={1}
            className="input input-bordered input-sm"
            value={value.burst_size ?? 1}
            onChange={(e) =>
              patch({
                burst_size: Math.max(1, Math.floor(Number(e.target.value) || 1)),
              })
            }
          />
        </label>
      )}

      {!compact && mode === "adaptive" && (
        <div className="grid grid-cols-2 gap-2 max-w-md">
          <label className="form-control">
            <span className="label-text text-xs">Min RPS</span>
            <input
              type="number"
              min={0.1}
              step={0.1}
              className="input input-bordered input-sm"
              value={value.min_rps ?? 0.25}
              onChange={(e) =>
                patch({ min_rps: Number(e.target.value) || 0.25 })
              }
            />
          </label>
          <label className="form-control">
            <span className="label-text text-xs">Max RPS</span>
            <input
              type="number"
              min={0.1}
              step={0.5}
              className="input input-bordered input-sm"
              value={value.max_rps ?? 10}
              onChange={(e) =>
                patch({ max_rps: Number(e.target.value) || 10 })
              }
            />
          </label>
          <label className="form-control col-span-2">
            <span className="label-text text-xs">Slow threshold (ms)</span>
            <input
              type="number"
              min={100}
              className="input input-bordered input-sm"
              value={value.slow_ms ?? 2000}
              onChange={(e) =>
                patch({ slow_ms: Number(e.target.value) || 2000 })
              }
            />
          </label>
        </div>
      )}

      {!compact && (
        <div className="grid grid-cols-2 gap-2 max-w-md">
          <label className="form-control">
            <span className="label-text text-xs">Jitter (ms)</span>
            <input
              type="number"
              min={0}
              className="input input-bordered input-sm"
              value={value.jitter_ms ?? 0}
              onChange={(e) =>
                patch({ jitter_ms: Math.max(0, Number(e.target.value) || 0) })
              }
            />
          </label>
          <label className="form-control">
            <span className="label-text text-xs">Timeout (s)</span>
            <input
              type="number"
              min={1}
              className="input input-bordered input-sm"
              value={value.timeout_s ?? 30}
              onChange={(e) =>
                patch({ timeout_s: Math.max(1, Number(e.target.value) || 30) })
              }
            />
          </label>
        </div>
      )}

      {highRps && (
        <div className="text-xs text-warning">
          RPS {rps} is above the default ({DEFAULT_RPS}) — increases load on the
          target.
        </div>
      )}
      {highConc && (
        <div className="text-xs text-warning">
          Concurrency {concurrency} &gt; 1 increases load on the target and
          local host.
        </div>
      )}
    </div>
  );
}
