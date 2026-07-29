import { useEffect, useState } from "react";
import { Modal } from "../../components/Common";
import type { SendOutcomeDto } from "../../types";

export type MultiSendMode = "repeat" | "parallel";

interface Props {
  open: boolean;
  onClose: () => void;
  onConfirm: (opts: {
    mode: MultiSendMode;
    n: number;
    delay_ms: number;
  }) => Promise<void>;
  /** While request in flight */
  running: boolean;
  elapsedMs: number;
  /** Populated after completion */
  outcomes: SendOutcomeDto[] | null;
}

export default function MultiSendDialog({
  open,
  onClose,
  onConfirm,
  running,
  elapsedMs,
  outcomes,
}: Props) {
  const [mode, setMode] = useState<MultiSendMode>("repeat");
  const [n, setN] = useState(5);
  const [delayMs, setDelayMs] = useState(0);
  const [confirmed, setConfirmed] = useState(false);

  useEffect(() => {
    if (!open) {
      setConfirmed(false);
    }
  }, [open]);

  const start = async () => {
    setConfirmed(true);
    await onConfirm({ mode, n, delay_ms: delayMs });
  };

  const elapsedSec = (elapsedMs / 1000).toFixed(1);

  return (
    <Modal
      open={open}
      onClose={() => {
        if (!running) onClose();
      }}
      title="Send multiple"
      wide
    >
      {!confirmed && !outcomes && (
        <div className="space-y-3">
          <p className="text-xs text-base-content/60">
            Fires N requests from the current draft (same raw message). Cap N ≤ 50.
            Parallel concurrency is the engine default (up to 10). Cancel mid-flight
            is not supported — the browser request may run for a long time.
          </p>
          <div className="flex gap-2">
            <button
              type="button"
              className={`btn btn-sm ${mode === "repeat" ? "btn-primary" : ""}`}
              onClick={() => setMode("repeat")}
            >
              Repeat (sequential)
            </button>
            <button
              type="button"
              className={`btn btn-sm ${mode === "parallel" ? "btn-primary" : ""}`}
              onClick={() => setMode("parallel")}
            >
              Parallel
            </button>
          </div>
          <label className="form-control w-full max-w-xs">
            <span className="label-text text-xs">N (1–50)</span>
            <input
              type="number"
              className="input input-bordered input-sm"
              min={1}
              max={50}
              value={n}
              onChange={(e) =>
                setN(Math.min(50, Math.max(1, Number(e.target.value) || 1)))
              }
            />
          </label>
          {mode === "repeat" && (
            <label className="form-control w-full max-w-xs">
              <span className="label-text text-xs">Delay between sends (ms)</span>
              <input
                type="number"
                className="input input-bordered input-sm"
                min={0}
                value={delayMs}
                onChange={(e) => setDelayMs(Math.max(0, Number(e.target.value) || 0))}
              />
            </label>
          )}
          {mode === "parallel" && (
            <p className="text-xs text-base-content/50">
              Up to 10 concurrent (engine default). Not operator-editable in v1.
            </p>
          )}
          <div className="flex gap-2 justify-end">
            <button type="button" className="btn btn-sm" onClick={onClose}>
              Cancel
            </button>
            <button type="button" className="btn btn-sm btn-primary" onClick={start}>
              Confirm send
            </button>
          </div>
        </div>
      )}

      {(running || (confirmed && !outcomes)) && (
        <div className="flex flex-col items-center gap-3 py-6">
          <span className="loading loading-spinner loading-md" />
          <p className="text-sm">
            {mode === "parallel"
              ? `Sending ${n} concurrent requests (engine concurrency ≤ 10)…`
              : `Sending ${n} requests…`}
          </p>
          <p className="text-xs text-base-content/50 mono">Elapsed {elapsedSec}s</p>
          <p className="text-[10px] text-base-content/40">
            No mid-flight progress or cancel — this is intentional.
          </p>
        </div>
      )}

      {outcomes && (
        <div className="space-y-3">
          <p className="text-xs text-base-content/60">
            Completed in {elapsedSec}s · {outcomes.length} outcome
            {outcomes.length === 1 ? "" : "s"}
          </p>
          <div className="overflow-x-auto max-h-64">
            <table className="table table-xs">
              <thead>
                <tr>
                  <th>#</th>
                  <th>Status</th>
                  <th>Verdict</th>
                  <th>Execution</th>
                  <th>OK</th>
                </tr>
              </thead>
              <tbody>
                {outcomes.map((o, i) => (
                  <tr key={o.execution_flow_id || i}>
                    <td>{i + 1}</td>
                    <td>{o.status_code ?? "—"}</td>
                    <td>{o.verdict ?? "—"}</td>
                    <td className="mono text-[10px]">
                      {o.execution_flow_id?.slice(0, 8) || "—"}
                    </td>
                    <td>{o.success ? "✓" : "✗"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="flex justify-end">
            <button type="button" className="btn btn-sm" onClick={onClose}>
              Close
            </button>
          </div>
        </div>
      )}
    </Modal>
  );
}
