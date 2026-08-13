/**
 * Sticky bar: run one or more attack modules on selected flows.
 */

import { ConfirmButton } from "../../components/Common";
import FlowAttackPicker from "./FlowAttackPicker";
import { estimateFlowAttackJobs } from "./flowAttacks";

export default function FlowsAttackBar({
  flowCount,
  selectedAttackIds,
  busy,
  onToggleAttack,
  onClear,
  onRun,
}: {
  flowCount: number;
  selectedAttackIds: string[];
  busy: boolean;
  onToggleAttack: (id: string) => void;
  onClear: () => void;
  onRun: () => void | Promise<void>;
}) {
  if (flowCount === 0) return null;

  const estimate = estimateFlowAttackJobs(flowCount, selectedAttackIds);
  const canRun = selectedAttackIds.length > 0 && !busy;
  const nAttacks = selectedAttackIds.length;
  const label = `Run ${nAttacks || ""} attack${nAttacks === 1 ? "" : "s"}`.trim();

  return (
    <div className="sticky bottom-3 z-20 mx-auto max-w-4xl">
      <div className="panel border border-primary/30 shadow-lg px-3 py-2 space-y-2 bg-base-100">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-xs font-medium shrink-0">
            {flowCount} flow{flowCount === 1 ? "" : "s"} selected
          </span>
          <span className="text-[11px] text-base-content/50">
            Choose attacks to run on these flows only
          </span>
          <button
            type="button"
            className="btn btn-xs btn-ghost ml-auto"
            disabled={busy}
            onClick={onClear}
          >
            Clear
          </button>
        </div>
        <FlowAttackPicker
          flowCount={flowCount}
          selectedIds={selectedAttackIds}
          busy={busy}
          onToggle={onToggleAttack}
        />
        <div className="flex flex-wrap items-center gap-2">
          {estimate > 50 ? (
            <ConfirmButton
              className="btn btn-xs btn-primary"
              confirmText={`Enqueue ~${estimate} jobs on ${flowCount} flow${flowCount === 1 ? "" : "s"}?`}
              onConfirm={onRun}
            >
              {busy ? <span className="loading loading-spinner loading-xs" /> : label}
            </ConfirmButton>
          ) : (
            <button
              type="button"
              className="btn btn-xs btn-primary"
              disabled={!canRun}
              onClick={() => void onRun()}
            >
              {busy ? <span className="loading loading-spinner loading-xs" /> : label}
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
