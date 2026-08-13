/**
 * Modal: pick attack modules and run them on one or more flows.
 */

import { ConfirmButton, Modal } from "../../components/Common";
import FlowAttackPicker from "./FlowAttackPicker";
import { estimateFlowAttackJobs } from "./flowAttacks";

export default function FlowAttackRunModal({
  open,
  flowCount,
  selectedAttackIds,
  busy,
  onToggleAttack,
  onClose,
  onRun,
}: {
  open: boolean;
  flowCount: number;
  selectedAttackIds: string[];
  busy: boolean;
  onToggleAttack: (id: string) => void;
  onClose: () => void;
  onRun: () => void | Promise<void>;
}) {
  const estimate = estimateFlowAttackJobs(flowCount, selectedAttackIds);
  const canRun = selectedAttackIds.length > 0 && !busy;

  return (
    <Modal open={open} onClose={onClose} title="Run attacks on selected flows">
      <div className="flex flex-col gap-3">
        <p className="text-xs text-base-content/60">
          {flowCount} flow{flowCount === 1 ? "" : "s"} · only these captures ·
          pick every module you want to fire
        </p>
        <FlowAttackPicker
          flowCount={flowCount}
          selectedIds={selectedAttackIds}
          busy={busy}
          onToggle={onToggleAttack}
        />
        <div className="flex gap-2 flex-wrap">
          {estimate > 50 ? (
            <ConfirmButton
              className="btn btn-sm btn-primary"
              confirmText={`Enqueue ~${estimate} jobs on ${flowCount} flow${flowCount === 1 ? "" : "s"}?`}
              onConfirm={onRun}
            >
              {busy ? <span className="loading loading-spinner loading-xs" /> : "Run selected"}
            </ConfirmButton>
          ) : (
            <button
              type="button"
              className="btn btn-sm btn-primary"
              disabled={!canRun}
              onClick={() => void onRun()}
            >
              {busy ? <span className="loading loading-spinner loading-xs" /> : "Run selected"}
            </button>
          )}
        </div>
      </div>
    </Modal>
  );
}
