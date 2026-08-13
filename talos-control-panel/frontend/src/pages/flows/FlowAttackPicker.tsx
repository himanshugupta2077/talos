/**
 * Shared attack picker for the Flows bulk bar and the flow Actions modal.
 */

import { Link } from "react-router-dom";
import { FLOW_ATTACKS, estimateFlowAttackJobs } from "./flowAttacks";

export default function FlowAttackPicker({
  flowCount,
  selectedIds,
  busy,
  onToggle,
}: {
  flowCount: number;
  selectedIds: string[];
  busy: boolean;
  onToggle: (id: string) => void;
}) {
  const selected = new Set(selectedIds);
  const estimate = estimateFlowAttackJobs(flowCount, selectedIds);

  return (
    <div className="space-y-2">
      <div className="flex flex-wrap gap-1">
        {FLOW_ATTACKS.map((attack) => {
          const soon = attack.status !== "available";
          const on = selected.has(attack.id);
          return (
            <button
              key={attack.id}
              type="button"
              className={`btn btn-xs ${on && !soon ? "btn-primary" : "btn-ghost"}`}
              disabled={soon || busy}
              title={
                soon
                  ? `${attack.name} — needs a session template (open Intruder)`
                  : `${attack.description} (${attack.cliHint})`
              }
              onClick={() => onToggle(attack.id)}
            >
              {attack.shortLabel}
              {soon && (
                <span className="ml-1 text-[10px] font-normal opacity-70">soon</span>
              )}
            </button>
          );
        })}
      </div>
      <p className="text-[11px] text-base-content/50">
        {estimate > 0 ? (
          <>
            ~{estimate} job{estimate === 1 ? "" : "s"} on {flowCount} flow
            {flowCount === 1 ? "" : "s"} · only the selected captures
          </>
        ) : (
          <>Pick at least one attack. Intruder still needs a configured session.</>
        )}
        {" · "}
        <Link to="/testing" className="link">
          Testing hub
        </Link>
      </p>
    </div>
  );
}
