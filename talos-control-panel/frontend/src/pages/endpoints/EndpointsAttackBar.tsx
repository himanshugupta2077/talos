/**
 * Attack launcher for Inventory multi-select.
 * Resolves top 1–5 ranked test flows per selected endpoint, then reuses
 * the same flow-targeted attack catalog as the Flows table.
 */

import { useEffect, useState } from "react";
import { api } from "../../api/client";
import { ConfirmButton } from "../../components/Common";
import { useAction } from "../../hooks/useAction";
import FlowAttackPicker from "../flows/FlowAttackPicker";
import {
  defaultSelectedAttackIds,
  estimateFlowAttackJobs,
  runFlowAttacks,
} from "../flows/flowAttacks";

interface TestFlowsResponse {
  flow_ids?: string[];
  flows?: { flow_id: string }[];
  skipped_endpoints?: string[];
  limit_per_endpoint?: number;
}

export default function EndpointsAttackBar({
  projectId,
  endpointIds,
  busy: parentBusy,
}: {
  projectId: string;
  endpointIds: string[];
  busy?: boolean;
}) {
  const [attackIds, setAttackIds] = useState<string[]>(defaultSelectedAttackIds);
  const [flowIds, setFlowIds] = useState<string[]>([]);
  const [skipped, setSkipped] = useState(0);
  const [resolving, setResolving] = useState(false);
  const runAttacks = useAction("Run attacks on selected endpoints", () =>
    runFlowAttacks(projectId, flowIds, attackIds)
  );

  const endpointKey = endpointIds.join(",");

  useEffect(() => {
    if (!projectId || !endpointKey) {
      setFlowIds([]);
      setSkipped(0);
      return;
    }
    const ids = endpointKey.split(",").filter(Boolean);
    let cancelled = false;
    setResolving(true);
    api
      .post<TestFlowsResponse>(
        "/api/endpoints/test-flows",
        { endpoint_ids: ids, limit: 5 },
        { project_id: projectId }
      )
      .then((res) => {
        if (cancelled) return;
        const ids =
          res.flow_ids ||
          (res.flows || []).map((f) => f.flow_id).filter(Boolean);
        setFlowIds(ids);
        setSkipped((res.skipped_endpoints || []).length);
      })
      .catch(() => {
        if (!cancelled) {
          setFlowIds([]);
          setSkipped(endpointIds.length);
        }
      })
      .finally(() => {
        if (!cancelled) setResolving(false);
      });
    return () => {
      cancelled = true;
    };
  }, [projectId, endpointKey]);

  const busy = Boolean(parentBusy || resolving || runAttacks.running);
  const estimate = estimateFlowAttackJobs(flowIds.length, attackIds);
  const canRun = attackIds.length > 0 && flowIds.length > 0 && !busy;
  const nAttacks = attackIds.length;
  const label = `Run ${nAttacks || ""} attack${nAttacks === 1 ? "" : "s"}`.trim();

  const onRun = async () => {
    if (!canRun) return;
    await runAttacks.run();
  };

  return (
    <div className="w-full space-y-2 pt-2 border-t border-base-300">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-xs font-medium">
          {resolving
            ? "Resolving test flows…"
            : `${flowIds.length} test flow${flowIds.length === 1 ? "" : "s"}`}
        </span>
        <span className="text-[11px] text-base-content/50">
          Top 1–5 2xx captures per endpoint (baseline first)
          {skipped > 0 ? ` · ${skipped} endpoint${skipped === 1 ? "" : "s"} with no usable flow` : ""}
        </span>
      </div>
      <FlowAttackPicker
        flowCount={flowIds.length}
        selectedIds={attackIds}
        busy={busy}
        onToggle={(id) =>
          setAttackIds((prev) =>
            prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id]
          )
        }
      />
      <div className="flex flex-wrap items-center gap-2">
        {estimate > 50 ? (
          <ConfirmButton
            className="btn btn-xs btn-primary"
            confirmText={`Enqueue ~${estimate} jobs on ${flowIds.length} flow${flowIds.length === 1 ? "" : "s"}?`}
            onConfirm={onRun}
          >
            {runAttacks.running ? <span className="loading loading-spinner loading-xs" /> : label}
          </ConfirmButton>
        ) : (
          <button
            type="button"
            className="btn btn-xs btn-primary"
            disabled={!canRun}
            onClick={() => void onRun()}
          >
            {runAttacks.running ? <span className="loading loading-spinner loading-xs" /> : label}
          </button>
        )}
      </div>
    </div>
  );
}
