import { useEffect, useRef } from "react";
import { api } from "../../../api/client";
import { ACTIVE_STATUSES, TERMINAL_STATUSES } from "../shared";
import type { IntruderSessionDetail, IntruderSessionStatus } from "../types";

/**
 * Poll session status while queued/running/paused.
 * 2s running/queued; 5s paused; stop on terminal.
 */
export function useSessionPoll(
  projectId: string | undefined,
  sessionId: string | undefined,
  status: IntruderSessionStatus | string | undefined,
  onUpdate: (partial: Partial<IntruderSessionDetail>) => void
) {
  const onUpdateRef = useRef(onUpdate);
  onUpdateRef.current = onUpdate;

  useEffect(() => {
    if (!projectId || !sessionId || !status) return;
    if (TERMINAL_STATUSES.includes(status as IntruderSessionStatus)) return;
    if (!ACTIVE_STATUSES.includes(status as IntruderSessionStatus)) return;

    const intervalMs = status === "paused" ? 5000 : 2000;
    let cancelled = false;

    const tick = async () => {
      try {
        const s = await api.get<{
          id: string;
          status: IntruderSessionStatus;
          job_id: string | null;
          progress: IntruderSessionDetail["progress"];
          updated_at: string;
          started_at?: string | null;
          finished_at?: string | null;
          failure_reason?: string | null;
          estimate_attempts?: number | null;
        }>(`/api/intruder/sessions/${sessionId}/status`, {
          project_id: projectId,
        });
        if (cancelled) return;
        onUpdateRef.current({
          status: s.status,
          job_id: s.job_id,
          progress: s.progress,
          updated_at: s.updated_at,
          started_at: s.started_at,
          finished_at: s.finished_at,
          failure_reason: s.failure_reason,
          estimate_attempts: s.estimate_attempts,
        });
      } catch {
        /* ignore transient poll errors */
      }
    };

    void tick();
    const id = window.setInterval(tick, intervalMs);
    return () => {
      cancelled = true;
      window.clearInterval(id);
    };
  }, [projectId, sessionId, status]);
}
