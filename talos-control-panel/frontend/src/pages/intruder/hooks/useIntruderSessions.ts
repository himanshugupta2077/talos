import { useCallback, useEffect, useState } from "react";
import { api } from "../../../api/client";
import type { IntruderSessionSummary } from "../types";

export function useIntruderSessions(
  projectId: string | undefined,
  statusFilter?: string
) {
  const [sessions, setSessions] = useState<IntruderSessionSummary[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const reload = useCallback(() => {
    if (!projectId) {
      setSessions([]);
      return;
    }
    setLoading(true);
    setError(null);
    api
      .get<{ sessions: IntruderSessionSummary[] }>("/api/intruder/sessions", {
        project_id: projectId,
        status: statusFilter || undefined,
        limit: 200,
      })
      .then((r) => setSessions(r.sessions || []))
      .catch((e) => {
        setError(e?.body?.detail || e?.message || "Failed to load sessions");
        setSessions([]);
      })
      .finally(() => setLoading(false));
  }, [projectId, statusFilter]);

  useEffect(() => {
    reload();
  }, [reload]);

  return { sessions, loading, error, reload };
}
