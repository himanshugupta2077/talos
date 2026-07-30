import { useCallback, useEffect, useState } from "react";
import { api } from "../../../api/client";
import type { IntruderSessionDetail } from "../types";

export function useSessionDetail(
  projectId: string | undefined,
  sessionId: string | undefined
) {
  const [session, setSession] = useState<IntruderSessionDetail | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const reload = useCallback(async () => {
    if (!projectId || !sessionId) {
      setSession(null);
      return null;
    }
    setLoading(true);
    setError(null);
    try {
      const s = await api.get<IntruderSessionDetail>(
        `/api/intruder/sessions/${sessionId}`,
        { project_id: projectId }
      );
      setSession(s);
      return s;
    } catch (e: any) {
      setError(e?.body?.detail || e?.message || "Failed to load session");
      setSession(null);
      return null;
    } finally {
      setLoading(false);
    }
  }, [projectId, sessionId]);

  useEffect(() => {
    // Drop stale session immediately so draft/UI don't flash previous campaign
    setSession(null);
    setError(null);
    void reload();
  }, [reload]);

  return { session, setSession, loading, error, reload };
}
