import { useCallback, useEffect, useState } from "react";
import { api } from "../../api/client";
import type { ProjectDashboard } from "./types";

const POLL_MS = 5000;

export function useDashboardData(projectId: string | undefined) {
  const [data, setData] = useState<ProjectDashboard | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    if (!projectId) {
      setData(null);
      setError(null);
      return;
    }
    try {
      const payload = await api.get<ProjectDashboard>(
        `/api/projects/${projectId}/dashboard`
      );
      setData(payload);
      setError(null);
    } catch (e: unknown) {
      const msg =
        e && typeof e === "object" && "message" in e
          ? String((e as { message?: string }).message)
          : "Failed to load dashboard";
      setError(msg);
    } finally {
      setLoading(false);
    }
  }, [projectId]);

  useEffect(() => {
    if (!projectId) {
      setData(null);
      setLoading(false);
      return;
    }
    setLoading(true);
    void refresh();
    const id = window.setInterval(() => {
      if (document.visibilityState === "hidden") return;
      void refresh();
    }, POLL_MS);
    return () => window.clearInterval(id);
  }, [projectId, refresh]);

  return { data, loading, error, refresh };
}
