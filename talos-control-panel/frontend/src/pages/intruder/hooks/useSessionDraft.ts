/**
 * Workspace-level draft: local edits + dirty flag shared by Configure/Run.
 */

import { useCallback, useEffect, useMemo, useState } from "react";
import { api, ApiError } from "../../../api/client";
import type { StepsResponse } from "../../../types";
import {
  deepCloneConfig,
  ensureConfigDefaults,
} from "../shared";
import type {
  ArtifactDrafts,
  IntruderConfig,
  IntruderSessionDetail,
  PayloadSetConfig,
  TemplateVariable,
} from "../types";

export function useSessionDraft(
  projectId: string | undefined,
  session: IntruderSessionDetail | null,
  onSessionUpdated: (s: IntruderSessionDetail) => void
) {
  const [config, setConfig] = useState<IntruderConfig>(() =>
    ensureConfigDefaults({})
  );
  const [artifacts, setArtifacts] = useState<ArtifactDrafts>({});
  const [serverUpdatedAt, setServerUpdatedAt] = useState("");
  const [dirty, setDirty] = useState(false);
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);

  // Hydrate when session identity changes. Do not reset on poll-driven
  // updated_at bumps (running progress) — that would wipe local dirty edits.
  // Explicit save/validate/discard call hydrateFromSession or replace via save.
  useEffect(() => {
    if (!session) return;
    setConfig(ensureConfigDefaults(session.config || {}));
    setArtifacts({});
    setServerUpdatedAt(session.updated_at || "");
    setDirty(false);
    setSaveError(null);
    // eslint-disable-next-line react-hooks/exhaustive-deps -- only on id
  }, [session?.id]);

  const markDirty = useCallback(() => setDirty(true), []);

  const updateConfig = useCallback((fn: (c: IntruderConfig) => IntruderConfig) => {
    setConfig((prev) => fn(deepCloneConfig(prev)));
    setDirty(true);
  }, []);

  const setVariables = useCallback((vars: TemplateVariable[]) => {
    updateConfig((c) => {
      c.template = c.template || {};
      c.template.variables = vars;
      return c;
    });
  }, [updateConfig]);

  const setPayloadSet = useCallback(
    (name: string, ps: PayloadSetConfig | null) => {
      updateConfig((c) => {
        c.payload_sets = { ...(c.payload_sets || {}) };
        if (ps == null) delete c.payload_sets[name];
        else c.payload_sets[name] = ps;
        return c;
      });
    },
    [updateConfig]
  );

  const setArtifactText = useCallback(
    (varName: string, text: string, kind: "wordlist" | "csv" | "json" = "wordlist") => {
      setArtifacts((prev) => ({ ...prev, [varName]: { kind, text } }));
      setDirty(true);
    },
    []
  );

  const clearArtifact = useCallback((varName: string) => {
    setArtifacts((prev) => {
      const next = { ...prev };
      delete next[varName];
      return next;
    });
    setDirty(true);
  }, []);

  const discard = useCallback(() => {
    if (!session) return;
    setConfig(ensureConfigDefaults(session.config || {}));
    setArtifacts({});
    setServerUpdatedAt(session.updated_at || "");
    setDirty(false);
    setSaveError(null);
  }, [session]);

  const save = useCallback(async (): Promise<{
    ok: boolean;
    estimate?: number | null;
    steps?: StepsResponse["steps"];
  }> => {
    if (!projectId || !session) return { ok: false };
    setSaving(true);
    setSaveError(null);
    try {
      const body: Record<string, unknown> = {
        expected_updated_at: serverUpdatedAt,
        force: false,
        config,
      };
      if (Object.keys(artifacts).length > 0) {
        body.artifacts = artifacts;
      }
      const res = await api.post<{
        session: IntruderSessionDetail;
        estimate_attempts?: number | null;
        steps: StepsResponse["steps"];
      }>(`/api/intruder/sessions/${session.id}/configure`, body, {
        project_id: projectId,
      });
      onSessionUpdated(res.session);
      setConfig(ensureConfigDefaults(res.session.config || {}));
      setArtifacts({});
      setServerUpdatedAt(res.session.updated_at || "");
      setDirty(false);
      return {
        ok: true,
        estimate: res.estimate_attempts,
        steps: res.steps,
      };
    } catch (e) {
      if (e instanceof ApiError) {
        const d = e.body?.detail;
        if (e.status === 409) {
          setSaveError(
            typeof d === "object" && d?.message
              ? d.message
              : "Session was modified elsewhere — reload and try again."
          );
        } else {
          setSaveError(
            typeof d === "string" ? d : d?.message || e.message
          );
        }
      } else {
        setSaveError(e instanceof Error ? e.message : String(e));
      }
      return { ok: false };
    } finally {
      setSaving(false);
    }
  }, [projectId, session, serverUpdatedAt, config, artifacts, onSessionUpdated]);

  const hydrateFromSession = useCallback((s: IntruderSessionDetail) => {
    setConfig(ensureConfigDefaults(s.config || {}));
    setArtifacts({});
    setServerUpdatedAt(s.updated_at || "");
    setDirty(false);
    setSaveError(null);
  }, []);

  const estimatePreview = useMemo(() => {
    // lazy import circular-safe: compute inline
    return null as number | null;
  }, [config, artifacts]);

  return {
    config,
    setConfig: updateConfig,
    artifacts,
    dirty,
    saving,
    saveError,
    serverUpdatedAt,
    markDirty,
    setVariables,
    setPayloadSet,
    setArtifactText,
    clearArtifact,
    discard,
    save,
    hydrateFromSession,
    estimatePreview,
  };
}

export type SessionDraftApi = ReturnType<typeof useSessionDraft>;
