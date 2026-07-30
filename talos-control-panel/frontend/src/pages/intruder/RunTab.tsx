import { useState } from "react";
import { Modal } from "../../components/Common";
import { useAction } from "../../hooks/useAction";
import { api, ApiError } from "../../api/client";
import AttemptEstimate from "./components/AttemptEstimate";
import ProgressStrip from "./components/ProgressStrip";
import SafetyChecklist from "./components/SafetyChecklist";
import type { SessionDraftApi } from "./hooks/useSessionDraft";
import {
  CONFIRM_THRESHOLD,
  DEFAULT_MAX_ATTEMPTS,
  DEFAULT_MAX_CONCURRENCY,
  DEFAULT_RPS,
  estimateAttemptsFromDraft,
  formatRelative,
} from "./shared";
import type { IntruderSessionDetail } from "./types";

export default function RunTab({
  projectId,
  session,
  draft,
  onSessionUpdated,
  onGoConfigure,
}: {
  projectId: string;
  session: IntruderSessionDetail;
  draft: SessionDraftApi;
  onSessionUpdated: (s: IntruderSessionDetail) => void;
  onGoConfigure?: () => void;
}) {
  const { config, dirty, artifacts } = draft;
  const [lastEstimate, setLastEstimate] = useState<number | null>(
    session.estimate_attempts ??
      (session.progress?.estimate_total as number | null) ??
      null
  );
  const [actionError, setActionError] = useState<string | null>(null);
  const [confirm, setConfirm] = useState<null | {
    kind: "estimate" | "storage" | "dangerous";
    message: string;
  }>(null);

  const previewEstimate = estimateAttemptsFromDraft(config, artifacts);
  const estimate = lastEstimate ?? previewEstimate;
  const rps = Number(config.timing?.rps ?? DEFAULT_RPS);
  const concurrency = Number(
    config.timing?.max_concurrency ?? DEFAULT_MAX_CONCURRENCY
  );
  const storage = (config.storage?.mode || "metrics_only") as string;
  const status = session.status;
  const active =
    status === "running" || status === "queued" || status === "paused";

  const validate = useAction("Validate Intruder session", async () => {
    const res = await api.post<{
      session: IntruderSessionDetail;
      estimate_attempts?: number | null;
      steps: any[];
    }>(
      `/api/intruder/sessions/${session.id}/validate`,
      { force: false },
      { project_id: projectId }
    );
    onSessionUpdated(res.session);
    draft.hydrateFromSession(res.session);
    setLastEstimate(res.estimate_attempts ?? null);
    return { steps: res.steps || [] };
  });

  const runMut = useAction("Run Intruder session", async (force: boolean) => {
    const res = await api.post<{
      session: IntruderSessionDetail;
      steps: any[];
    }>(
      `/api/intruder/sessions/${session.id}/run`,
      { force },
      { project_id: projectId }
    );
    onSessionUpdated(res.session);
    draft.hydrateFromSession(res.session);
    return { steps: res.steps || [] };
  });

  const pauseMut = useAction("Pause Intruder session", async () => {
    const res = await api.post<{ session: IntruderSessionDetail; steps: any[] }>(
      `/api/intruder/sessions/${session.id}/pause`,
      {},
      { project_id: projectId }
    );
    onSessionUpdated(res.session);
    return { steps: res.steps || [] };
  });

  const resumeMut = useAction("Resume Intruder session", async () => {
    const res = await api.post<{ session: IntruderSessionDetail; steps: any[] }>(
      `/api/intruder/sessions/${session.id}/resume`,
      {},
      { project_id: projectId }
    );
    onSessionUpdated(res.session);
    return { steps: res.steps || [] };
  });

  const stopMut = useAction("Stop Intruder session", async () => {
    const res = await api.post<{ session: IntruderSessionDetail; steps: any[] }>(
      `/api/intruder/sessions/${session.id}/stop`,
      {},
      { project_id: projectId }
    );
    onSessionUpdated(res.session);
    return { steps: res.steps || [] };
  });

  const busy =
    validate.running ||
    runMut.running ||
    pauseMut.running ||
    resumeMut.running ||
    stopMut.running ||
    draft.saving;

  const doValidate = async () => {
    setActionError(null);
    try {
      await validate.run();
    } catch (e) {
      setActionError(formatErr(e));
    }
  };

  const tryRun = async (force: boolean) => {
    setActionError(null);
    // Confirm gates (UI) before sending force
    if (!force) {
      const est = lastEstimate ?? previewEstimate;
      if (est != null && est > CONFIRM_THRESHOLD) {
        setConfirm({
          kind: "estimate",
          message: `Estimated ${est.toLocaleString()} attempts exceeds ${CONFIRM_THRESHOLD.toLocaleString()}. Continue?`,
        });
        return;
      }
      if (storage === "all_flows") {
        setConfirm({
          kind: "storage",
          message:
            "Storage mode all_flows writes a full flow row per attempt and can grow the project DB very quickly. Continue?",
        });
        return;
      }
    }
    try {
      await runMut.run(force);
      setConfirm(null);
    } catch (e) {
      setActionError(formatErr(e));
    }
  };

  const onConfirmRun = async () => {
    // Chain remaining confirms
    if (confirm?.kind === "estimate" && storage === "all_flows") {
      setConfirm({
        kind: "storage",
        message:
          "Storage mode all_flows writes a full flow row per attempt. Continue?",
      });
      return;
    }
    await tryRun(true);
  };

  /** Save draft then continue with validate or run. */
  const saveThen = async (next: "validate" | "run") => {
    setActionError(null);
    const res = await draft.save();
    if (!res.ok) {
      setActionError(draft.saveError || "Save failed");
      return;
    }
    if (res.estimate != null) setLastEstimate(res.estimate);
    if (next === "validate") await doValidate();
    else await tryRun(false);
  };

  const canStart =
    status === "draft" ||
    status === "configured" ||
    status === "completed" ||
    status === "failed" ||
    status === "cancelled";

  return (
    <div className="space-y-4">
      {dirty && (
        <div className="alert alert-warning text-xs py-2">
          <div className="flex flex-wrap items-center justify-between gap-2 w-full">
            <div>
              <strong>Save configuration first</strong> — unsaved Configure
              changes are not used for Validate/Run.
            </div>
            <div className="flex flex-wrap gap-1.5">
              {onGoConfigure && (
                <button
                  type="button"
                  className="btn btn-xs btn-ghost"
                  onClick={onGoConfigure}
                >
                  Open Configure
                </button>
              )}
              <button
                type="button"
                className="btn btn-xs"
                disabled={busy}
                onClick={() => void saveThen("validate")}
              >
                Save then Validate
              </button>
              {canStart && (
                <button
                  type="button"
                  className="btn btn-xs btn-primary"
                  disabled={busy}
                  onClick={() => void saveThen("run")}
                >
                  Save then Run
                </button>
              )}
            </div>
          </div>
        </div>
      )}

      {session.failure_reason &&
        (status === "failed" || status === "cancelled") && (
          <div className="alert alert-error text-xs py-2">
            <div>
              <strong>Stopped:</strong> {session.failure_reason}
            </div>
          </div>
        )}

      <div className="flex flex-wrap items-center gap-2 text-xs">
        {dirty ? (
          <span className="badge badge-warning badge-sm">Unsaved changes</span>
        ) : (
          <span className="badge badge-ghost badge-sm">
            Last saved: {formatRelative(draft.serverUpdatedAt)}
          </span>
        )}
        <span className="badge badge-outline badge-sm capitalize">
          {status}
        </span>
        {session.progress?.stopped_reason && status !== "running" && (
          <span className="text-base-content/50">
            reason: {String(session.progress.stopped_reason)}
          </span>
        )}
      </div>

      {active && (
        <ProgressStrip status={status} progress={session.progress || {}} />
      )}

      <AttemptEstimate
        attempts={estimate}
        rps={rps}
        concurrency={concurrency}
        maxAttempts={Number(
          config.safety?.max_attempts ?? DEFAULT_MAX_ATTEMPTS
        )}
        authoritative={lastEstimate != null}
      />

      <SafetyChecklist config={config} estimate={estimate} dirty={dirty} />

      {actionError && (
        <div className="alert alert-error text-xs py-2 whitespace-pre-wrap">
          {actionError}
        </div>
      )}

      <div className="flex flex-wrap gap-2">
        <button
          type="button"
          className="btn btn-sm"
          disabled={dirty || busy}
          onClick={() => void doValidate()}
        >
          {validate.running ? (
            <span className="loading loading-spinner loading-xs" />
          ) : (
            "Validate"
          )}
        </button>

        {canStart && (
          <button
            type="button"
            className="btn btn-sm btn-primary"
            disabled={dirty || busy}
            onClick={() => void tryRun(false)}
          >
            {runMut.running ? (
              <span className="loading loading-spinner loading-xs" />
            ) : (
              "Run"
            )}
          </button>
        )}

        {(status === "running" || status === "queued") && (
          <>
            <button
              type="button"
              className="btn btn-sm"
              disabled={busy}
              onClick={() =>
                void pauseMut
                  .run()
                  .catch((e) => setActionError(formatErr(e)))
              }
            >
              Pause
            </button>
            <button
              type="button"
              className="btn btn-sm btn-error"
              disabled={busy}
              onClick={() =>
                void stopMut.run().catch((e) => setActionError(formatErr(e)))
              }
            >
              Stop
            </button>
          </>
        )}

        {status === "paused" && (
          <>
            <button
              type="button"
              className="btn btn-sm btn-primary"
              disabled={busy || dirty}
              onClick={() =>
                void resumeMut
                  .run()
                  .catch((e) => setActionError(formatErr(e)))
              }
            >
              Resume
            </button>
            <button
              type="button"
              className="btn btn-sm btn-error"
              disabled={busy}
              onClick={() =>
                void stopMut.run().catch((e) => setActionError(formatErr(e)))
              }
            >
              Stop
            </button>
          </>
        )}
      </div>

      {(status === "completed" ||
        status === "running" ||
        status === "paused" ||
        status === "queued") && (
        <div className="text-xs text-base-content/50">
          Tip: open the <strong>Results</strong> tab to triage interesting
          responses while the campaign runs.
        </div>
      )}

      <div className="text-xs text-base-content/50 rounded-md border border-base-300 px-3 py-2">
        Global Scheduler <strong>Pause/Resume</strong> does not resume Intruder
        sessions. After a global pause, open each paused session and click{" "}
        <strong>Resume</strong> here (or{" "}
        <code className="mono">talos intruder session resume &lt;id&gt;</code>
        ).
      </div>

      <Modal
        open={!!confirm}
        onClose={() => setConfirm(null)}
        title="Confirm Intruder run"
      >
        <p className="text-sm mb-4">{confirm?.message}</p>
        <div className="flex justify-end gap-2">
          <button
            type="button"
            className="btn btn-sm btn-ghost"
            onClick={() => setConfirm(null)}
          >
            Cancel
          </button>
          <button
            type="button"
            className="btn btn-sm btn-warning"
            onClick={() => void onConfirmRun()}
          >
            Continue with force
          </button>
        </div>
      </Modal>
    </div>
  );
}

function formatErr(e: unknown): string {
  if (e instanceof ApiError) {
    const d = e.body?.detail;
    if (typeof d === "string") return d;
    if (d?.message) return d.message;
    return e.message;
  }
  if (e instanceof Error) return e.message;
  return String(e);
}
