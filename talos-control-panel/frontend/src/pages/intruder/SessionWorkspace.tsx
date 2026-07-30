import { useCallback, useEffect, useMemo, useRef } from "react";
import { Link } from "react-router-dom";
import { ConfirmButton } from "../../components/Common";
import { useAction } from "../../hooks/useAction";
import { api } from "../../api/client";
import AdvancedTab from "./AdvancedTab";
import ConfigureTab from "./ConfigureTab";
import BaselineSourceChip from "./components/BaselineSourceChip";
import ProgressStrip from "./components/ProgressStrip";
import SessionStatusBadge from "./components/SessionStatusBadge";
import { useSessionDetail } from "./hooks/useSessionDetail";
import { useSessionDraft } from "./hooks/useSessionDraft";
import { useSessionPoll } from "./hooks/useSessionPoll";
import ResultsTab from "./ResultsTab";
import RunTab from "./RunTab";
import { ACTIVE_STATUSES, attackVariables, shortId } from "./shared";
import type { BaselineSource, IntruderSessionDetail, IntruderTab } from "./types";

const TABS: { id: IntruderTab; label: string }[] = [
  { id: "configure", label: "Configure" },
  { id: "run", label: "Run" },
  { id: "results", label: "Results" },
  { id: "advanced", label: "Advanced" },
];

function defaultTabForStatus(status: string): IntruderTab {
  if (status === "running" || status === "queued" || status === "paused") {
    return "run";
  }
  if (status === "completed" || status === "failed" || status === "cancelled") {
    return "results";
  }
  return "configure";
}

export default function SessionWorkspace({
  projectId,
  sessionId,
  tab,
  onTab,
  tabExplicit,
  baselineSource = "flow",
  onDeleted,
  onCloned,
  onSessionMeta,
}: {
  projectId: string;
  sessionId: string;
  tab: IntruderTab;
  onTab: (t: IntruderTab) => void;
  /** True when URL has an explicit ?tab= preference. */
  tabExplicit?: boolean;
  baselineSource?: BaselineSource;
  onDeleted: () => void;
  onCloned: (newId: string) => void;
  onSessionMeta?: (s: IntruderSessionDetail) => void;
}) {
  const { session, setSession, loading, error, reload } = useSessionDetail(
    projectId,
    sessionId
  );

  const onSessionUpdated = useCallback(
    (s: IntruderSessionDetail) => {
      setSession(s);
      onSessionMeta?.(s);
    },
    [setSession, onSessionMeta]
  );

  const draft = useSessionDraft(projectId, session, onSessionUpdated);

  useSessionPoll(
    projectId,
    sessionId,
    session?.status,
    (partial) => {
      setSession((prev) =>
        prev ? ({ ...prev, ...partial } as IntruderSessionDetail) : prev
      );
    }
  );

  // Auto-pick tab by status once per session load when URL has no explicit tab
  const autoTabDone = useRef<string | null>(null);
  useEffect(() => {
    if (!session) return;
    if (tabExplicit) return;
    if (autoTabDone.current === session.id) return;
    autoTabDone.current = session.id;
    const preferred = defaultTabForStatus(session.status);
    if (preferred !== tab) onTab(preferred);
  }, [session, tabExplicit, tab, onTab]);

  // Reset auto-tab tracker when session id changes
  useEffect(() => {
    autoTabDone.current = null;
  }, [sessionId]);

  const isEmptyDraft = useMemo(() => {
    if (!session) return false;
    if (session.status !== "draft" && session.status !== "configured")
      return false;
    const vars = session.config?.template?.variables || [];
    const attack = attackVariables(session.config || {});
    const hasPayload = attack.some(
      (v) => session.config?.payload_sets?.[v.name]
    );
    return vars.length === 0 || !hasPayload;
  }, [session]);

  const cloneMut = useAction("Clone Intruder session", async () => {
    const res = await api.post<{
      session: IntruderSessionDetail;
      steps: any[];
    }>(
      `/api/intruder/sessions/${sessionId}/clone`,
      { name: session?.name ? `${session.name} (copy)` : "" },
      { project_id: projectId }
    );
    onCloned(res.session.id);
    return { steps: res.steps || [] };
  });

  const deleteMut = useAction("Delete Intruder session", async () => {
    const res = await api.del<{ steps: any[] }>(
      `/api/intruder/sessions/${sessionId}`,
      { project_id: projectId, force: true }
    );
    onDeleted();
    return { steps: res.steps || [] };
  });

  if (loading && !session) {
    return (
      <div className="p-8 text-sm text-base-content/50">Loading session…</div>
    );
  }
  if (error || !session) {
    return (
      <div className="p-8">
        <div className="alert alert-error text-sm">{error || "Session not found"}</div>
        <button type="button" className="btn btn-sm mt-3" onClick={() => void reload()}>
          Retry
        </button>
      </div>
    );
  }

  const showProgress = ACTIVE_STATUSES.includes(session.status as any);
  const baselineLabel =
    session.baseline_label ||
    (session.config?.template
      ? `${session.config.template.method || "GET"} ${
          session.config.template.normalized_path ||
          session.config.template.url ||
          ""
        }`.trim()
      : null);

  return (
    <div className="flex flex-col min-h-0 h-full">
      {/* Workspace header */}
      <div className="px-4 py-3 border-b border-base-300 space-y-2 shrink-0">
        <div className="flex flex-wrap items-start justify-between gap-2">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2 mb-1">
              <h2 className="text-lg font-semibold truncate">
                {session.name || `Session ${shortId(session.id)}`}
              </h2>
              <SessionStatusBadge status={session.status} />
              {draft.dirty && (
                <span className="badge badge-warning badge-sm">unsaved</span>
              )}
            </div>
            <div className="flex flex-wrap items-center gap-2 text-xs">
              <BaselineSourceChip
                flowId={session.base_flow_id}
                source={baselineSource}
              />
              {baselineLabel && (
                <span
                  className="mono text-base-content/50 truncate max-w-[280px]"
                  title={baselineLabel}
                >
                  {baselineLabel}
                </span>
              )}
              <span className="mono text-base-content/40">
                {shortId(session.id)}
              </span>
              {session.job_id && (
                <Link
                  to={`/scheduler?job=${session.job_id}`}
                  className="link link-hover mono text-base-content/50"
                >
                  job {shortId(session.job_id)}
                </Link>
              )}
            </div>
          </div>
          <div className="flex flex-wrap gap-1.5">
            <button
              type="button"
              className="btn btn-xs"
              disabled={cloneMut.running}
              onClick={() => void cloneMut.run()}
            >
              Clone
            </button>
            <ConfirmButton
              className="btn btn-xs btn-ghost text-error"
              confirmText="Delete session and results?"
              onConfirm={() => void deleteMut.run()}
            >
              Delete
            </ConfirmButton>
          </div>
        </div>
        {showProgress && (
          <ProgressStrip
            status={session.status}
            progress={session.progress || {}}
          />
        )}
        {session.failure_reason &&
          (session.status === "failed" || session.status === "cancelled") && (
            <div className="text-xs text-error bg-error/10 rounded px-2 py-1">
              {session.failure_reason}
            </div>
          )}
      </div>

      {/* Tabs */}
      <div className="tabs tabs-bordered px-4 shrink-0">
        {TABS.map((t) => (
          <button
            key={t.id}
            type="button"
            className={`tab tab-sm ${tab === t.id ? "tab-active" : ""}`}
            onClick={() => onTab(t.id)}
          >
            {t.label}
            {t.id === "configure" && draft.dirty && (
              <span className="ml-1 w-1.5 h-1.5 rounded-full bg-warning inline-block" />
            )}
            {t.id === "results" &&
              Number(session.progress?.interesting ?? 0) > 0 && (
                <span className="ml-1 badge badge-xs badge-warning">
                  {Number(session.progress?.interesting)}
                </span>
              )}
          </button>
        ))}
      </div>

      <div className="flex-1 overflow-y-auto p-4">
        {tab === "configure" && (
          <ConfigureTab
            projectId={projectId}
            session={session}
            draft={draft}
            isEmptyDraft={isEmptyDraft && !draft.dirty}
            onSessionUpdated={onSessionUpdated}
          />
        )}
        {tab === "run" && (
          <RunTab
            projectId={projectId}
            session={session}
            draft={draft}
            onSessionUpdated={onSessionUpdated}
            onGoConfigure={() => onTab("configure")}
          />
        )}
        {tab === "results" && (
          <ResultsTab projectId={projectId} session={session} />
        )}
        {tab === "advanced" && (
          <AdvancedTab
            projectId={projectId}
            session={session}
            draft={draft}
            onSessionUpdated={onSessionUpdated}
          />
        )}
      </div>
    </div>
  );
}
