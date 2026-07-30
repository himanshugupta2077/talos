/**
 * Intruder workbench: session list + workspace.
 * Deep links: ?session= ?flow= ?tab=
 */

import { useCallback, useEffect, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api, ApiError } from "../../api/client";
import { useProject } from "../../state/ProjectContext";
import { useAction } from "../../hooks/useAction";
import { NoProjectNotice } from "../../components/Common";
import IntruderDisclaimer from "./components/IntruderDisclaimer";
import { useIntruderSessions } from "./hooks/useIntruderSessions";
import SessionList from "./SessionList";
import SessionWorkspace from "./SessionWorkspace";
import { isIntruderTab } from "./shared";
import type { BaselineSource, IntruderSessionDetail, IntruderTab } from "./types";

export default function IntruderPage() {
  const { selected } = useProject();
  const [searchParams, setSearchParams] = useSearchParams();
  const sessionParam = searchParams.get("session");
  const flowParam = searchParams.get("flow");
  const tabParam = searchParams.get("tab");
  const baselineParam = searchParams.get("baseline") as BaselineSource | null;

  const tabExplicit = isIntruderTab(tabParam);
  const tab: IntruderTab = tabExplicit ? tabParam : "configure";
  const [statusFilter, setStatusFilter] = useState("");
  const [createError, setCreateError] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const createOnceRef = useRef<string | null>(null);

  const { sessions, loading, reload } = useIntruderSessions(
    selected?.id,
    statusFilter || undefined
  );

  const setSession = useCallback(
    (id: string | null, extra?: Record<string, string>) => {
      const next = new URLSearchParams(searchParams);
      if (id) next.set("session", id);
      else next.delete("session");
      next.delete("flow");
      if (extra) {
        for (const [k, v] of Object.entries(extra)) {
          if (v) next.set(k, v);
          else next.delete(k);
        }
      }
      setSearchParams(next, { replace: true });
    },
    [searchParams, setSearchParams]
  );

  const setTab = useCallback(
    (t: IntruderTab) => {
      const next = new URLSearchParams(searchParams);
      next.set("tab", t);
      setSearchParams(next, { replace: true });
    },
    [searchParams, setSearchParams]
  );

  // Create from ?flow= once
  useEffect(() => {
    if (!selected || !flowParam || sessionParam) return;
    if (createOnceRef.current === flowParam) return;
    createOnceRef.current = flowParam;
    setCreating(true);
    setCreateError(null);
    api
      .post<{ session: IntruderSessionDetail; steps: unknown[] }>(
        "/api/intruder/sessions",
        { flow_id: flowParam },
        { project_id: selected.id }
      )
      .then((res) => {
        const next = new URLSearchParams();
        next.set("session", res.session.id);
        next.set("tab", "configure");
        if (baselineParam) next.set("baseline", baselineParam);
        setSearchParams(next, { replace: true });
        reload();
      })
      .catch((e) => {
        const msg =
          e instanceof ApiError
            ? typeof e.body?.detail === "string"
              ? e.body.detail
              : e.message
            : String(e);
        setCreateError(msg);
        createOnceRef.current = null;
      })
      .finally(() => setCreating(false));
  }, [selected, flowParam, sessionParam, baselineParam, setSearchParams, reload]);

  const createFromPrompt = useAction("Create Intruder session", async () => {
    const flowId = window.prompt(
      "Baseline flow UUID (or open Flows → Send to Intruder):"
    );
    if (!flowId?.trim()) return { steps: [] };
    const name = window.prompt("Session name (optional):") || "";
    const res = await api.post<{
      session: IntruderSessionDetail;
      steps: any[];
    }>(
      "/api/intruder/sessions",
      { flow_id: flowId.trim(), name: name.trim() },
      { project_id: selected!.id }
    );
    setSession(res.session.id, { tab: "configure" });
    reload();
    return { steps: res.steps || [] };
  });

  if (!selected) return <NoProjectNotice />;

  const baselineSource: BaselineSource =
    baselineParam === "last_send" || baselineParam === "capture"
      ? baselineParam
      : "flow";

  return (
    <div className="flex flex-col gap-3 min-h-[calc(100vh-8rem)]">
      <IntruderDisclaimer />

      {createError && (
        <div className="alert alert-error text-xs py-2">{createError}</div>
      )}
      {creating && (
        <div className="alert alert-info text-xs py-2">
          Creating session from flow…
        </div>
      )}

      <div className="flex-1 min-h-0 grid grid-cols-1 md:grid-cols-[280px_1fr] border border-base-300 rounded-lg overflow-hidden bg-base-100">
        <SessionList
          sessions={sessions}
          loading={loading}
          selectedId={sessionParam}
          statusFilter={statusFilter}
          onStatusFilter={setStatusFilter}
          onSelect={(id) => {
            // Clear tab so workspace can default by session status
            const next = new URLSearchParams(searchParams);
            next.set("session", id);
            next.delete("flow");
            next.delete("tab");
            setSearchParams(next, { replace: true });
          }}
          onNew={() => void createFromPrompt.run()}
        />

        <div className="min-h-[420px] min-w-0">
          {!sessionParam && !flowParam && (
            <EmptyWorkspace onReload={reload} />
          )}
          {sessionParam && (
            <SessionWorkspace
              projectId={selected.id}
              sessionId={sessionParam}
              tab={tab}
              onTab={setTab}
              tabExplicit={tabExplicit}
              baselineSource={baselineSource}
              onDeleted={() => {
                setSession(null);
                reload();
              }}
              onCloned={(newId) => {
                setSession(newId, { tab: "configure" });
                reload();
              }}
              onSessionMeta={() => reload()}
            />
          )}
        </div>
      </div>
    </div>
  );
}

function EmptyWorkspace({ onReload }: { onReload: () => void }) {
  return (
    <div className="h-full flex flex-col items-center justify-center p-8 text-center text-sm text-base-content/60 gap-3">
      <div className="text-base font-medium text-base-content/80">
        Select or create an Intruder session
      </div>
      <p className="max-w-md text-xs leading-relaxed">
        High-volume mutation of one baseline request. Start from Capture: open a
        flow or Repeater tab and choose <strong>Send to Intruder</strong>, or
        create from a flow UUID with <strong>+ New</strong>.
      </p>
      <div className="flex flex-wrap gap-2 justify-center">
        <Link to="/flows" className="btn btn-sm btn-outline">
          Open Flows
        </Link>
        <Link to="/repeater" className="btn btn-sm btn-ghost">
          Open Repeater
        </Link>
        <button type="button" className="btn btn-sm btn-ghost" onClick={onReload}>
          Refresh list
        </button>
      </div>
    </div>
  );
}
