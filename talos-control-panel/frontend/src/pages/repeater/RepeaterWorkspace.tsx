/**
 * Single-tab repeater workspace: context, toolbar, editor | response, history.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../../api/client";
import { UuidChip } from "../../components/Common";
import StatusBadge from "../../components/StatusBadge";
import HttpInspector from "../../components/http/HttpInspector";
import HttpRequestEditor from "../../components/http/HttpRequestEditor";
import HttpDiffView from "../../components/http/HttpDiffView";
import SplitPane from "../../components/http/SplitPane";
import { useAction } from "../../hooks/useAction";
import type {
  SendDupResponse,
  SendExportResponse,
  SendHistoryResponse,
  SendHistoryRow,
  SendMutationResponse,
  SendOutcomeDto,
  SendTreeResponse,
} from "../../types";
import type { RepeaterTabState } from "./draftState";
import {
  draftFromSendResponse,
  draftTitle,
  serializeDraft,
} from "./serializeDraft";
import {
  downloadBase64,
  isDangerousAnnotated,
  isLogoutAnnotated,
  shortUuid,
} from "./shared";
import MultiSendDialog from "./MultiSendDialog";
import RepeaterHistory from "./RepeaterHistory";
import RepeaterToolbar from "./RepeaterToolbar";
import {
  postDup,
  postExport,
  postNote,
  postRedo,
  postSendOnce,
  touchRepeaterTab,
} from "./useSendMutation";

interface Props {
  projectId: string;
  tab: RepeaterTabState;
  onTabChange: (next: RepeaterTabState) => void;
  splitRatio: number;
  onSplitRatio: (r: number) => void;
  historyCollapsed: boolean;
  onHistoryCollapsed: (c: boolean) => void;
  onToast: (msg: string, kind?: "info" | "error" | "success") => void;
}

export default function RepeaterWorkspace({
  projectId,
  tab,
  onTabChange,
  splitRatio,
  onSplitRatio,
  historyCollapsed,
  onHistoryCollapsed,
  onToast,
}: Props) {
  const [history, setHistory] = useState<SendHistoryRow[]>([]);
  const [treeNodes, setTreeNodes] = useState<SendTreeResponse["nodes"]>([]);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [historyView, setHistoryView] = useState<"list" | "tree">("list");
  const [sessionFilter, setSessionFilter] = useState<string | null>(
    tab.sessionId
  );
  const [selectedHistoryId, setSelectedHistoryId] = useState<string | null>(
    null
  );
  const [responseOverride, setResponseOverride] = useState<SendOutcomeDto | null>(
    null
  );
  const [respTab, setRespTab] = useState<"pretty" | "diff">("pretty");
  const [diffData, setDiffData] = useState<{
    request?: any;
    response?: any;
  } | null>(null);
  const [multiOpen, setMultiOpen] = useState(false);
  const [multiRunning, setMultiRunning] = useState(false);
  const [multiElapsed, setMultiElapsed] = useState(0);
  const [multiOutcomes, setMultiOutcomes] = useState<SendOutcomeDto[] | null>(
    null
  );
  const multiTimer = useRef<number | null>(null);

  const logoutBlocked = isLogoutAnnotated(tab.endpointAnnotations);
  const dangerous = isDangerousAnnotated(tab.endpointAnnotations);

  const loadHistory = useCallback(async () => {
    setHistoryLoading(true);
    try {
      const params: Record<string, string | number> = {
        project_id: projectId,
        from: tab.originalFlowId || tab.parentFlowId,
        limit: 200,
      };
      if (sessionFilter) params.session = sessionFilter;
      const [h, t] = await Promise.all([
        api.get<SendHistoryResponse>("/api/send/history", params),
        api.get<SendTreeResponse>("/api/send/tree", {
          project_id: projectId,
          from: tab.originalFlowId || tab.parentFlowId,
          limit: 200,
        }),
      ]);
      setHistory(h.executions || []);
      setTreeNodes(t.nodes || []);
    } catch {
      setHistory([]);
      setTreeNodes([]);
    } finally {
      setHistoryLoading(false);
    }
  }, [projectId, tab.originalFlowId, tab.parentFlowId, sessionFilter]);

  useEffect(() => {
    loadHistory();
  }, [loadHistory]);

  const sessions = useMemo(() => {
    const s = new Set<string>();
    for (const r of history) {
      if (r.session_id) s.add(r.session_id);
    }
    if (tab.sessionId) s.add(tab.sessionId);
    return [...s];
  }, [history, tab.sessionId]);

  const displayOutcome = responseOverride || tab.lastOutcome;

  const patch = (partial: Partial<RepeaterTabState>) => {
    onTabChange({
      ...tab,
      ...partial,
      updatedAt: new Date().toISOString(),
      title: partial.draft
        ? draftTitle(partial.draft)
        : partial.title || tab.title,
    });
  };

  const sendAction = useAction("Send once", async () => {
    const raw = serializeDraft(tab.draft, tab.editorMode);
    return postSendOnce(projectId, {
      parent_flow_id: tab.parentFlowId,
      rawBytes: raw,
      session_id: tab.sessionId,
      update_content_length: tab.updateContentLength,
      profile: { type: "once" },
    });
  });

  const redoAction = useAction("Redo send", async () => {
    const target = tab.lastExecutionId || selectedHistoryId;
    if (!target) throw new Error("No execution to redo");
    return postRedo(projectId, target);
  });

  const dupAction = useAction("Dup session", () =>
    postDup(projectId, tab.parentFlowId)
  );

  const noteAction = useAction("Send note", (note: string) => {
    const target = tab.lastExecutionId;
    if (!target) throw new Error("No send execution for note");
    return postNote(projectId, target, note);
  });

  const exportAction = useAction("Send export", () => {
    const target = tab.lastExecutionId || tab.parentFlowId;
    return postExport(projectId, target);
  });

  const persistTabMeta = async (body: {
    parent_flow_id?: string | null;
    session_id?: string | null;
    last_execution_id?: string | null;
    clear_last_execution?: boolean;
  }) => {
    try {
      await touchRepeaterTab(projectId, tab.id, body);
    } catch {
      /* non-fatal: local state already updated */
    }
  };

  const onSend = async () => {
    if (logoutBlocked) {
      onToast("Logout-annotated endpoint — send blocked", "error");
      return;
    }
    try {
      const res = (await sendAction.run()) as unknown as SendMutationResponse;
      const outcome = res.result?.outcomes?.[0];
      if (outcome) {
        setResponseOverride(null);
        patch({
          lastExecutionId: outcome.execution_flow_id,
          lastOutcome: outcome,
          dirty: false,
          // parent stays (product rule)
        });
        if (outcome.execution_flow_id) {
          void persistTabMeta({
            last_execution_id: outcome.execution_flow_id,
          });
        }
        onToast(
          `Send ${outcome.status_code ?? "—"} / ${outcome.verdict ?? "—"}`,
          outcome.success ? "success" : "error"
        );
        loadHistory();
      }
    } catch {
      /* useAction already logged */
    }
  };

  const onRedo = async () => {
    try {
      const res = (await redoAction.run()) as unknown as SendMutationResponse;
      const outcome = res.result?.outcomes?.[0];
      if (outcome) {
        setResponseOverride(null);
        patch({
          lastExecutionId: outcome.execution_flow_id,
          lastOutcome: outcome,
        });
        if (outcome.execution_flow_id) {
          void persistTabMeta({
            last_execution_id: outcome.execution_flow_id,
          });
        }
        onToast(
          `Redo ${outcome.status_code ?? "—"} / ${outcome.verdict ?? "—"}`,
          outcome.success ? "success" : "error"
        );
        loadHistory();
      }
    } catch {
      /* logged */
    }
  };

  const onDup = async () => {
    try {
      const res = (await dupAction.run()) as unknown as SendDupResponse;
      const sid = res.result?.session_id;
      if (sid) {
        patch({ sessionId: sid });
        setSessionFilter(sid);
        void persistTabMeta({ session_id: sid });
        onToast(`Branch session ${sid.slice(0, 8)}`, "info");
      }
    } catch {
      /* logged */
    }
  };

  const onReset = async () => {
    if (tab.dirty && !window.confirm("Discard draft edits and re-load from parent?")) {
      return;
    }
    try {
      const d = await api.get(`/api/send/draft/${tab.parentFlowId}`, {
        project_id: projectId,
      });
      patch({
        draft: draftFromSendResponse(d as any),
        dirty: false,
        endpointAnnotations: (d as any).endpoint_annotations || [],
        originalFlowId: (d as any).original_flow_id || tab.originalFlowId,
        editorMode: "pretty",
      });
      onToast("Draft reset from parent", "info");
    } catch (err) {
      onToast(
        err instanceof Error ? err.message : "Failed to reset draft",
        "error"
      );
    }
  };

  const onExport = async () => {
    try {
      const res = (await exportAction.run()) as unknown as SendExportResponse;
      const r = res.result;
      if (r?.request_http_base64) {
        downloadBase64(
          `request-${r.flow_id.slice(0, 8)}.http`,
          r.request_http_base64
        );
        downloadBase64(
          `response-${r.flow_id.slice(0, 8)}.http`,
          r.response_http_base64
        );
        onToast("Exported request.http + response.http", "success");
      }
    } catch {
      /* logged */
    }
  };

  const onNote = async (note: string) => {
    try {
      await noteAction.run(note);
      onToast("Note saved", "success");
      loadHistory();
    } catch {
      /* logged */
    }
  };

  const multiAction = useAction("Multi-send", async (opts: {
    mode: "repeat" | "parallel";
    n: number;
    delay_ms: number;
  }) => {
    const raw = serializeDraft(tab.draft, tab.editorMode);
    return postSendOnce(projectId, {
      parent_flow_id: tab.parentFlowId,
      rawBytes: raw,
      session_id: tab.sessionId,
      update_content_length: tab.updateContentLength,
      profile:
        opts.mode === "repeat"
          ? { type: "repeat", n: opts.n, delay_ms: opts.delay_ms }
          : { type: "parallel", n: opts.n },
    });
  });

  const onMultiConfirmLogged = async (opts: {
    mode: "repeat" | "parallel";
    n: number;
    delay_ms: number;
  }) => {
    setMultiRunning(true);
    setMultiOutcomes(null);
    setMultiElapsed(0);
    const t0 = Date.now();
    multiTimer.current = window.setInterval(() => {
      setMultiElapsed(Date.now() - t0);
    }, 200);
    try {
      const res = (await multiAction.run(opts)) as unknown as SendMutationResponse;
      setMultiOutcomes(res.result?.outcomes || []);
      const last = res.result?.outcomes?.[res.result.outcomes.length - 1];
      if (last) {
        setResponseOverride(null);
        patch({
          lastExecutionId: last.execution_flow_id,
          lastOutcome: last,
          dirty: false,
        });
        if (last.execution_flow_id) {
          void persistTabMeta({
            last_execution_id: last.execution_flow_id,
          });
        }
      }
      loadHistory();
    } catch {
      /* logged */
    } finally {
      if (multiTimer.current) window.clearInterval(multiTimer.current);
      setMultiElapsed(Date.now() - t0);
      setMultiRunning(false);
    }
  };

  const onHistorySelect = async (row: SendHistoryRow) => {
    setSelectedHistoryId(row.id);
    // Load response only
    try {
      const show = await api.get(`/api/send/show/${row.id}`, {
        project_id: projectId,
      });
      const outcome: SendOutcomeDto = {
        execution_flow_id: row.id,
        parent_flow_id: row.parent_flow_id || tab.parentFlowId,
        original_flow_id: tab.originalFlowId,
        status_code: show.status_code ?? row.status_code,
        success: !show.replay_error,
        failure_reason: show.replay_error,
        verdict: show.verdict ?? row.verdict,
        request_body_len: show.request_body_len || 0,
        response_body_len: show.response_body_len || 0,
        source: show.source || row.source,
        session_id: show.session_id ?? row.session_id,
        profile: show.profile || "once",
        profile_index: 0,
        profile_count: 1,
        note: show.note ?? row.note,
        duration_ms: show.duration_ms ?? row.duration_ms,
        normalizers: show.normalizers || [],
        response: {
          headers: show.response_headers || {},
          body: show.response_body,
          body_base64: show.response_body_base64,
          body_encoding: show.response_body_encoding,
          status_code: show.status_code,
          content_type: show.content_type,
        },
        request_as_sent: {
          method: show.method,
          url: show.url,
          host: show.host,
          path: show.path,
          query: show.query,
          headers: show.request_headers || {},
          cookies: show.request_cookies || {},
          body: show.request_body,
          body_base64: show.request_body_base64,
          body_encoding: show.request_body_encoding,
        },
      };
      setResponseOverride(outcome);
      setRespTab("pretty");
    } catch {
      onToast("Failed to load execution", "error");
    }
  };

  const onFork = async (row: SendHistoryRow) => {
    try {
      const d = await api.get(`/api/send/draft/${row.id}`, {
        project_id: projectId,
      });
      setResponseOverride(null);
      patch({
        parentFlowId: row.id,
        originalFlowId: (d as any).original_flow_id || tab.originalFlowId,
        draft: draftFromSendResponse(d as any),
        dirty: false,
        endpointAnnotations: (d as any).endpoint_annotations || [],
        editorMode: "pretty",
        lastExecutionId: null,
        lastOutcome: null,
      });
      void persistTabMeta({
        parent_flow_id: row.id,
        clear_last_execution: true,
      });
      onToast(`Forked from ${row.id.slice(0, 8)}`, "info");
      loadHistory();
    } catch {
      onToast("Fork failed", "error");
    }
  };

  const loadDiff = async (a: string, b: string) => {
    try {
      const d = await api.get("/api/send/diff", {
        project_id: projectId,
        a,
        b,
        side: "both",
      });
      setDiffData({ request: d.request, response: d.response });
      setRespTab("diff");
    } catch {
      onToast("Diff failed", "error");
    }
  };

  // Compare last vs parent when opening diff tab without selection
  useEffect(() => {
    if (respTab !== "diff") return;
    const a = tab.parentFlowId;
    const b = tab.lastExecutionId || selectedHistoryId;
    if (a && b) loadDiff(a, b);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [respTab]);

  const sending =
    sendAction.running ||
    redoAction.running ||
    multiRunning ||
    multiAction.running;

  const resp = displayOutcome?.response;
  const normalizers = displayOutcome?.normalizers || [];

  return (
    <div className="flex flex-col h-full min-h-0">
      {/* Context bar */}
      <div className="flex flex-wrap items-center gap-2 px-3 py-1.5 text-xs border-b border-base-300 bg-base-200/30 shrink-0">
        <span className="font-mono font-medium">
          {(tab.draft.method || "GET").toUpperCase()} {tab.draft.path || "/"}
        </span>
        <span className="text-base-content/40">·</span>
        <span>
          Parent <UuidChip value={tab.parentFlowId} />
        </span>
        <span>
          Root <UuidChip value={tab.originalFlowId} />
        </span>
        {tab.sessionId && (
          <span className="badge badge-outline badge-xs mono">
            session {shortUuid(tab.sessionId)}
          </span>
        )}
        <span className="badge badge-ghost badge-xs">
          CL: {tab.updateContentLength ? "auto ✓" : "off"}
        </span>
        {logoutBlocked && (
          <span className="badge badge-error badge-xs">logout — send blocked</span>
        )}
        {dangerous && !logoutBlocked && (
          <span className="badge badge-warning badge-xs">dangerous</span>
        )}
        {tab.dirty && (
          <span className="badge badge-info badge-xs">Dirty ✱</span>
        )}
        {tab.lastExecutionId && (
          <Link
            to={`/flows/${tab.lastExecutionId}`}
            className="link mono text-[10px]"
          >
            last {shortUuid(tab.lastExecutionId)}
          </Link>
        )}
      </div>

      <RepeaterToolbar
        sending={sending}
        canSend={!!tab.parentFlowId}
        canRedo={!!(tab.lastExecutionId || selectedHistoryId)}
        canNote={!!tab.lastExecutionId}
        logoutBlocked={logoutBlocked}
        updateContentLength={tab.updateContentLength}
        onToggleCL={() =>
          patch({ updateContentLength: !tab.updateContentLength, dirty: true })
        }
        onSend={onSend}
        onMulti={() => {
          setMultiOutcomes(null);
          setMultiOpen(true);
        }}
        onRedo={onRedo}
        onDup={onDup}
        onReset={onReset}
        onExport={onExport}
        onNote={onNote}
        onClearDrafts={() => {
          /* handled by parent via custom event */
          window.dispatchEvent(new CustomEvent("talos-repeater-clear-drafts"));
        }}
        parentFlowId={tab.parentFlowId}
        originalFlowId={tab.originalFlowId}
        lastExecutionId={tab.lastExecutionId}
      />

      <SplitPane
        ratio={splitRatio}
        onRatioChange={onSplitRatio}
        className="flex-1"
        left={
          <div className="p-3 h-full flex flex-col min-h-0">
            <div className="text-[10px] uppercase text-base-content/50 mb-1 shrink-0">
              Request
            </div>
            <HttpRequestEditor
              draft={tab.draft}
              mode={tab.editorMode}
              disabled={sending}
              onModeChange={(m) => patch({ editorMode: m })}
              onModeError={(msg) => onToast(msg, "error")}
              onChange={(draft) =>
                patch({ draft, dirty: true, title: draftTitle(draft) })
              }
            />
          </div>
        }
        right={
          <div className="p-3 h-full flex flex-col min-h-0">
            <div className="flex items-center gap-2 mb-2 flex-wrap shrink-0">
              <div className="text-[10px] uppercase text-base-content/50">
                Response
              </div>
              <div className="join">
                <button
                  type="button"
                  className={`btn btn-xs join-item ${respTab === "pretty" ? "btn-active" : ""}`}
                  onClick={() => setRespTab("pretty")}
                >
                  Body
                </button>
                <button
                  type="button"
                  className={`btn btn-xs join-item ${respTab === "diff" ? "btn-active" : ""}`}
                  onClick={() => setRespTab("diff")}
                >
                  Diff
                </button>
              </div>
              {displayOutcome && (
                <>
                  {displayOutcome.status_code != null && (
                    <StatusBadge value={displayOutcome.status_code} />
                  )}
                  {displayOutcome.verdict && (
                    <StatusBadge value={displayOutcome.verdict} />
                  )}
                  {displayOutcome.duration_ms != null && (
                    <span className="badge badge-ghost badge-xs mono">
                      {displayOutcome.duration_ms}ms
                    </span>
                  )}
                  <span className="badge badge-ghost badge-xs">
                    {displayOutcome.response_body_len ?? 0} B
                  </span>
                  {normalizers.length > 0 && (
                    <span
                      className="badge badge-warning badge-xs"
                      title={normalizers.join(", ")}
                    >
                      CL-normalized
                    </span>
                  )}
                  {displayOutcome.failure_reason && (
                    <span className="text-error text-[10px]">
                      {displayOutcome.failure_reason}
                    </span>
                  )}
                </>
              )}
            </div>
            <div className="flex-1 min-h-0 overflow-auto">
              {respTab === "diff" ? (
                <HttpDiffView
                  request={diffData?.request}
                  response={diffData?.response}
                />
              ) : displayOutcome && resp ? (
                <HttpInspector
                  side="response"
                  startLine={`HTTP/1.1 ${resp.status_code ?? displayOutcome.status_code ?? 0}`}
                  headers={resp.headers || {}}
                  body={resp.body}
                  bodyEncoding={resp.body_encoding}
                  contentType={resp.content_type}
                />
              ) : (
                <div className="text-xs text-base-content/40 p-4">
                  Send a request to see the response here. History click loads
                  response only without changing the draft.
                </div>
              )}
            </div>
          </div>
        }
      />

      <RepeaterHistory
        rows={
          sessionFilter
            ? history.filter((r) => r.session_id === sessionFilter)
            : history
        }
        treeNodes={treeNodes}
        view={historyView}
        onViewChange={setHistoryView}
        sessionFilter={sessionFilter}
        sessions={sessions}
        onSessionFilter={setSessionFilter}
        selectedId={selectedHistoryId}
        onSelect={onHistorySelect}
        onFork={onFork}
        collapsed={historyCollapsed}
        onToggleCollapse={() => onHistoryCollapsed(!historyCollapsed)}
        loading={historyLoading}
      />

      <MultiSendDialog
        open={multiOpen}
        onClose={() => {
          if (!multiRunning) setMultiOpen(false);
        }}
        onConfirm={onMultiConfirmLogged}
        running={multiRunning}
        elapsedMs={multiElapsed}
        outcomes={multiOutcomes}
      />
    </div>
  );
}
