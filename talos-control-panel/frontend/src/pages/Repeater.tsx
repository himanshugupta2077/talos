/**
 * Control Panel Repeater — Mode 2 send workbench.
 *
 * Tab archive is project-scoped (server `repeater_tabs` / `talos send tab`).
 * Draft request bodies stay client-local until Send — re-open re-materializes
 * from parent_flow_id. Deep-link: /repeater?flow=
 */

import {
  useCallback,
  useEffect,
  useRef,
  useState,
  type ComponentProps,
} from "react";
import { useSearchParams } from "react-router-dom";
import { api } from "../api/client";
import { Modal, ModuleHelp, NoProjectNotice } from "../components/Common";
import { useProject } from "../state/ProjectContext";
import type { RepeaterTabDto, SendDraftResponse } from "../types";
import {
  createTab,
  MAX_TABS,
  type RepeaterTabState,
} from "./repeater/draftState";
import { draftFromSendResponse } from "./repeater/serializeDraft";
import { NoTabsEmpty } from "./repeater/emptyStates";
import RepeaterTabStrip from "./repeater/RepeaterTabStrip";
import RepeaterWorkspace from "./repeater/RepeaterWorkspace";
import { REPEATER_HELP_BODY, REPEATER_HELP_TITLE } from "./repeater/shared";
import {
  isTypingTarget,
  matchMod,
  REPEATER_SHORTCUTS,
} from "./repeater/shortcuts";
import {
  clearRepeaterTabs,
  closeRepeaterTab,
  listRepeaterTabs,
  openRepeaterTab,
} from "./repeater/useSendMutation";

const UI_PREFS_KEY = "talos-cp-repeater-ui-v1";

function loadUiPrefs(projectId: string): {
  activeTabId: string;
  splitRatio: number;
  historyCollapsed: boolean;
} {
  try {
    const raw = localStorage.getItem(`${UI_PREFS_KEY}:${projectId}`);
    if (!raw) {
      return { activeTabId: "", splitRatio: 0.5, historyCollapsed: false };
    }
    const parsed = JSON.parse(raw) as Record<string, unknown>;
    return {
      activeTabId: typeof parsed.activeTabId === "string" ? parsed.activeTabId : "",
      splitRatio:
        typeof parsed.splitRatio === "number" ? parsed.splitRatio : 0.5,
      historyCollapsed: !!parsed.historyCollapsed,
    };
  } catch {
    return { activeTabId: "", splitRatio: 0.5, historyCollapsed: false };
  }
}

function saveUiPrefs(
  projectId: string,
  prefs: {
    activeTabId: string;
    splitRatio: number;
    historyCollapsed: boolean;
  }
): void {
  try {
    localStorage.setItem(`${UI_PREFS_KEY}:${projectId}`, JSON.stringify(prefs));
  } catch {
    /* quota / private mode */
  }
}

async function hydrateServerTab(
  projectId: string,
  serverTab: RepeaterTabDto
): Promise<RepeaterTabState> {
  const d = (await api.get(`/api/send/draft/${serverTab.parent_flow_id}`, {
    project_id: projectId,
  })) as SendDraftResponse;
  return createTab({
    id: serverTab.id,
    parentFlowId: serverTab.parent_flow_id,
    originalFlowId: serverTab.original_flow_id || d.original_flow_id,
    sessionId: serverTab.session_id,
    lastExecutionId: serverTab.last_execution_id,
    title: serverTab.title,
    draft: draftFromSendResponse(d as any),
    endpointAnnotations: d.endpoint_annotations || [],
    editorMode: "pretty",
    createdAt: serverTab.created_at,
    updatedAt: serverTab.updated_at,
  });
}

export default function Repeater() {
  const { selected } = useProject();
  const [searchParams, setSearchParams] = useSearchParams();
  const [tabs, setTabs] = useState<RepeaterTabState[]>([]);
  const [activeTabId, setActiveTabId] = useState("");
  const [splitRatio, setSplitRatio] = useState(0.5);
  const [historyCollapsed, setHistoryCollapsed] = useState(false);
  const [toast, setToast] = useState<{
    msg: string;
    kind: "info" | "error" | "success";
  } | null>(null);
  const [openFlowOpen, setOpenFlowOpen] = useState(false);
  const [flowInput, setFlowInput] = useState("");
  const [opening, setOpening] = useState(false);
  const [loadingTabs, setLoadingTabs] = useState(false);
  const [shortcutsOpen, setShortcutsOpen] = useState(false);

  const tabsRef = useRef(tabs);
  const activeRef = useRef(activeTabId);
  const splitRef = useRef(splitRatio);
  const histRef = useRef(historyCollapsed);
  const handledFlowRef = useRef<string | null>(null);
  const loadGenRef = useRef(0);

  tabsRef.current = tabs;
  activeRef.current = activeTabId;
  splitRef.current = splitRatio;
  histRef.current = historyCollapsed;

  const showToast = useCallback(
    (msg: string, kind: "info" | "error" | "success" = "info") => {
      setToast({ msg, kind });
      window.setTimeout(() => setToast(null), 3200);
    },
    []
  );

  // Persist lightweight UI prefs only (tab archive is server-side).
  useEffect(() => {
    if (!selected?.id) return;
    saveUiPrefs(selected.id, {
      activeTabId,
      splitRatio,
      historyCollapsed,
    });
  }, [selected?.id, activeTabId, splitRatio, historyCollapsed]);

  // Load project tab archive + re-materialize drafts from parents.
  useEffect(() => {
    if (!selected?.id) {
      setTabs([]);
      setActiveTabId("");
      return;
    }
    const projectId = selected.id;
    const gen = ++loadGenRef.current;
    const prefs = loadUiPrefs(projectId);
    setSplitRatio(prefs.splitRatio);
    setHistoryCollapsed(prefs.historyCollapsed);
    setLoadingTabs(true);
    handledFlowRef.current = null;

    (async () => {
      try {
        const listed = await listRepeaterTabs(projectId);
        if (gen !== loadGenRef.current) return;
        const hydrated: RepeaterTabState[] = [];
        for (const st of listed.tabs) {
          try {
            hydrated.push(await hydrateServerTab(projectId, st));
          } catch {
            // Keep a stub so the archive entry remains visible even if
            // the parent flow was deleted.
            hydrated.push(
              createTab({
                id: st.id,
                parentFlowId: st.parent_flow_id,
                originalFlowId: st.original_flow_id,
                sessionId: st.session_id,
                lastExecutionId: st.last_execution_id,
                title: st.title || "Missing parent",
                createdAt: st.created_at,
                updatedAt: st.updated_at,
              })
            );
          }
        }
        if (gen !== loadGenRef.current) return;
        setTabs(hydrated);
        const preferred =
          (prefs.activeTabId &&
            hydrated.find((t) => t.id === prefs.activeTabId)?.id) ||
          hydrated[0]?.id ||
          "";
        setActiveTabId(preferred);
      } catch (err: any) {
        if (gen !== loadGenRef.current) return;
        setTabs([]);
        setActiveTabId("");
        const detail =
          err?.body?.detail ||
          (err instanceof Error ? err.message : "Failed to load Repeater tabs");
        showToast(String(detail), "error");
      } finally {
        if (gen === loadGenRef.current) setLoadingTabs(false);
      }
    })();
  }, [selected?.id, showToast]);

  // Clear archive event from workspace toolbar
  useEffect(() => {
    const onClear = async () => {
      if (!selected?.id) return;
      if (
        !window.confirm(
          "Close all Repeater tabs for this project? Send history/flows are kept."
        )
      ) {
        return;
      }
      try {
        await clearRepeaterTabs(selected.id);
        setTabs([]);
        setActiveTabId("");
        showToast("Repeater tabs cleared (flows kept)", "info");
      } catch (err: any) {
        const detail =
          err?.body?.detail ||
          (err instanceof Error ? err.message : "Failed to clear tabs");
        showToast(String(detail), "error");
      }
    };
    window.addEventListener("talos-repeater-clear-drafts", onClear);
    return () =>
      window.removeEventListener("talos-repeater-clear-drafts", onClear);
  }, [selected?.id, showToast]);

  const openFlow = useCallback(
    async (flowId: string) => {
      if (!selected?.id || !flowId.trim()) return;
      const id = flowId.trim();
      // Prefer already-loaded client tab with same parent
      const existing = tabsRef.current.find((t) => t.parentFlowId === id);
      if (existing) {
        setActiveTabId(existing.id);
        return;
      }
      if (tabsRef.current.length >= MAX_TABS) {
        showToast(`Tab limit ${MAX_TABS} — close a tab first`, "error");
        return;
      }
      setOpening(true);
      try {
        const opened = await openRepeaterTab(selected.id, { flow_id: id });
        const serverTab = opened.result.tab;
        // If server reused a tab we already have, just activate.
        const already = tabsRef.current.find((t) => t.id === serverTab.id);
        if (already) {
          setActiveTabId(already.id);
          if (opened.result.reused) {
            showToast("Activated existing Repeater tab", "info");
          }
          return;
        }
        const tab = await hydrateServerTab(selected.id, serverTab);
        setTabs((prev) => {
          if (prev.some((t) => t.id === tab.id)) return prev;
          return [...prev, tab];
        });
        setActiveTabId(tab.id);
        if (opened.result.reused) {
          showToast("Opened existing archive tab", "info");
        }
      } catch (err: any) {
        const detail =
          err?.body?.detail ||
          (err instanceof Error ? err.message : "Failed to open flow");
        showToast(String(detail), "error");
      } finally {
        setOpening(false);
      }
    },
    [selected?.id, showToast]
  );

  // Deep-link ?flow=
  useEffect(() => {
    const flow = searchParams.get("flow");
    if (!flow || !selected?.id || loadingTabs) return;
    if (handledFlowRef.current === flow) return;
    handledFlowRef.current = flow;
    openFlow(flow).then(() => {
      const next = new URLSearchParams(searchParams);
      next.delete("flow");
      setSearchParams(next, { replace: true });
    });
  }, [searchParams, selected?.id, openFlow, setSearchParams, loadingTabs]);

  const closeTab = useCallback(
    async (id: string) => {
      const tab = tabsRef.current.find((t) => t.id === id);
      if (tab?.dirty && !window.confirm("Discard unsaved draft in this tab?")) {
        return;
      }
      if (!selected?.id) return;
      try {
        await closeRepeaterTab(selected.id, id);
      } catch (err: any) {
        // 404 = already gone server-side; still drop locally.
        if (err?.status !== 404) {
          const detail =
            err?.body?.detail ||
            (err instanceof Error ? err.message : "Failed to close tab");
          showToast(String(detail), "error");
          return;
        }
      }
      setTabs((prev) => {
        const next = prev.filter((t) => t.id !== id);
        if (activeRef.current === id) {
          setActiveTabId(next[next.length - 1]?.id || "");
        }
        return next;
      });
    },
    [selected?.id, showToast]
  );

  // Keyboard shortcuts
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "?" && !isTypingTarget(e.target)) {
        e.preventDefault();
        setShortcutsOpen(true);
        return;
      }
      if (!matchMod(e)) return;
      if (e.key === "Enter" && e.shiftKey) {
        e.preventDefault();
        window.dispatchEvent(new CustomEvent("talos-repeater-redo"));
        return;
      }
      if (e.key === "Enter" && !e.shiftKey) {
        e.preventDefault();
        window.dispatchEvent(new CustomEvent("talos-repeater-send"));
        return;
      }
      if (e.shiftKey && (e.key === "T" || e.key === "t")) {
        e.preventDefault();
        setOpenFlowOpen(true);
        return;
      }
      if (e.shiftKey && (e.key === "W" || e.key === "w")) {
        e.preventDefault();
        if (activeRef.current) void closeTab(activeRef.current);
        return;
      }
      if (e.shiftKey && e.key === "]") {
        e.preventDefault();
        cycleTab(1);
        return;
      }
      if (e.shiftKey && e.key === "[") {
        e.preventDefault();
        cycleTab(-1);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [closeTab]);

  const cycleTab = (dir: number) => {
    const list = tabsRef.current;
    if (list.length === 0) return;
    const idx = list.findIndex((t) => t.id === activeRef.current);
    const next = list[(idx + dir + list.length) % list.length];
    if (next) setActiveTabId(next.id);
  };

  const updateTab = (next: RepeaterTabState) => {
    setTabs((prev) => prev.map((t) => (t.id === next.id ? next : t)));
  };

  if (!selected) {
    return (
      <div className="p-4">
        <NoProjectNotice />
      </div>
    );
  }

  const active = tabs.find((t) => t.id === activeTabId) || tabs[0] || null;

  return (
    <div className="flex flex-col h-[calc(100vh-3.5rem)] min-h-0 -m-6">
      <div className="px-3 pt-2 pb-1 shrink-0 flex items-start justify-between gap-3 flex-wrap">
        <div>
          <h1 className="text-base font-semibold leading-tight">Repeater</h1>
          <p className="text-[11px] text-base-content/50">
            Mode 2 send — sticky tabs in the project archive. Exact re-run stays
            under <strong>Replay</strong> on Flow Detail.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <ModuleHelp title={REPEATER_HELP_TITLE}>
            <div className="whitespace-pre-wrap text-base-content/70 p-3 pt-0">
              {REPEATER_HELP_BODY}
            </div>
          </ModuleHelp>
          <button
            type="button"
            className="btn btn-ghost btn-xs"
            onClick={() => setShortcutsOpen(true)}
            title="Keyboard shortcuts"
          >
            ?
          </button>
        </div>
      </div>

      <RepeaterTabStrip
        tabs={tabs}
        activeTabId={active?.id || ""}
        onSelect={setActiveTabId}
        onClose={(id) => void closeTab(id)}
        onNew={() => setOpenFlowOpen(true)}
        disabled={opening || loadingTabs}
      />

      {toast && (
        <div
          className={`mx-3 mt-1 alert alert-sm py-1 text-xs ${
            toast.kind === "error"
              ? "alert-error"
              : toast.kind === "success"
                ? "alert-success"
                : "alert-info"
          }`}
        >
          {toast.msg}
        </div>
      )}

      <div className="flex-1 min-h-0">
        {loadingTabs ? (
          <div className="flex items-center justify-center py-16 text-sm text-base-content/50">
            <span className="loading loading-spinner loading-sm mr-2" />
            Loading Repeater archive…
          </div>
        ) : !active ? (
          <NoTabsEmpty onOpenFlow={() => setOpenFlowOpen(true)} />
        ) : (
          <RepeaterWorkspaceWithSendBridge
            projectId={selected.id}
            tab={active}
            onTabChange={updateTab}
            splitRatio={splitRatio}
            onSplitRatio={setSplitRatio}
            historyCollapsed={historyCollapsed}
            onHistoryCollapsed={setHistoryCollapsed}
            onToast={showToast}
          />
        )}
      </div>

      <Modal
        open={openFlowOpen}
        onClose={() => setOpenFlowOpen(false)}
        title="Open flow in Repeater"
      >
        <div className="space-y-3">
          <p className="text-xs text-base-content/60">
            Enter a flow UUID (capture, prior send, or replay row). Creates a
            sticky project tab (same as{" "}
            <span className="mono">talos send tab open</span>). Draft bodies
            stay local until Send.
          </p>
          <input
            className="input input-bordered input-sm w-full mono"
            placeholder="flow UUID"
            value={flowInput}
            onChange={(e) => setFlowInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                openFlow(flowInput).then(() => {
                  setOpenFlowOpen(false);
                  setFlowInput("");
                });
              }
            }}
          />
          <div className="flex justify-end gap-2">
            <button
              type="button"
              className="btn btn-sm"
              onClick={() => setOpenFlowOpen(false)}
            >
              Cancel
            </button>
            <button
              type="button"
              className="btn btn-sm btn-primary"
              disabled={opening || !flowInput.trim()}
              onClick={() => {
                openFlow(flowInput).then(() => {
                  setOpenFlowOpen(false);
                  setFlowInput("");
                });
              }}
            >
              {opening ? (
                <span className="loading loading-spinner loading-xs" />
              ) : (
                "Open"
              )}
            </button>
          </div>
        </div>
      </Modal>

      <Modal
        open={shortcutsOpen}
        onClose={() => setShortcutsOpen(false)}
        title="Repeater shortcuts"
      >
        <table className="table table-xs">
          <tbody>
            {REPEATER_SHORTCUTS.map((s) => (
              <tr key={s.keys}>
                <td className="mono whitespace-nowrap">{s.keys}</td>
                <td>{s.action}</td>
                <td className="text-base-content/50 text-[10px]">
                  {s.context || ""}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Modal>
    </div>
  );
}

/** Workspace wrapper that listens for page-level Send shortcut. */
function RepeaterWorkspaceWithSendBridge(
  props: ComponentProps<typeof RepeaterWorkspace>
) {
  useEffect(() => {
    const onSend = () => {
      document
        .querySelector<HTMLButtonElement>("[data-repeater-send]")
        ?.click();
    };
    const onRedo = () => {
      document
        .querySelector<HTMLButtonElement>("[data-repeater-redo]")
        ?.click();
    };
    window.addEventListener("talos-repeater-send", onSend);
    window.addEventListener("talos-repeater-redo", onRedo);
    return () => {
      window.removeEventListener("talos-repeater-send", onSend);
      window.removeEventListener("talos-repeater-redo", onRedo);
    };
  }, []);

  return <RepeaterWorkspace {...props} />;
}
