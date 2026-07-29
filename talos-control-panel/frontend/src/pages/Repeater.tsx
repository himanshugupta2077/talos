/**
 * Control Panel Repeater — Mode 2 send workbench.
 *
 * Client multi-tab drafts (localStorage per project). Deep-link: /repeater?flow=
 * Operator guidance: ModuleHelp + inline CL / logout chips.
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
import {
  clearPersist,
  createTab,
  DEBOUNCE_MS,
  evaluateRemoteUpdate,
  fromPersist,
  loadPersist,
  MAX_TABS,
  newWriterId,
  parseStorageEvent,
  savePersist,
  toPersist,
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
  const [shortcutsOpen, setShortcutsOpen] = useState(false);
  const [remoteConflict, setRemoteConflict] = useState<ReturnType<
    typeof loadPersist
  > | null>(null);

  const writerIdRef = useRef(newWriterId());
  const tabsRef = useRef(tabs);
  const activeRef = useRef(activeTabId);
  const splitRef = useRef(splitRatio);
  const histRef = useRef(historyCollapsed);
  const persistTimer = useRef<number | null>(null);
  const handledFlowRef = useRef<string | null>(null);

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

  const flushPersist = useCallback(
    (projectId: string) => {
      if (!projectId) return;
      const data = toPersist(
        writerIdRef.current,
        activeRef.current,
        tabsRef.current,
        splitRef.current,
        histRef.current
      );
      const res = savePersist(projectId, data);
      if (!res.ok) {
        showToast(
          "Draft storage full — large bodies kept in memory only",
          "error"
        );
      }
    },
    [showToast]
  );

  const schedulePersist = useCallback(
    (projectId: string) => {
      if (persistTimer.current) window.clearTimeout(persistTimer.current);
      persistTimer.current = window.setTimeout(() => {
        flushPersist(projectId);
      }, DEBOUNCE_MS);
    },
    [flushPersist]
  );

  // Load tabs when project changes
  useEffect(() => {
    if (!selected?.id) {
      setTabs([]);
      setActiveTabId("");
      return;
    }
    // flush previous is handled by switch: load new key
    const blob = loadPersist(selected.id);
    if (blob) {
      const restored = fromPersist(blob);
      setTabs(restored.tabs);
      setActiveTabId(restored.activeTabId || restored.tabs[0]?.id || "");
      setSplitRatio(restored.splitRatio);
      setHistoryCollapsed(restored.historyCollapsed);
    } else {
      setTabs([]);
      setActiveTabId("");
      setSplitRatio(0.5);
      setHistoryCollapsed(false);
    }
    handledFlowRef.current = null;
  }, [selected?.id]);

  // Debounced persist on tab/state changes
  useEffect(() => {
    if (!selected?.id) return;
    schedulePersist(selected.id);
  }, [tabs, activeTabId, splitRatio, historyCollapsed, selected?.id, schedulePersist]);

  // Flush on hide / unload
  useEffect(() => {
    if (!selected?.id) return;
    const pid = selected.id;
    const flush = () => flushPersist(pid);
    const onVis = () => {
      if (document.visibilityState === "hidden") flush();
    };
    window.addEventListener("pagehide", flush);
    window.addEventListener("beforeunload", flush);
    document.addEventListener("visibilitychange", onVis);
    return () => {
      window.removeEventListener("pagehide", flush);
      window.removeEventListener("beforeunload", flush);
      document.removeEventListener("visibilitychange", onVis);
      flush();
    };
  }, [selected?.id, flushPersist]);

  // Multi-window storage events
  useEffect(() => {
    if (!selected?.id) return;
    const pid = selected.id;
    const onStorage = (e: StorageEvent) => {
      const remote = parseStorageEvent(pid, e);
      if (!remote) return;
      const decision = evaluateRemoteUpdate(
        tabsRef.current,
        writerIdRef.current,
        remote
      );
      if (decision.kind === "auto-reload") {
        const restored = fromPersist(decision.remote);
        setTabs(restored.tabs);
        setActiveTabId(restored.activeTabId);
        setSplitRatio(restored.splitRatio);
        setHistoryCollapsed(restored.historyCollapsed);
        showToast("Repeater tabs reloaded from another window", "info");
      } else if (decision.kind === "dirty-conflict") {
        setRemoteConflict(decision.remote);
      }
    };
    window.addEventListener("storage", onStorage);
    return () => window.removeEventListener("storage", onStorage);
  }, [selected?.id, showToast]);

  // Clear drafts event from workspace toolbar
  useEffect(() => {
    const onClear = () => {
      if (!selected?.id) return;
      if (
        !window.confirm(
          "Clear all local Repeater drafts for this project? (server history is kept)"
        )
      ) {
        return;
      }
      clearPersist(selected.id);
      setTabs([]);
      setActiveTabId("");
      showToast("Local drafts cleared", "info");
    };
    window.addEventListener("talos-repeater-clear-drafts", onClear);
    return () =>
      window.removeEventListener("talos-repeater-clear-drafts", onClear);
  }, [selected?.id, showToast]);

  const openFlow = useCallback(
    async (flowId: string) => {
      if (!selected?.id || !flowId.trim()) return;
      const id = flowId.trim();
      // Activate existing tab with same parent if present
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
        const d = await api.get(`/api/send/draft/${id}`, {
          project_id: selected.id,
        });
        const draft = draftFromSendResponse(d as any);
        const tab = createTab({
          parentFlowId: (d as any).parent_flow_id || id,
          originalFlowId: (d as any).original_flow_id || id,
          draft,
          endpointAnnotations: (d as any).endpoint_annotations || [],
          editorMode: "pretty",
        });
        setTabs((prev) => [...prev, tab]);
        setActiveTabId(tab.id);
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
    if (!flow || !selected?.id) return;
    if (handledFlowRef.current === flow) return;
    handledFlowRef.current = flow;
    openFlow(flow).then(() => {
      // clear query to avoid re-open on tab switch
      const next = new URLSearchParams(searchParams);
      next.delete("flow");
      setSearchParams(next, { replace: true });
    });
  }, [searchParams, selected?.id, openFlow, setSearchParams]);

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
        // Allow Ctrl+Enter from textarea and global
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
        if (activeRef.current) closeTab(activeRef.current);
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
  }, []);

  const cycleTab = (dir: number) => {
    const list = tabsRef.current;
    if (list.length === 0) return;
    const idx = list.findIndex((t) => t.id === activeRef.current);
    const next = list[(idx + dir + list.length) % list.length];
    if (next) setActiveTabId(next.id);
  };

  const closeTab = (id: string) => {
    const tab = tabsRef.current.find((t) => t.id === id);
    if (tab?.dirty && !window.confirm("Discard unsaved draft in this tab?")) {
      return;
    }
    setTabs((prev) => {
      const next = prev.filter((t) => t.id !== id);
      if (activeRef.current === id) {
        setActiveTabId(next[next.length - 1]?.id || "");
      }
      return next;
    });
  };

  const updateTab = (next: RepeaterTabState) => {
    setTabs((prev) => prev.map((t) => (t.id === next.id ? next : t)));
  };

  // Bridge send shortcut to active workspace via custom event listened in workspace
  useEffect(() => {
    // Workspace listens for talos-repeater-send — we inject a small bridge
    // by storing a callback on window (simplest without context)
  }, []);

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
            Mode 2 send — edit & fire with lineage. Exact re-run stays under{" "}
            <strong>Replay</strong> on Flow Detail.
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
        onClose={closeTab}
        onNew={() => setOpenFlowOpen(true)}
        disabled={opening}
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

      {remoteConflict && (
        <div className="mx-3 mt-1 alert alert-warning py-2 text-xs flex flex-wrap gap-2 items-center">
          <span>
            Another window updated Repeater drafts. You have local unsaved
            edits.
          </span>
          <button
            type="button"
            className="btn btn-xs"
            onClick={() => {
              const restored = fromPersist(remoteConflict);
              setTabs(restored.tabs);
              setActiveTabId(restored.activeTabId);
              setSplitRatio(restored.splitRatio);
              setHistoryCollapsed(restored.historyCollapsed);
              setRemoteConflict(null);
              showToast("Loaded remote drafts (local discarded)", "info");
            }}
          >
            Load remote (discard local)
          </button>
          <button
            type="button"
            className="btn btn-xs btn-primary"
            onClick={() => {
              setRemoteConflict(null);
              flushPersist(selected.id);
              showToast("Keeping local — will overwrite remote on save", "info");
            }}
          >
            Keep local
          </button>
        </div>
      )}

      <div className="flex-1 min-h-0">
        {!active ? (
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
            Enter a flow UUID (capture, prior send, or replay row). Engine
            requires a parent for lineage — blank compose is not supported.
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
