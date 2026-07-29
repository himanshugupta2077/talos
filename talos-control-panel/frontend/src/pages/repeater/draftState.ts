/**
 * Client-side repeater tab persistence (localStorage).
 *
 * Key: talos-cp-repeater-v1:{projectId}
 * Multi-window: writerId + storage events; never silently discard dirty local.
 */

import type { SendEditorMode, SendOutcomeDto } from "../../types";
import {
  draftTitle,
  emptyDraft,
  type RequestDraft,
} from "./serializeDraft";

export const PERSIST_VERSION = 1 as const;
export const MAX_TABS = 12;
export const LS_BODY_CAP = 512 * 1024; // drop large bodies from LS
export const DEBOUNCE_MS = 300;

export interface RepeaterTabState {
  id: string;
  title: string;
  parentFlowId: string;
  originalFlowId: string;
  sessionId: string | null;
  draft: RequestDraft;
  dirty: boolean;
  lastExecutionId: string | null;
  /** Last hydrated response for response pane */
  lastOutcome: SendOutcomeDto | null;
  updateContentLength: boolean;
  editorMode: SendEditorMode;
  endpointAnnotations: string[];
  createdAt: string;
  updatedAt: string;
}

export interface RepeaterPersistV1 {
  version: 1;
  writerId: string;
  updatedAt: string;
  activeTabId: string;
  tabs: Array<{
    id: string;
    title: string;
    parentFlowId: string;
    originalFlowId: string;
    sessionId: string | null;
    draft: RequestDraft;
    dirty: boolean;
    lastExecutionId: string | null;
    updateContentLength: boolean;
    editorMode: SendEditorMode;
    endpointAnnotations: string[];
    createdAt: string;
    updatedAt: string;
  }>;
  splitRatio: number;
  historyCollapsed: boolean;
}

export type MultiWindowConflict =
  | { kind: "none" }
  | { kind: "auto-reload"; remote: RepeaterPersistV1 }
  | { kind: "dirty-conflict"; remote: RepeaterPersistV1 };

export function storageKey(projectId: string): string {
  return `talos-cp-repeater-v1:${projectId}`;
}

export function newWriterId(): string {
  return `w-${Math.random().toString(36).slice(2, 10)}-${Date.now().toString(36)}`;
}

export function newTabId(): string {
  return `tab-${Math.random().toString(36).slice(2, 10)}-${Date.now().toString(36)}`;
}

export function createTab(partial: {
  parentFlowId: string;
  originalFlowId: string;
  draft?: RequestDraft;
  sessionId?: string | null;
  endpointAnnotations?: string[];
  editorMode?: SendEditorMode;
}): RepeaterTabState {
  const now = new Date().toISOString();
  const draft = partial.draft || emptyDraft();
  return {
    id: newTabId(),
    title: draftTitle(draft),
    parentFlowId: partial.parentFlowId,
    originalFlowId: partial.originalFlowId,
    sessionId: partial.sessionId ?? null,
    draft,
    dirty: false,
    lastExecutionId: null,
    lastOutcome: null,
    updateContentLength: true,
    editorMode: partial.editorMode || "pretty",
    endpointAnnotations: partial.endpointAnnotations || [],
    createdAt: now,
    updatedAt: now,
  };
}

/** Strip large bodies for localStorage quota safety. */
export function slimDraftForStorage(draft: RequestDraft): RequestDraft {
  const slim = { ...draft };
  const bodySize =
    (slim.request_body?.length || 0) +
    (slim.request_body_base64?.length || 0) +
    (slim.raw_text?.length || 0) +
    (slim.raw_base64?.length || 0);
  if (bodySize > LS_BODY_CAP) {
    slim.request_body = null;
    slim.request_body_base64 = null;
    slim.raw_text = null;
    slim.raw_base64 = null;
  }
  return slim;
}

export function toPersist(
  writerId: string,
  activeTabId: string,
  tabs: RepeaterTabState[],
  splitRatio: number,
  historyCollapsed: boolean
): RepeaterPersistV1 {
  return {
    version: 1,
    writerId,
    updatedAt: new Date().toISOString(),
    activeTabId,
    tabs: tabs.map((t) => ({
      id: t.id,
      title: t.title,
      parentFlowId: t.parentFlowId,
      originalFlowId: t.originalFlowId,
      sessionId: t.sessionId,
      draft: slimDraftForStorage(t.draft),
      dirty: t.dirty,
      lastExecutionId: t.lastExecutionId,
      updateContentLength: t.updateContentLength,
      editorMode: t.editorMode,
      endpointAnnotations: t.endpointAnnotations,
      createdAt: t.createdAt,
      updatedAt: t.updatedAt,
    })),
    splitRatio,
    historyCollapsed,
  };
}

export function fromPersist(blob: RepeaterPersistV1): {
  activeTabId: string;
  tabs: RepeaterTabState[];
  splitRatio: number;
  historyCollapsed: boolean;
} {
  const tabs: RepeaterTabState[] = (blob.tabs || []).map((t) => ({
    id: t.id,
    title: t.title,
    parentFlowId: t.parentFlowId,
    originalFlowId: t.originalFlowId,
    sessionId: t.sessionId,
    draft: t.draft || emptyDraft(),
    dirty: !!t.dirty,
    lastExecutionId: t.lastExecutionId,
    lastOutcome: null, // never persist response bodies in LS
    updateContentLength: t.updateContentLength !== false,
    editorMode: t.editorMode || "pretty",
    endpointAnnotations: t.endpointAnnotations || [],
    createdAt: t.createdAt,
    updatedAt: t.updatedAt,
  }));
  return {
    activeTabId: blob.activeTabId || tabs[0]?.id || "",
    tabs,
    splitRatio: typeof blob.splitRatio === "number" ? blob.splitRatio : 0.5,
    historyCollapsed: !!blob.historyCollapsed,
  };
}

export function loadPersist(projectId: string): RepeaterPersistV1 | null {
  try {
    const raw = localStorage.getItem(storageKey(projectId));
    if (!raw) return null;
    const parsed = JSON.parse(raw) as RepeaterPersistV1;
    if (!parsed || parsed.version !== PERSIST_VERSION) return null;
    return parsed;
  } catch {
    return null;
  }
}

export function savePersist(
  projectId: string,
  data: RepeaterPersistV1
): { ok: boolean; memoryOnly: boolean } {
  try {
    localStorage.setItem(storageKey(projectId), JSON.stringify(data));
    return { ok: true, memoryOnly: false };
  } catch (err) {
    // QuotaExceededError or similar
    if (err instanceof DOMException || (err as Error)?.name === "QuotaExceededError") {
      return { ok: false, memoryOnly: true };
    }
    return { ok: false, memoryOnly: true };
  }
}

export function clearPersist(projectId: string): void {
  try {
    localStorage.removeItem(storageKey(projectId));
  } catch {
    /* ignore */
  }
}

/**
 * Evaluate a storage event from another window.
 * - No local dirty → auto-reload
 * - Any local dirty → dirty-conflict (operator chooses)
 */
export function evaluateRemoteUpdate(
  localTabs: RepeaterTabState[],
  localWriterId: string,
  remote: RepeaterPersistV1 | null
): MultiWindowConflict {
  if (!remote || remote.version !== PERSIST_VERSION) return { kind: "none" };
  if (remote.writerId === localWriterId) return { kind: "none" };
  const anyDirty = localTabs.some((t) => t.dirty);
  if (anyDirty) return { kind: "dirty-conflict", remote };
  return { kind: "auto-reload", remote };
}

export function parseStorageEvent(
  projectId: string,
  e: StorageEvent
): RepeaterPersistV1 | null {
  if (e.key !== storageKey(projectId) || !e.newValue) return null;
  try {
    const parsed = JSON.parse(e.newValue) as RepeaterPersistV1;
    if (!parsed || parsed.version !== PERSIST_VERSION) return null;
    return parsed;
  } catch {
    return null;
  }
}
