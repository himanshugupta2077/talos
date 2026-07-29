import { describe, expect, it, beforeEach, vi } from "vitest";
import {
  clearPersist,
  createTab,
  evaluateRemoteUpdate,
  fromPersist,
  loadPersist,
  PERSIST_VERSION,
  savePersist,
  storageKey,
  toPersist,
  type RepeaterPersistV1,
} from "./draftState";
import { emptyDraft } from "./serializeDraft";

/** Minimal in-memory localStorage for unit tests (jsdom may omit it). */
function installMemoryStorage() {
  const map = new Map<string, string>();
  const store = {
    getItem: (k: string) => map.get(k) ?? null,
    setItem: (k: string, v: string) => {
      map.set(k, String(v));
    },
    removeItem: (k: string) => {
      map.delete(k);
    },
    clear: () => map.clear(),
    key: (i: number) => [...map.keys()][i] ?? null,
    get length() {
      return map.size;
    },
  };
  vi.stubGlobal("localStorage", store);
  return store;
}

describe("repeater draftState", () => {
  beforeEach(() => {
    installMemoryStorage();
  });

  it("round-trips persist schema", () => {
    const tab = createTab({
      parentFlowId: "p1",
      originalFlowId: "r1",
      draft: emptyDraft(),
    });
    tab.dirty = true;
    const blob = toPersist("writer-a", tab.id, [tab], 0.55, true);
    expect(blob.version).toBe(PERSIST_VERSION);
    const res = savePersist("proj1", blob);
    expect(res.ok).toBe(true);
    const loaded = loadPersist("proj1");
    expect(loaded?.activeTabId).toBe(tab.id);
    const restored = fromPersist(loaded!);
    expect(restored.tabs).toHaveLength(1);
    expect(restored.tabs[0].dirty).toBe(true);
    expect(restored.splitRatio).toBe(0.55);
    expect(restored.historyCollapsed).toBe(true);
  });

  it("ignores wrong version", () => {
    localStorage.setItem(
      storageKey("proj1"),
      JSON.stringify({ version: 99, tabs: [] })
    );
    expect(loadPersist("proj1")).toBeNull();
  });

  it("clearPersist removes key", () => {
    savePersist("proj1", toPersist("w", "t", [], 0.5, false));
    clearPersist("proj1");
    expect(loadPersist("proj1")).toBeNull();
  });

  it("multi-window: clean local auto-reloads", () => {
    const tab = createTab({
      parentFlowId: "p",
      originalFlowId: "r",
    });
    const remote: RepeaterPersistV1 = toPersist(
      "writer-other",
      tab.id,
      [tab],
      0.5,
      false
    );
    const d = evaluateRemoteUpdate([tab], "writer-me", remote);
    expect(d.kind).toBe("auto-reload");
  });

  it("multi-window: dirty local does not auto-reload", () => {
    const tab = createTab({
      parentFlowId: "p",
      originalFlowId: "r",
    });
    tab.dirty = true;
    const remote: RepeaterPersistV1 = toPersist(
      "writer-other",
      tab.id,
      [tab],
      0.5,
      false
    );
    const d = evaluateRemoteUpdate([tab], "writer-me", remote);
    expect(d.kind).toBe("dirty-conflict");
  });

  it("same writerId is ignored", () => {
    const tab = createTab({ parentFlowId: "p", originalFlowId: "r" });
    const remote = toPersist("writer-me", tab.id, [tab], 0.5, false);
    expect(evaluateRemoteUpdate([tab], "writer-me", remote).kind).toBe("none");
  });
});
