/** Keyboard map for the Repeater workspace (browser-safe chords). */

export interface ShortcutDef {
  keys: string;
  action: string;
  context?: string;
}

export const REPEATER_SHORTCUTS: ShortcutDef[] = [
  { keys: "Ctrl/Cmd+Enter", action: "Send once", context: "Workspace" },
  {
    keys: "Ctrl/Cmd+Shift+Enter",
    action: "Redo last execution",
    context: "After a send",
  },
  {
    keys: "Ctrl/Cmd+Shift+] / [",
    action: "Next / previous tab",
    context: "Tab strip",
  },
  { keys: "Ctrl/Cmd+Shift+T", action: "New tab (open flow)" },
  {
    keys: "Ctrl/Cmd+Shift+W",
    action: "Close active tab",
    context: "Confirm if dirty",
  },
  { keys: "Alt+1 / Alt+2", action: "Focus request / response pane" },
  { keys: "?", action: "Shortcuts help", context: "Not in input" },
];

export function isTypingTarget(el: EventTarget | null): boolean {
  if (!el || !(el instanceof HTMLElement)) return false;
  const tag = el.tagName.toLowerCase();
  if (tag === "input" || tag === "textarea" || tag === "select") return true;
  if (el.isContentEditable) return true;
  return false;
}

export function matchMod(e: KeyboardEvent): boolean {
  return e.metaKey || e.ctrlKey;
}
