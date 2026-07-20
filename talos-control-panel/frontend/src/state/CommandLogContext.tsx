import { createContext, useContext, useState, ReactNode, useCallback } from "react";
import { CommandResult } from "../types";

export interface LogEntry {
  id: string;
  at: number;
  label: string;
  steps: CommandResult[];
}

export interface Toast {
  id: string;
  label: string;
  ok: boolean;
}

interface CommandLogContextValue {
  entries: LogEntry[];
  log: (label: string, steps: CommandResult[]) => void;
  clear: () => void;
  open: boolean;
  setOpen: (open: boolean) => void;
  lastFailed: boolean;
  toasts: Toast[];
  dismissToast: (id: string) => void;
}

const CommandLogContext = createContext<CommandLogContextValue | null>(null);

export function CommandLogProvider({ children }: { children: ReactNode }) {
  const [entries, setEntries] = useState<LogEntry[]>([]);
  const [open, setOpen] = useState(false);
  const [lastFailed, setLastFailed] = useState(false);
  const [toasts, setToasts] = useState<Toast[]>([]);

  const dismissToast = useCallback((id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  const log = useCallback((label: string, steps: CommandResult[]) => {
    const entry: LogEntry = { id: crypto.randomUUID(), at: Date.now(), label, steps };
    setEntries((prev) => [entry, ...prev].slice(0, 100));
    const failed = steps.some((s) => !s.ok);
    setLastFailed(failed);
    if (failed) setOpen(true);

    // Small non-blocking confirmation toast for every action, success or
    // failure — so add/remove/update actions always give visible feedback
    // even when the operator isn't watching the bottom console.
    const toastId = crypto.randomUUID();
    setToasts((prev) => [...prev, { id: toastId, label, ok: !failed }]);
    setTimeout(() => dismissToast(toastId), failed ? 5000 : 2800);
  }, [dismissToast]);

  const clear = useCallback(() => setEntries([]), []);

  return (
    <CommandLogContext.Provider
      value={{ entries, log, clear, open, setOpen, lastFailed, toasts, dismissToast }}
    >
      {children}
    </CommandLogContext.Provider>
  );
}

export function useCommandLog() {
  const ctx = useContext(CommandLogContext);
  if (!ctx) throw new Error("useCommandLog must be used within CommandLogProvider");
  return ctx;
}
