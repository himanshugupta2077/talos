import { useCallback, useEffect, useRef, useState } from "react";
import { useCommandLog, type LogEntry } from "../state/CommandLogContext";
import type { CommandResult } from "../types";

/**
 * Bottom-docked activity console (Chrome DevTools style).
 * Modes mirror the left sidebar: Expanded | Collapsed (bar) | Auto-hide (hover).
 * Height is drag-resizable; each command entry/step has a copy button.
 */

type ConsoleMode = "expanded" | "collapsed" | "auto";

const MODE_KEY = "talos-cp-console-mode";
const HEIGHT_KEY = "talos-cp-console-height";
const COLLAPSE_DELAY_MS = 280;
const DEFAULT_HEIGHT = 280;
const MIN_HEIGHT = 120;
const MAX_HEIGHT_RATIO = 0.75;

function readMode(): ConsoleMode {
  const raw = localStorage.getItem(MODE_KEY);
  if (raw === "expanded" || raw === "collapsed" || raw === "auto") return raw;
  return "collapsed";
}

function readHeight(): number {
  const n = Number(localStorage.getItem(HEIGHT_KEY));
  if (Number.isFinite(n) && n >= MIN_HEIGHT) return n;
  return DEFAULT_HEIGHT;
}

function formatEntryText(entry: LogEntry): string {
  const lines: string[] = [
    `# ${entry.label}`,
    `# ${new Date(entry.at).toLocaleString()}`,
    "",
  ];
  for (const step of entry.steps) {
    lines.push(`$ ${step.cmd_str}`);
    lines.push(`# exit ${step.exit_code} · ${step.duration_ms}ms · ${step.ok ? "ok" : "failed"}`);
    if (step.stdout) lines.push(step.stdout.replace(/\s+$/, ""));
    if (step.stderr) {
      lines.push("# stderr:");
      lines.push(step.stderr.replace(/\s+$/, ""));
    }
    lines.push("");
  }
  return lines.join("\n").trimEnd() + "\n";
}

function formatStepText(step: CommandResult): string {
  const lines = [
    `$ ${step.cmd_str}`,
    `# exit ${step.exit_code} · ${step.duration_ms}ms · ${step.ok ? "ok" : "failed"}`,
  ];
  if (step.stdout) lines.push(step.stdout.replace(/\s+$/, ""));
  if (step.stderr) {
    lines.push("# stderr:");
    lines.push(step.stderr.replace(/\s+$/, ""));
  }
  return lines.join("\n") + "\n";
}

function CopyButton({
  text,
  label = "Copy",
  className = "btn btn-ghost btn-xs",
}: {
  text: string;
  label?: string;
  className?: string;
}) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      className={className}
      aria-label={label}
      title={label}
      onClick={async (e) => {
        e.stopPropagation();
        try {
          await navigator.clipboard.writeText(text);
          setCopied(true);
          setTimeout(() => setCopied(false), 1200);
        } catch {
          /* clipboard may be unavailable */
        }
      }}
    >
      {copied ? "Copied" : label}
    </button>
  );
}

function ModeIcon({ mode }: { mode: ConsoleMode }) {
  if (mode === "auto") {
    return (
      <svg className="h-3.5 w-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
        <path d="M4 8h10" />
        <path d="M14 8 11 5M14 8l-3 3" />
        <path d="M20 16H10" />
        <path d="M10 16l3-3M10 16l3 3" />
      </svg>
    );
  }
  if (mode === "collapsed") {
    return (
      <svg className="h-3.5 w-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
        <rect x="3" y="4" width="18" height="16" rx="2" />
        <path d="M3 16h18" />
      </svg>
    );
  }
  return (
    <svg className="h-3.5 w-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
      <rect x="3" y="4" width="18" height="16" rx="2" />
      <path d="M3 12h18" />
    </svg>
  );
}

export default function CommandDrawer() {
  const { entries, open, setOpen, clear, lastFailed } = useCommandLog();
  const [mode, setMode] = useState<ConsoleMode>(readMode);
  const [height, setHeight] = useState(readHeight);
  const [hovered, setHovered] = useState(false);
  const collapseTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const dragRef = useRef<{ startY: number; startH: number } | null>(null);
  const skipCloseCollapse = useRef(false);

  useEffect(() => {
    localStorage.setItem(MODE_KEY, mode);
  }, [mode]);

  useEffect(() => {
    localStorage.setItem(HEIGHT_KEY, String(height));
  }, [height]);

  // Restore pinned-open on mount if mode was left expanded.
  useEffect(() => {
    if (readMode() === "expanded") setOpen(true);
    // eslint-disable-next-line react-hooks/exhaustive-deps -- mount only
  }, []);

  useEffect(() => {
    return () => {
      if (collapseTimer.current) clearTimeout(collapseTimer.current);
    };
  }, []);

  // Header / close button set open=false → leave expanded pin.
  useEffect(() => {
    if (!open && mode === "expanded" && !skipCloseCollapse.current) {
      setMode("collapsed");
    }
    skipCloseCollapse.current = false;
  }, [open, mode]);

  // Failures force-open via context; pin expanded so the operator sees output.
  useEffect(() => {
    if (lastFailed && open && mode !== "expanded") {
      setMode("expanded");
    }
  }, [lastFailed, open, mode]);

  const clearCollapseTimer = useCallback(() => {
    if (collapseTimer.current) {
      clearTimeout(collapseTimer.current);
      collapseTimer.current = null;
    }
  }, []);

  const onPanelEnter = useCallback(() => {
    clearCollapseTimer();
    setHovered(true);
  }, [clearCollapseTimer]);

  const onPanelLeave = useCallback(() => {
    clearCollapseTimer();
    collapseTimer.current = setTimeout(() => setHovered(false), COLLAPSE_DELAY_MS);
  }, [clearCollapseTimer]);

  // expanded: always; auto: hover or header/failure open; collapsed: only when open
  const showPanel =
    mode === "expanded" ||
    (mode === "auto" && (hovered || open)) ||
    (mode === "collapsed" && open);

  // Auto hover-expand overlays so the main column doesn't reflow on every hover.
  // When `open` is true (header pin / failure), reserve layout space instead.
  const isOverlayExpand = mode === "auto" && showPanel && !open;
  const reservePanel = showPanel && !isOverlayExpand;
  // Thin bar when panel is not taking layout space (collapsed rail or auto-hide hover base).
  const showBar = !reservePanel;

  const setModeAndPersist = (next: ConsoleMode) => {
    if (next === "collapsed" || next === "auto") {
      // Avoid the open→false effect also flipping mode (we're setting it explicitly).
      skipCloseCollapse.current = true;
      setOpen(false);
      setHovered(false);
    }
    if (next === "expanded") {
      setOpen(true);
    }
    setMode(next);
    if (document.activeElement instanceof HTMLElement) {
      document.activeElement.blur();
    }
  };

  const closePanel = () => {
    setOpen(false);
    setHovered(false);
    if (mode === "expanded") setMode("collapsed");
  };

  const onResizePointerDown = (e: React.PointerEvent) => {
    e.preventDefault();
    dragRef.current = { startY: e.clientY, startH: height };
    (e.target as HTMLElement).setPointerCapture?.(e.pointerId);
  };

  const onResizePointerMove = (e: React.PointerEvent) => {
    if (!dragRef.current) return;
    const dy = dragRef.current.startY - e.clientY;
    const maxH = Math.floor(window.innerHeight * MAX_HEIGHT_RATIO);
    const next = Math.min(maxH, Math.max(MIN_HEIGHT, dragRef.current.startH + dy));
    setHeight(next);
  };

  const onResizePointerUp = () => {
    dragRef.current = null;
  };

  const modeLabel =
    mode === "expanded" ? "Expanded" : mode === "collapsed" ? "Collapsed" : "Auto-hide";

  const autoHoverHandlers =
    mode === "auto"
      ? {
          onMouseEnter: onPanelEnter,
          onMouseLeave: onPanelLeave,
          onFocusCapture: onPanelEnter,
          onBlurCapture: (e: React.FocusEvent) => {
            if (!e.currentTarget.contains(e.relatedTarget as Node | null)) {
              onPanelLeave();
            }
          },
        }
      : {};

  const panelBody = (
    <>
      {/* Resize handle */}
      <div
        role="separator"
        aria-orientation="horizontal"
        aria-label="Resize console"
        className="h-1.5 shrink-0 cursor-ns-resize group relative flex items-center justify-center hover:bg-primary/10 active:bg-primary/20"
        onPointerDown={onResizePointerDown}
        onPointerMove={onResizePointerMove}
        onPointerUp={onResizePointerUp}
        onPointerCancel={onResizePointerUp}
      >
        <span className="w-10 h-0.5 rounded-full bg-base-content/25 group-hover:bg-primary/60" />
      </div>

      {/* Toolbar */}
      <div className="flex items-center justify-between gap-2 px-3 py-1.5 border-b border-base-300 shrink-0">
        <span className="font-semibold text-sm flex items-center gap-2 min-w-0">
          <span className="mono">$_</span>
          <span>Console</span>
          {entries.length > 0 && (
            <span className={`badge badge-xs ${lastFailed ? "badge-error" : ""}`}>
              {entries.length}
            </span>
          )}
        </span>
        <div className="flex items-center gap-1 shrink-0">
          <button
            type="button"
            className="btn btn-xs btn-ghost"
            onClick={clear}
            disabled={entries.length === 0}
          >
            Clear
          </button>

          <div className="dropdown dropdown-top dropdown-end">
            <button
              type="button"
              tabIndex={0}
              className={`btn btn-ghost btn-xs gap-1 ${mode === "auto" ? "text-primary" : ""}`}
              aria-label={`Console view: ${modeLabel}. Open menu to change.`}
            >
              <ModeIcon mode={mode} />
              <span className="text-xs font-normal hidden sm:inline">{modeLabel}</span>
            </button>
            <ul
              tabIndex={0}
              className="dropdown-content menu bg-base-100 rounded-box z-50 w-52 p-2 shadow-lg border border-base-300 mb-1"
            >
              <li className="menu-title px-2 pt-1 pb-0">
                <span className="text-[11px]">Console view</span>
              </li>
              <li>
                <button
                  type="button"
                  className={mode === "expanded" ? "active" : ""}
                  onClick={() => setModeAndPersist("expanded")}
                >
                  <ModeIcon mode="expanded" />
                  <span>
                    Expanded
                    <span className="block text-[11px] font-normal opacity-60">Pinned open</span>
                  </span>
                </button>
              </li>
              <li>
                <button
                  type="button"
                  className={mode === "collapsed" ? "active" : ""}
                  onClick={() => setModeAndPersist("collapsed")}
                >
                  <ModeIcon mode="collapsed" />
                  <span>
                    Collapsed
                    <span className="block text-[11px] font-normal opacity-60">Bar only</span>
                  </span>
                </button>
              </li>
              <li>
                <button
                  type="button"
                  className={mode === "auto" ? "active" : ""}
                  onClick={() => setModeAndPersist("auto")}
                >
                  <ModeIcon mode="auto" />
                  <span>
                    Auto-hide
                    <span className="block text-[11px] font-normal opacity-60">Expand on hover</span>
                  </span>
                </button>
              </li>
            </ul>
          </div>

          <button
            type="button"
            className="btn btn-xs btn-ghost"
            aria-label="Close console"
            onClick={closePanel}
          >
            ✕
          </button>
        </div>
      </div>

      {/* Log body */}
      <div className="flex-1 min-h-0 overflow-y-auto px-3 py-2 space-y-2 mono text-xs">
        {entries.length === 0 && (
          <div className="text-base-content/50 py-6 text-center font-sans">
            No commands run yet. Actions you take will show their exact CLI invocation and output here.
          </div>
        )}
        {entries.map((entry) => (
          <div key={entry.id} className="panel p-2.5">
            <div className="flex items-center justify-between gap-2 mb-1 font-sans">
              <span className="font-medium text-sm truncate min-w-0">{entry.label}</span>
              <div className="flex items-center gap-1.5 shrink-0">
                <span className="text-base-content/40 text-[11px]">
                  {new Date(entry.at).toLocaleTimeString()}
                </span>
                <CopyButton text={formatEntryText(entry)} label="Copy" />
              </div>
            </div>
            {entry.steps.map((step, i) => (
              <div key={i} className="mb-2 last:mb-0">
                <div className="flex items-start gap-2 flex-wrap">
                  <span className={step.ok ? "text-success shrink-0" : "text-error shrink-0"}>
                    {step.ok ? "✓" : "✗"}
                  </span>
                  <span className="text-base-content/70 break-all flex-1 min-w-0">$ {step.cmd_str}</span>
                  <span className="text-base-content/40 whitespace-nowrap text-[11px]">
                    {step.duration_ms}ms · exit {step.exit_code}
                  </span>
                  <CopyButton
                    text={formatStepText(step)}
                    label="Copy"
                    className="btn btn-ghost btn-xs shrink-0"
                  />
                </div>
                {step.stdout && (
                  <pre className="whitespace-pre-wrap break-words text-base-content/90 mt-1 max-h-48 overflow-y-auto">
                    {step.stdout}
                  </pre>
                )}
                {step.stderr && (
                  <pre className="whitespace-pre-wrap break-words text-error/90 mt-1 max-h-48 overflow-y-auto">
                    {step.stderr}
                  </pre>
                )}
              </div>
            ))}
          </div>
        ))}
      </div>
    </>
  );

  return (
    <div className="shrink-0 relative z-40 flex flex-col" {...autoHoverHandlers}>
      {/* In-flow panel (expanded, or collapsed/auto when pinned open) */}
      {reservePanel && (
        <div
          className={`flex flex-col border-t border-base-300 bg-base-200 ${
            lastFailed ? "border-error/40" : ""
          }`}
          style={{ height }}
        >
          {panelBody}
        </div>
      )}

      {/* Overlay panel for auto-hide hover (does not reflow main content) */}
      {isOverlayExpand && (
        <div
          className={`absolute bottom-9 left-0 right-0 flex flex-col border-t border-base-300 bg-base-200 shadow-2xl shadow-base-content/15 ${
            lastFailed ? "border-error/40" : ""
          }`}
          style={{ height }}
        >
          {panelBody}
        </div>
      )}

      {/* Thin bottom bar (collapsed / auto-hide rail) */}
      {showBar && (
        <button
          type="button"
          className={`w-full flex items-center justify-between gap-2 px-3 py-1.5 border-t border-base-300 text-left transition-colors ${
            lastFailed
              ? "bg-error text-error-content hover:bg-error/90"
              : "bg-base-200 text-base-content/70 hover:bg-base-300/60"
          }`}
          aria-label={showPanel ? "Console open" : "Open console"}
          aria-expanded={showPanel}
          onClick={() => setOpen(!open)}
        >
          <span className="flex items-center gap-2 min-w-0">
            <span className="mono text-sm shrink-0">$_</span>
            <span className="text-xs font-medium truncate">Console</span>
            {entries.length > 0 && (
              <span className={`badge badge-xs ${lastFailed ? "badge-error" : ""}`}>
                {entries.length}
              </span>
            )}
            {lastFailed && <span className="text-[11px] opacity-90">last run failed</span>}
          </span>
          <span className="text-[11px] opacity-60 shrink-0 hidden sm:inline">
            {showPanel ? "Drag top edge to resize" : modeLabel}
          </span>
        </button>
      )}
    </div>
  );
}
