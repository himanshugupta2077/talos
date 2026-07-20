import { useCallback, useEffect, useId, useRef, useState, type ReactNode } from "react";

const LEAVE_DELAY_MS = 180;

type Align = "start" | "end";

/**
 * Header hover panel that stays open while the pointer moves from the
 * trigger into the panel. Uses a leave delay + zero-gap layout so the
 * classic "gap closes the menu" problem does not happen.
 */
export default function HoverMenu({
  trigger,
  children,
  align = "start",
  panelClassName = "",
  disabled = false,
}: {
  trigger: ReactNode;
  children: ReactNode;
  align?: Align;
  panelClassName?: string;
  disabled?: boolean;
}) {
  const [open, setOpen] = useState(false);
  const leaveTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const rootRef = useRef<HTMLDivElement>(null);
  const panelId = useId();

  const clearLeave = useCallback(() => {
    if (leaveTimer.current) {
      clearTimeout(leaveTimer.current);
      leaveTimer.current = null;
    }
  }, []);

  const openNow = useCallback(() => {
    if (disabled) return;
    clearLeave();
    setOpen(true);
  }, [clearLeave, disabled]);

  const scheduleClose = useCallback(() => {
    clearLeave();
    leaveTimer.current = setTimeout(() => setOpen(false), LEAVE_DELAY_MS);
  }, [clearLeave]);

  useEffect(() => {
    return () => clearLeave();
  }, [clearLeave]);

  useEffect(() => {
    if (disabled) setOpen(false);
  }, [disabled]);

  // Close on Escape / outside click (pointer + keyboard friendly).
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    const onDown = (e: MouseEvent) => {
      if (!rootRef.current?.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("keydown", onKey);
    document.addEventListener("mousedown", onDown);
    return () => {
      document.removeEventListener("keydown", onKey);
      document.removeEventListener("mousedown", onDown);
    };
  }, [open]);

  return (
    <div
      ref={rootRef}
      className="relative inline-flex"
      onMouseEnter={openNow}
      onMouseLeave={scheduleClose}
      onFocusCapture={openNow}
      onBlurCapture={(e) => {
        if (!e.currentTarget.contains(e.relatedTarget as Node | null)) {
          scheduleClose();
        }
      }}
    >
      <div
        className="inline-flex"
        aria-haspopup="menu"
        aria-expanded={open}
        aria-controls={open ? panelId : undefined}
      >
        {trigger}
      </div>

      {/*
        Absolute panel sits flush under the trigger. A transparent top pad
        acts as a hit-bridge so the pointer never "falls off" between chips.
      */}
      {open && (
        <div
          id={panelId}
          role="menu"
          className={`absolute top-full z-50 pt-1 ${
            align === "end" ? "right-0" : "left-0"
          } ${panelClassName}`}
          onMouseEnter={openNow}
          onMouseLeave={scheduleClose}
        >
          <div className="rounded-lg border border-base-content/20 bg-base-100 p-2 shadow-2xl shadow-black/30 ring-1 ring-base-content/10">
            {children}
          </div>
        </div>
      )}
    </div>
  );
}
