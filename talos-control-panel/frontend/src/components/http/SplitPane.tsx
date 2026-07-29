/**
 * Minimal horizontal split (request | response). ~50 LOC, no dependency.
 * Ratio persisted by parent via onRatioChange.
 */

import { useCallback, useRef, type ReactNode } from "react";

interface Props {
  left: ReactNode;
  right: ReactNode;
  /** 0..1 left fraction (default 0.5) */
  ratio?: number;
  onRatioChange?: (ratio: number) => void;
  className?: string;
}

export default function SplitPane({
  left,
  right,
  ratio = 0.5,
  onRatioChange,
  className = "",
}: Props) {
  const containerRef = useRef<HTMLDivElement>(null);
  const dragging = useRef(false);

  const onPointerDown = useCallback((e: React.PointerEvent) => {
    dragging.current = true;
    (e.target as HTMLElement).setPointerCapture?.(e.pointerId);
  }, []);

  const onPointerMove = useCallback(
    (e: React.PointerEvent) => {
      if (!dragging.current || !containerRef.current || !onRatioChange) return;
      const rect = containerRef.current.getBoundingClientRect();
      if (rect.width <= 0) return;
      const next = Math.min(0.8, Math.max(0.2, (e.clientX - rect.left) / rect.width));
      onRatioChange(next);
    },
    [onRatioChange]
  );

  const onPointerUp = useCallback(() => {
    dragging.current = false;
  }, []);

  const leftPct = `${(ratio * 100).toFixed(1)}%`;
  const rightPct = `${((1 - ratio) * 100).toFixed(1)}%`;

  return (
    <div
      ref={containerRef}
      className={`flex min-h-0 flex-1 overflow-hidden ${className}`}
      onPointerMove={onPointerMove}
      onPointerUp={onPointerUp}
      onPointerLeave={onPointerUp}
    >
      <div className="min-w-0 min-h-0 overflow-auto" style={{ width: leftPct }}>
        {left}
      </div>
      <div
        role="separator"
        aria-orientation="vertical"
        className="w-1.5 shrink-0 cursor-col-resize bg-base-300 hover:bg-primary/40 active:bg-primary/60"
        onPointerDown={onPointerDown}
      />
      <div className="min-w-0 min-h-0 overflow-auto" style={{ width: rightPct }}>
        {right}
      </div>
    </div>
  );
}
