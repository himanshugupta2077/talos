import { ReactNode, useState } from "react";

export function ConfirmButton({
  onConfirm, children, className = "btn btn-sm btn-error", confirmText = "Are you sure?",
}: {
  onConfirm: () => void | Promise<void>;
  children: ReactNode;
  className?: string;
  confirmText?: string;
}) {
  const [confirming, setConfirming] = useState(false);
  if (confirming) {
    return (
      <span className="inline-flex items-center gap-1">
        <span className="text-xs text-base-content/60">{confirmText}</span>
        <button
          className="btn btn-xs btn-error"
          onClick={async (e) => {
            e.stopPropagation();
            setConfirming(false);
            await onConfirm();
          }}
        >
          Yes
        </button>
        <button className="btn btn-xs btn-ghost" onClick={(e) => { e.stopPropagation(); setConfirming(false); }}>
          Cancel
        </button>
      </span>
    );
  }
  return (
    <button className={className} onClick={(e) => { e.stopPropagation(); setConfirming(true); }}>
      {children}
    </button>
  );
}

export function UuidChip({ value }: { value: string | null | undefined }) {
  const [copied, setCopied] = useState(false);
  if (!value) return <span className="text-base-content/40">—</span>;
  return (
    <button
      className="uuid-chip hover:bg-base-content/10"
      aria-label="Click to copy"
      onClick={(e) => {
        e.stopPropagation();
        navigator.clipboard.writeText(value);
        setCopied(true);
        setTimeout(() => setCopied(false), 1200);
      }}
    >
      {copied ? "copied!" : value.slice(0, 8)}
    </button>
  );
}

export function NoProjectNotice() {
  return (
    <div className="panel p-8 text-center text-base-content/60">
      Select a project from the dropdown above to get started — or{" "}
      <a href="/projects" className="link link-primary">
        create a new one
      </a>
      .
    </div>
  );
}

export function Modal({
  open, onClose, title, children, wide = false,
}: {
  open: boolean; onClose: () => void; title: string; children: ReactNode; wide?: boolean;
}) {
  if (!open) return null;
  return (
    <div className="modal modal-open">
      <div className={`modal-box ${wide ? "max-w-3xl" : ""}`}>
        <h3 className="font-bold text-lg mb-4">{title}</h3>
        {children}
        <div className="modal-action">
          <button className="btn btn-sm" onClick={onClose}>
            Close
          </button>
        </div>
      </div>
      <div className="modal-backdrop" onClick={onClose} />
    </div>
  );
}

export function Section({ title, action, children }: { title: string; action?: ReactNode; children: ReactNode }) {
  return (
    <div className="mb-6">
      <div className="flex items-center justify-between mb-2">
        <h2 className="font-semibold text-base">{title}</h2>
        {action}
      </div>
      {children}
    </div>
  );
}

/**
 * Compact collapsible page/section help for operators.
 * Use for non-obvious module purpose or workflow — keep body short and module-specific.
 * Required input rules must stay visible near controls, not only here.
 */
export function ModuleHelp({
  title,
  children,
}: {
  title: string;
  children: ReactNode;
}) {
  return (
    <details className="group rounded-md border border-base-300 bg-base-200/30 text-xs">
      <summary className="cursor-pointer select-none px-3 py-2 font-medium text-base-content/70 hover:text-base-content flex items-center gap-2 list-none [&::-webkit-details-marker]:hidden">
        <span
          className="text-base-content/40 transition-transform group-open:rotate-90 inline-block leading-none"
          aria-hidden
        >
          ▸
        </span>
        {title}
      </summary>
      <div className="px-3 pb-3 space-y-2 text-base-content/60 leading-relaxed border-t border-base-300/50">
        {children}
      </div>
    </details>
  );
}

/** Optional field-level clarification (tooltip). Do not hide required usage info here. */
export function FieldHint({ text }: { text: string }) {
  return (
    <span
      className="tooltip tooltip-top align-middle"
      data-tip={text}
    >
      <span
        className="inline-flex items-center justify-center w-3.5 h-3.5 rounded-full border border-base-content/25 text-[9px] leading-none text-base-content/45 cursor-help ml-1 select-none"
        aria-label={text}
      >
        ?
      </span>
    </span>
  );
}
