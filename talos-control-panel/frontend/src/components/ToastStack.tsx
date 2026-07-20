import { useCommandLog } from "../state/CommandLogContext";

/**
 * Small, non-blocking confirmation toasts for every action run through
 * useAction (add/remove/update/etc.) — gives the operator visible feedback
 * even when the console drawer is closed.
 */
export default function ToastStack() {
  const { toasts, dismissToast } = useCommandLog();

  if (toasts.length === 0) return null;

  return (
    <div className="fixed bottom-14 right-4 z-[60] flex flex-col gap-2 items-end pointer-events-none">
      {toasts.map((t) => (
        <div
          key={t.id}
          className={`alert py-2 px-3 shadow-lg text-sm min-w-[220px] max-w-sm pointer-events-auto ${
            t.ok ? "alert-success" : "alert-error"
          }`}
        >
          <span>{t.ok ? "✓" : "✗"}</span>
          <span className="truncate">{t.label}</span>
          <button className="btn btn-ghost btn-xs" onClick={() => dismissToast(t.id)}>
            ✕
          </button>
        </div>
      ))}
    </div>
  );
}
