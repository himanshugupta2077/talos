import { useCommandLog } from "../state/CommandLogContext";

/**
 * Global header access to the command/activity drawer (CLI steps + output).
 */
export default function HeaderCommandButton() {
  const { open, setOpen, entries, lastFailed } = useCommandLog();

  return (
    <button
      type="button"
      className={`btn btn-xs gap-1 mono ${
        lastFailed ? "btn-error" : open ? "btn-primary" : "btn-ghost border border-base-300"
      }`}
      aria-label={open ? "Close activity console" : "Open activity console (CLI steps)"}
      aria-pressed={open}
      onClick={() => setOpen(!open)}
    >
      <span>$_</span>
      {entries.length > 0 && (
        <span className={`badge badge-xs ${lastFailed ? "badge-error" : ""}`}>
          {entries.length}
        </span>
      )}
    </button>
  );
}
