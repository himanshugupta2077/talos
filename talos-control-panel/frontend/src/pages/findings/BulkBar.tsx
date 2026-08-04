/**
 * Sticky bulk bar for multi-selected findings (list page).
 * Mirrors CLI lifecycle: confirm | reject | reopen, group add, notes.
 */

export default function FindingsBulkBar({
  count,
  busy,
  groups,
  applyLinked,
  onApplyLinkedChange,
  onClear,
  onConfirm,
  onReject,
  onReopen,
  onAddToGroup,
  onSetNotes,
}: {
  count: number;
  busy: boolean;
  groups: { id: string; name: string }[];
  applyLinked: boolean;
  onApplyLinkedChange: (v: boolean) => void;
  onClear: () => void;
  onConfirm: () => void;
  onReject: () => void;
  onReopen: () => void;
  onAddToGroup: (group: string) => void;
  onSetNotes: (notes: string) => void;
}) {
  if (count === 0) return null;

  return (
    <div className="sticky bottom-3 z-20 mx-auto max-w-5xl">
      <div className="panel border border-primary/30 shadow-lg px-3 py-2 flex flex-wrap items-center gap-2 bg-base-100">
        <span className="text-xs font-medium shrink-0">
          {count} finding{count === 1 ? "" : "s"} selected
        </span>

        <div className="flex flex-wrap items-center gap-1 border-l border-base-300 pl-2">
          <button
            type="button"
            className="btn btn-xs btn-success"
            disabled={busy}
            onClick={onConfirm}
            title="talos finding confirm"
          >
            Confirm
          </button>
          <button
            type="button"
            className="btn btn-xs btn-error"
            disabled={busy}
            onClick={onReject}
            title="talos finding reject"
          >
            Reject
          </button>
          <button
            type="button"
            className="btn btn-xs"
            disabled={busy}
            onClick={onReopen}
            title="talos finding reopen"
          >
            Reopen
          </button>
        </div>

        <label className="label cursor-pointer gap-1 py-0 border-l border-base-300 pl-2">
          <input
            type="checkbox"
            className="checkbox checkbox-xs"
            checked={applyLinked}
            onChange={(e) => onApplyLinkedChange(e.target.checked)}
            disabled={busy}
          />
          <span className="label-text text-xs" title="CLI --linked --force on each PRIMARY">
            + linked
          </span>
        </label>

        <div className="flex items-center gap-1 border-l border-base-300 pl-2">
          <select
            className="select select-xs select-bordered"
            disabled={busy || groups.length === 0}
            value=""
            onChange={(e) => {
              if (e.target.value) {
                onAddToGroup(e.target.value);
                e.target.value = "";
              }
            }}
            title="talos finding group add"
          >
            <option value="">Add to group…</option>
            {groups.map((g) => (
              <option key={g.id} value={g.name}>
                {g.name}
              </option>
            ))}
          </select>
          <button
            type="button"
            className="btn btn-xs btn-ghost"
            disabled={busy}
            onClick={() => {
              const notes = window.prompt("Analyst notes for selected findings:");
              if (notes != null && notes.trim()) onSetNotes(notes);
            }}
            title="talos finding note set"
          >
            Notes…
          </button>
        </div>

        <button
          type="button"
          className="btn btn-xs btn-ghost ml-auto"
          disabled={busy}
          onClick={onClear}
        >
          Clear
        </button>
      </div>
    </div>
  );
}
