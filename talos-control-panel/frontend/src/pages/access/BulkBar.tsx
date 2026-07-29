/**
 * Sticky bulk bar when matrix cells are multi-selected.
 */

import { ACCESS_VALUES } from "./shared";
import type { AccessValue } from "../../types";

export default function BulkBar({
  count,
  busy,
  onClearSelection,
  onApplyClient,
  onApplyServer,
  onApplyBoth,
  onUnsetClient,
  onUnsetServer,
  onMirrorClientToServer,
  onDelete,
}: {
  count: number;
  busy: boolean;
  onClearSelection: () => void;
  onApplyClient: (v: AccessValue) => void;
  onApplyServer: (v: AccessValue) => void;
  onApplyBoth: (v: AccessValue) => void;
  onUnsetClient: () => void;
  onUnsetServer: () => void;
  onMirrorClientToServer: () => void;
  onDelete: () => void;
}) {
  if (count === 0) return null;

  return (
    <div className="sticky bottom-3 z-20 mx-auto max-w-4xl">
      <div className="panel border border-primary/30 shadow-lg px-3 py-2 flex flex-wrap items-center gap-2 bg-base-100">
        <span className="text-xs font-medium shrink-0">
          {count} cell{count === 1 ? "" : "s"} selected
        </span>

        <div className="flex flex-wrap items-center gap-1 border-l border-base-300 pl-2">
          <span className="text-[10px] text-base-content/45 uppercase tracking-wide">
            Client
          </span>
          {ACCESS_VALUES.map((v) => (
            <button
              key={`c-${v}`}
              type="button"
              className="btn btn-xs btn-outline"
              disabled={busy}
              onClick={() => onApplyClient(v)}
            >
              {v}
            </button>
          ))}
          <button
            type="button"
            className="btn btn-xs btn-ghost"
            disabled={busy}
            onClick={onUnsetClient}
          >
            Clear
          </button>
        </div>

        <div className="flex flex-wrap items-center gap-1 border-l border-base-300 pl-2">
          <span className="text-[10px] text-base-content/45 uppercase tracking-wide">
            Server
          </span>
          {ACCESS_VALUES.map((v) => (
            <button
              key={`s-${v}`}
              type="button"
              className="btn btn-xs btn-outline"
              disabled={busy}
              onClick={() => onApplyServer(v)}
            >
              {v}
            </button>
          ))}
          <button
            type="button"
            className="btn btn-xs btn-ghost"
            disabled={busy}
            onClick={onUnsetServer}
          >
            Clear
          </button>
        </div>

        <div className="flex flex-wrap items-center gap-1 border-l border-base-300 pl-2">
          <span className="text-[10px] text-base-content/45 uppercase tracking-wide">
            Both
          </span>
          {ACCESS_VALUES.map((v) => (
            <button
              key={`b-${v}`}
              type="button"
              className="btn btn-xs"
              disabled={busy}
              onClick={() => onApplyBoth(v)}
            >
              {v}
            </button>
          ))}
        </div>

        <button
          type="button"
          className="btn btn-xs btn-outline"
          disabled={busy}
          title="Copy client_allowed → server_expected where client is set"
          onClick={onMirrorClientToServer}
        >
          Mirror C→S
        </button>

        <button
          type="button"
          className="btn btn-xs btn-error btn-outline"
          disabled={busy}
          onClick={onDelete}
        >
          Delete
        </button>

        <button
          type="button"
          className="btn btn-xs btn-ghost ml-auto"
          disabled={busy}
          onClick={onClearSelection}
        >
          Deselect
        </button>

        {busy && <span className="loading loading-spinner loading-xs" />}
      </div>
    </div>
  );
}
