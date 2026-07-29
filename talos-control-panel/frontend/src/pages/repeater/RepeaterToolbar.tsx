import { useState } from "react";
import { Link } from "react-router-dom";
import NotePopover from "./NotePopover";

interface Props {
  sending: boolean;
  canSend: boolean;
  canRedo: boolean;
  canNote: boolean;
  logoutBlocked: boolean;
  updateContentLength: boolean;
  onToggleCL: () => void;
  onSend: () => void;
  onMulti: () => void;
  onRedo: () => void;
  onDup: () => void;
  onReset: () => void;
  onExport: () => void;
  onNote: (note: string) => void;
  onClearDrafts: () => void;
  parentFlowId: string;
  originalFlowId: string;
  noteInitial?: string;
}

export default function RepeaterToolbar({
  sending,
  canSend,
  canRedo,
  canNote,
  logoutBlocked,
  updateContentLength,
  onToggleCL,
  onSend,
  onMulti,
  onRedo,
  onDup,
  onReset,
  onExport,
  onNote,
  onClearDrafts,
  parentFlowId,
  originalFlowId,
  noteInitial = "",
}: Props) {
  const [noteOpen, setNoteOpen] = useState(false);

  return (
    <div className="flex flex-wrap items-center gap-1 px-3 py-1.5 border-b border-base-300 bg-base-100 shrink-0">
      <button
        type="button"
        data-repeater-send
        className="btn btn-sm btn-primary"
        disabled={!canSend || sending || logoutBlocked}
        title={
          logoutBlocked
            ? "Logout-annotated endpoint — send blocked"
            : "Send once (Ctrl+Enter)"
        }
        onClick={onSend}
      >
        {sending ? (
          <span className="loading loading-spinner loading-xs" />
        ) : (
          "Send"
        )}
        <span className="opacity-60 text-[10px] ml-1">↵</span>
      </button>
      <div className="dropdown">
        <button
          type="button"
          tabIndex={0}
          className="btn btn-sm"
          disabled={!canSend || sending || logoutBlocked}
        >
          Multi ▾
        </button>
        <ul
          tabIndex={0}
          className="dropdown-content menu p-2 shadow bg-base-200 rounded-box w-44 border border-base-300 z-20"
        >
          <li>
            <button type="button" onClick={onMulti}>
              Send multiple…
            </button>
          </li>
        </ul>
      </div>
      <button
        type="button"
        data-repeater-redo
        className="btn btn-sm"
        disabled={!canRedo || sending}
        title="Redo last execution as-sent (Ctrl+Shift+Enter)"
        onClick={onRedo}
      >
        Redo
      </button>
      <button
        type="button"
        className="btn btn-sm"
        disabled={sending}
        title="New session branch for subsequent sends"
        onClick={onDup}
      >
        Dup
      </button>
      <button
        type="button"
        className="btn btn-sm"
        disabled={sending}
        title="Re-materialize draft from current parent"
        onClick={onReset}
      >
        Reset
      </button>
      <button
        type="button"
        className="btn btn-sm"
        disabled={sending}
        onClick={onExport}
      >
        Export
      </button>
      <div className="relative">
        <button
          type="button"
          className="btn btn-sm"
          disabled={!canNote || sending}
          title="Note on last send execution only"
          onClick={() => setNoteOpen((v) => !v)}
        >
          Note
        </button>
        <NotePopover
          open={noteOpen}
          initial={noteInitial}
          disabled={sending}
          onClose={() => setNoteOpen(false)}
          onSave={(n) => {
            onNote(n);
            setNoteOpen(false);
          }}
        />
      </div>
      <button
        type="button"
        className="btn btn-sm btn-ghost"
        title="Wipe all local repeater drafts for this project"
        onClick={onClearDrafts}
      >
        Clear drafts
      </button>

      <div className="flex-1" />

      <label className="flex items-center gap-1 text-xs cursor-pointer">
        <input
          type="checkbox"
          className="checkbox checkbox-xs"
          checked={updateContentLength}
          onChange={onToggleCL}
          disabled={sending}
        />
        CL auto
      </label>

      <Link
        to={`/flows/${parentFlowId}`}
        className="btn btn-ghost btn-xs mono"
        title="Open parent flow"
      >
        parent
      </Link>
      {originalFlowId !== parentFlowId && (
        <Link
          to={`/flows/${originalFlowId}`}
          className="btn btn-ghost btn-xs mono"
          title="Open root capture"
        >
          root
        </Link>
      )}
    </div>
  );
}
