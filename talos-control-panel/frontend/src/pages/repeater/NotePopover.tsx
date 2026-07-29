import { useState } from "react";

interface Props {
  open: boolean;
  initial: string;
  onSave: (note: string) => void;
  onClose: () => void;
  disabled?: boolean;
}

export default function NotePopover({
  open,
  initial,
  onSave,
  onClose,
  disabled,
}: Props) {
  const [note, setNote] = useState(initial);
  if (!open) return null;
  return (
    <div className="absolute z-30 right-0 mt-1 w-72 panel p-3 shadow-lg border border-base-300 bg-base-100">
      <div className="text-xs font-medium mb-1">Note on last send</div>
      <p className="text-[10px] text-base-content/50 mb-2">
        Stored on the send execution only (not on proxy captures).
      </p>
      <textarea
        className="textarea textarea-bordered textarea-xs w-full min-h-[72px]"
        value={note}
        disabled={disabled}
        onChange={(e) => setNote(e.target.value)}
      />
      <div className="flex gap-2 justify-end mt-2">
        <button type="button" className="btn btn-xs" onClick={onClose}>
          Cancel
        </button>
        <button
          type="button"
          className="btn btn-xs btn-primary"
          disabled={disabled}
          onClick={() => onSave(note)}
        >
          Save
        </button>
      </div>
    </div>
  );
}
