/**
 * PathField — compact label + monospace path + Copy path / Open directory actions.
 *
 * Purpose:
 *   Display a resolved project path without large primary buttons.
 *   Copy is browser clipboard; Open is a callback (backend-resolved target).
 *
 * Inputs:
 *   label, path, onCopy, onOpen, optional openRunning / copyRunning flags.
 * Outputs:
 *   Accessible icon buttons with title + aria-label.
 * Side effects:
 *   None (parent handles clipboard + API).
 */

import { ReactNode } from "react";

function CopyIcon() {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 20 20"
      fill="currentColor"
      className="w-3.5 h-3.5"
      aria-hidden="true"
    >
      <path d="M8 2a1 1 0 0 0-1 1v1H5a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h6a2 2 0 0 0 2-2v-1h1a1 1 0 0 0 1-1V6.414A2 2 0 0 0 14.586 5L12 2.414A2 2 0 0 0 10.586 2H8zm4 4H9V3h1.586L12 4.414V6zM5 6h2v1a1 1 0 0 0 1 1h4a1 1 0 0 0 1-1V6h.5a.5.5 0 0 1 .5.5V15a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1z" />
    </svg>
  );
}

function FolderIcon() {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 20 20"
      fill="currentColor"
      className="w-3.5 h-3.5"
      aria-hidden="true"
    >
      <path d="M2 6a2 2 0 0 1 2-2h3.586a1 1 0 0 1 .707.293l1.414 1.414A1 1 0 0 0 10.414 6H16a2 2 0 0 1 2 2v6a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V6z" />
    </svg>
  );
}

export type OpenDirectoryTarget = "data_dir" | "database_dir";

export interface PathFieldProps {
  label: string;
  path: string;
  /** Optional note after the path (e.g. "(missing)"). */
  note?: string;
  onCopy: () => void | Promise<void>;
  onOpen: () => void | Promise<void>;
  openRunning?: boolean;
  copyRunning?: boolean;
  /** Extra trailing content (tests / extensions). */
  trailing?: ReactNode;
}

export default function PathField({
  label,
  path,
  note,
  onCopy,
  onOpen,
  openRunning = false,
  copyRunning = false,
  trailing,
}: PathFieldProps) {
  return (
    <div data-testid="path-field" data-path={path}>
      <div className="text-base-content/50 mb-0.5 text-xs">{label}</div>
      <div className="flex items-start gap-1 min-w-0">
        <div
          className="mono break-all bg-base-200/50 rounded px-2 py-1 flex-1 text-xs min-w-0"
          data-testid="path-value"
        >
          {path}
          {note ? (
            <span className="text-base-content/50 font-sans"> {note}</span>
          ) : null}
        </div>
        <div className="flex gap-0.5 shrink-0 pt-0.5">
          <button
            type="button"
            className="btn btn-ghost btn-xs btn-square"
            aria-label="Copy path"
            data-testid="copy-path"
            disabled={copyRunning || !path}
            onClick={() => void onCopy()}
          >
            <CopyIcon />
          </button>
          <button
            type="button"
            className="btn btn-ghost btn-xs btn-square"
            aria-label="Open directory"
            data-testid="open-directory"
            disabled={openRunning || !path}
            onClick={() => void onOpen()}
          >
            {openRunning ? (
              <span className="loading loading-spinner loading-xs" />
            ) : (
              <FolderIcon />
            )}
          </button>
          {trailing}
        </div>
      </div>
    </div>
  );
}

/**
 * Build the open-directory request body.
 * Never includes a filesystem path — only a predefined target enum.
 */
export function openDirectoryBody(target: OpenDirectoryTarget): {
  target: OpenDirectoryTarget;
} {
  return { target };
}
