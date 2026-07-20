/**
 * Right-side drawer for Policy explain / Rules create-edit.
 * Prefer this over small modals for multi-section operator forms.
 */

import { ReactNode } from "react";

export default function SideDrawer({
  open,
  onClose,
  title,
  children,
  wide = false,
}: {
  open: boolean;
  onClose: () => void;
  title: string;
  children: ReactNode;
  wide?: boolean;
}) {
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-40 flex justify-end">
      <div className="absolute inset-0 bg-black/40" onClick={onClose} />
      <div
        className={`relative h-full bg-base-100 border-l border-base-300 shadow-xl flex flex-col ${
          wide ? "w-full max-w-2xl" : "w-full max-w-lg"
        }`}
      >
        <div className="flex items-center justify-between px-4 py-3 border-b border-base-300">
          <h3 className="font-semibold text-base">{title}</h3>
          <button className="btn btn-xs btn-ghost" onClick={onClose}>
            ✕
          </button>
        </div>
        <div className="flex-1 overflow-y-auto p-4">{children}</div>
      </div>
    </div>
  );
}
