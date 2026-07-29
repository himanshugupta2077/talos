import type { RepeaterTabState } from "./draftState";

interface Props {
  tabs: RepeaterTabState[];
  activeTabId: string;
  onSelect: (id: string) => void;
  onClose: (id: string) => void;
  onNew: () => void;
  disabled?: boolean;
}

export default function RepeaterTabStrip({
  tabs,
  activeTabId,
  onSelect,
  onClose,
  onNew,
  disabled,
}: Props) {
  return (
    <div className="flex items-center gap-1 overflow-x-auto border-b border-base-300 bg-base-200/40 px-2 py-1 shrink-0">
      <button
        type="button"
        className="btn btn-ghost btn-xs shrink-0"
        title="New tab"
        disabled={disabled}
        onClick={onNew}
      >
        +
      </button>
      {tabs.map((t) => {
        const active = t.id === activeTabId;
        return (
          <div
            key={t.id}
            className={`flex items-center gap-1 rounded px-2 py-1 text-xs mono shrink-0 cursor-pointer border ${
              active
                ? "bg-base-100 border-primary/40 text-base-content"
                : "border-transparent text-base-content/70 hover:bg-base-100/60"
            }`}
            onClick={() => onSelect(t.id)}
            role="tab"
            aria-selected={active}
          >
            <span className="max-w-[160px] truncate">
              {t.title}
              {t.dirty ? " ✱" : ""}
            </span>
            <button
              type="button"
              className="btn btn-ghost btn-xs min-h-0 h-4 w-4 p-0 opacity-60 hover:opacity-100"
              title="Close tab"
              onClick={(e) => {
                e.stopPropagation();
                onClose(t.id);
              }}
            >
              ×
            </button>
          </div>
        );
      })}
    </div>
  );
}
