import type { BacTechnique } from "../shared";

/**
 * Multi-select card grid for BAC techniques.
 * Empty selection (`[]`) means all techniques (CLI default product behaviour).
 */
export default function TechniqueCards({
  techniques,
  totalVariants,
  selected,
  onChange,
  disabled,
}: {
  techniques: BacTechnique[];
  totalVariants: number;
  /** Empty = all techniques selected (default). */
  selected: string[];
  onChange: (names: string[]) => void;
  disabled?: boolean;
}) {
  const allSelected = selected.length === 0;
  const selectedSet = new Set(selected);

  const selectAll = () => onChange([]);

  const toggle = (name: string) => {
    if (allSelected) {
      // Leaving "all" mode: select only this technique? Or deselect it from full set?
      // Better: switch to full set minus this one when deselecting from all,
      // or just that one when clicking a card while all is active.
      // Click while all → select only that technique (common UX).
      onChange([name]);
      return;
    }
    if (selectedSet.has(name)) {
      const next = selected.filter((n) => n !== name);
      // If none left, fall back to all
      onChange(next.length === 0 ? [] : next);
    } else {
      const next = [...selected, name];
      // If every technique is selected, collapse to "all"
      if (next.length >= techniques.length) {
        onChange([]);
      } else {
        onChange(next);
      }
    }
  };

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
      <button
        type="button"
        disabled={disabled}
        onClick={selectAll}
        className={`panel p-3 text-left transition border ${
          allSelected
            ? "border-primary ring-1 ring-primary/40"
            : "border-transparent hover:border-base-300"
        } ${disabled ? "opacity-50 cursor-not-allowed" : "cursor-pointer"}`}
      >
        <div className="flex items-center justify-between gap-2 mb-1">
          <span className="font-medium text-sm">All techniques</span>
          <span className="badge badge-sm badge-primary badge-outline">
            {totalVariants} variants
          </span>
        </div>
        <p className="text-xs text-base-content/60 leading-snug">
          Enqueue every BAC family (default). Matches running each{" "}
          <span className="mono">talos attack bac &lt;technique&gt;</span> in
          sequence.
        </p>
      </button>

      {techniques.map((t) => {
        const isOn = allSelected || selectedSet.has(t.name);
        return (
          <button
            key={t.name}
            type="button"
            disabled={disabled}
            onClick={() => toggle(t.name)}
            className={`panel p-3 text-left transition border ${
              isOn && !allSelected
                ? "border-primary ring-1 ring-primary/40"
                : allSelected
                  ? "border-base-300/60"
                  : "border-transparent hover:border-base-300"
            } ${disabled ? "opacity-50 cursor-not-allowed" : "cursor-pointer"}`}
          >
            <div className="flex items-center justify-between gap-2 mb-1">
              <span className="font-medium text-sm mono">{t.name}</span>
              <span className="badge badge-sm badge-ghost">
                {t.variant_count} variant{t.variant_count === 1 ? "" : "s"}
              </span>
            </div>
            <p className="text-xs text-base-content/60 leading-snug">
              {t.description || "BAC technique family"}
            </p>
          </button>
        );
      })}
    </div>
  );
}
