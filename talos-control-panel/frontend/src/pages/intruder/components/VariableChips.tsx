import type { TemplateVariable } from "../types";

export default function VariableChips({
  variables,
  selected,
  onSelect,
  onRemove,
}: {
  variables: TemplateVariable[];
  selected?: string | null;
  onSelect?: (name: string) => void;
  onRemove?: (name: string) => void;
}) {
  if (!variables.length) {
    return (
      <div className="text-xs text-base-content/50">
        No variables — use Add variable below.
      </div>
    );
  }
  return (
    <div className="flex flex-wrap gap-1.5">
      {variables.map((v) => {
        const attack = v.fixed_value == null;
        const active = selected === v.name;
        return (
          <span
            key={v.name}
            className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-xs mono ${
              active
                ? "border-primary bg-primary/10"
                : "border-base-300 bg-base-100"
            }`}
          >
            <button
              type="button"
              className="hover:underline"
              onClick={() => onSelect?.(v.name)}
            >
              {v.name}
            </button>
            <span className="text-base-content/40">{v.location}</span>
            <span
              className={
                attack ? "text-warning" : "text-base-content/50"
              }
            >
              {attack
                ? "attack"
                : `fixed=${String(v.fixed_value).slice(0, 12)}`}
            </span>
            {onRemove && (
              <button
                type="button"
                className="text-base-content/40 hover:text-error ml-0.5"
                title="Remove variable"
                onClick={() => onRemove(v.name)}
              >
                ×
              </button>
            )}
          </span>
        );
      })}
    </div>
  );
}
