import type { UnauthTechnique } from "../shared";

/**
 * Card grid for technique selection.
 * Empty selection (`""`) means all recipes (CLI default).
 */
export default function TechniqueCards({
  techniques,
  totalRecipes,
  selected,
  onSelect,
  disabled,
}: {
  techniques: UnauthTechnique[];
  totalRecipes: number;
  selected: string;
  onSelect: (name: string) => void;
  disabled?: boolean;
}) {
  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
      <button
        type="button"
        disabled={disabled}
        onClick={() => onSelect("")}
        className={`panel p-3 text-left transition border ${
          selected === ""
            ? "border-primary ring-1 ring-primary/40"
            : "border-transparent hover:border-base-300"
        } ${disabled ? "opacity-50 cursor-not-allowed" : "cursor-pointer"}`}
      >
        <div className="flex items-center justify-between gap-2 mb-1">
          <span className="font-medium text-sm">All recipes</span>
          <span className="badge badge-sm badge-primary badge-outline">
            {totalRecipes} recipes
          </span>
        </div>
        <p className="text-xs text-base-content/60 leading-snug">
          Enqueue every configured technique and baseline+mutation combination
          (default CLI behaviour).
        </p>
      </button>

      {techniques.map((t) => (
        <button
          key={t.name}
          type="button"
          disabled={disabled}
          onClick={() => onSelect(t.name)}
          className={`panel p-3 text-left transition border ${
            selected === t.name
              ? "border-primary ring-1 ring-primary/40"
              : "border-transparent hover:border-base-300"
          } ${disabled ? "opacity-50 cursor-not-allowed" : "cursor-pointer"}`}
        >
          <div className="flex items-center justify-between gap-2 mb-1">
            <span className="font-medium text-sm mono">{t.name}</span>
            <span className="badge badge-sm badge-ghost">
              {t.recipe_count} recipe{t.recipe_count === 1 ? "" : "s"}
            </span>
          </div>
          <p className="text-xs text-base-content/60 leading-snug">
            {t.description || "Unauth technique"}
          </p>
          {t.mutation_family && (
            <div className="text-[10px] uppercase tracking-wide text-base-content/40 mt-1">
              {t.mutation_family}
            </div>
          )}
        </button>
      ))}
    </div>
  );
}
