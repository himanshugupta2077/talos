import { ALL_STRATEGIES, MULTI_SET_STRATEGIES, STRATEGY_COPY } from "../shared";
import type { IntruderStrategy } from "../types";

export default function StrategyPicker({
  value,
  onChange,
  attackVarCount = 0,
}: {
  value: string;
  onChange: (s: IntruderStrategy) => void;
  /** Number of attack (non-fixed) variables — used for multi-set guidance. */
  attackVarCount?: number;
}) {
  const current = (value || "single").toLowerCase();
  const multiNeedsVars = MULTI_SET_STRATEGIES.has(current) && attackVarCount < 2;

  return (
    <div className="space-y-2">
      <div className="text-sm font-medium">Strategy</div>
      <div className="flex flex-col gap-2">
        {ALL_STRATEGIES.map((s) => {
          const isMulti = MULTI_SET_STRATEGIES.has(s);
          return (
            <label
              key={s}
              className={`flex items-start gap-2 cursor-pointer rounded-md border px-3 py-2 text-sm transition-colors ${
                current === s
                  ? s === "cluster_bomb"
                    ? "border-warning/60 bg-warning/10"
                    : "border-primary bg-primary/5"
                  : "border-base-300 hover:border-base-content/20"
              }`}
            >
              <input
                type="radio"
                className="radio radio-sm mt-0.5"
                name="intruder-strategy"
                checked={current === s}
                onChange={() => onChange(s)}
              />
              <span className="min-w-0">
                <span className="font-medium capitalize">
                  {s === "cluster_bomb" ? "cluster bomb" : s.replace("_", " ")}
                  {isMulti && (
                    <span className="ml-1 badge badge-ghost badge-xs">
                      multi-set
                    </span>
                  )}
                </span>
                <span className="block text-xs text-base-content/60 mt-0.5">
                  {STRATEGY_COPY[s]}
                </span>
              </span>
            </label>
          );
        })}
      </div>

      {current === "cluster_bomb" && (
        <div className="alert alert-warning text-xs py-2">
          <span>
            <strong>Cluster bomb</strong> is a product of payload-set sizes.
            Two sets of 100 → 10,000 attempts. Confirm carefully before Run.
          </span>
        </div>
      )}

      {multiNeedsVars && (
        <div className="text-xs text-warning">
          Multi-set strategies need at least two attack variables with payload
          sets. Add more variables on Configure.
        </div>
      )}

      {/* Tiny visual diagrams */}
      <div className="rounded-md border border-base-300/60 bg-base-200/20 px-3 py-2 text-[11px] text-base-content/50 mono leading-relaxed">
        {current === "single" && "var₁ ← payload[i]  for i in set"}
        {current === "sniper" &&
          "for each attack position: rotate payload set; others fixed/baseline"}
        {(current === "pitchfork" || current === "zip") &&
          "zip(set₁, set₂, …) by index — length = min(sizes)"}
        {current === "cluster_bomb" &&
          "product(set₁ × set₂ × …) — length = ∏ sizes"}
      </div>
    </div>
  );
}
