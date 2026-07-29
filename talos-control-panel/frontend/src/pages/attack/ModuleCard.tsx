import { Link } from "react-router-dom";
import { AttackModuleDef } from "./registry";

export type ModuleKpis = {
  /** Short label/value pairs shown under the title. */
  chips: { label: string; value: string | number; tone?: "ok" | "warn" | "danger" | "muted" }[];
  /** Optional one-line status (e.g. "Auto-run on", "Scanner disabled"). */
  statusLine?: string;
};

const toneClass: Record<NonNullable<ModuleKpis["chips"][0]["tone"]>, string> = {
  ok: "text-success",
  warn: "text-warning",
  danger: "text-error",
  muted: "text-base-content/50",
};

/**
 * Hub card for one attack module. Click-through to the module workspace.
 * Cards stay minimal — class/risk live in section headers and workspace chrome.
 */
export default function ModuleCard({
  module,
  kpis,
}: {
  module: AttackModuleDef;
  kpis?: ModuleKpis | null;
}) {
  const comingSoon = module.status === "coming_soon";
  const body = (
    <div
      className={`panel p-4 h-full flex flex-col gap-2 transition-colors ${
        comingSoon
          ? "opacity-70 cursor-default"
          : "hover:border-primary/40 hover:bg-base-200/40 cursor-pointer"
      }`}
    >
      <div className="flex items-start justify-between gap-2">
        <h3 className="font-semibold text-sm leading-tight">{module.name}</h3>
        {comingSoon && (
          <span className="badge badge-xs badge-ghost shrink-0">soon</span>
        )}
      </div>

      {kpis?.chips && kpis.chips.length > 0 && (
        <div className="flex flex-wrap gap-x-3 gap-y-1 text-xs">
          {kpis.chips.map((c) => (
            <span key={c.label} className="inline-flex items-baseline gap-1">
              <span className={`font-semibold tabular-nums ${c.tone ? toneClass[c.tone] : ""}`}>
                {c.value}
              </span>
              <span className="text-base-content/45">{c.label}</span>
            </span>
          ))}
        </div>
      )}

      {kpis?.statusLine && (
        <div className="text-[11px] text-base-content/45">{kpis.statusLine}</div>
      )}
    </div>
  );

  if (comingSoon) return body;
  return (
    <Link to={module.path} className="block h-full no-underline text-inherit">
      {body}
    </Link>
  );
}
