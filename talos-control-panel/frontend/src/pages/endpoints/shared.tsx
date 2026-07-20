/** Shared helpers for Endpoint Workspace tabs. */

import { ReactNode } from "react";
import StatusBadge from "../../components/StatusBadge";
import { formatIST } from "../../lib/time";
import { EndpointRow } from "../../types";

/**
 * Compact relative age for inventory tables (e.g. 2m, 4h, 3d).
 * Lives here because frontend/src/lib is matched by repo-root `lib/` gitignore.
 */
export function formatRelativeAge(value: string | null | undefined): string {
  if (!value) return "—";
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return value;
  const sec = Math.max(0, Math.floor((Date.now() - d.getTime()) / 1000));
  if (sec < 60) return `${sec}s`;
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min}m`;
  const hr = Math.floor(min / 60);
  if (hr < 48) return `${hr}h`;
  const days = Math.floor(hr / 24);
  if (days < 60) return `${days}d`;
  return formatIST(value);
}

export const PAGE_SIZE = 50;
export const PRIORITIES = ["CRITICAL", "HIGH", "NORMAL", "LOW"] as const;
export const selectClass = "select select-xs select-bordered";
export const inputClass = "input input-xs input-bordered";

export type WorkspaceTab = "inventory" | "policy" | "rules" | "coverage";

export interface EndpointFilters {
  methods: string[];
  roles: string[];
  modules: string[];
  priorities: string[];
  priority_sources: string[];
  qualification_reasons: string[];
  tags: string[];
  origins: string[];
}

export type FilterState = {
  search: string;
  method: string;
  role: string;
  module: string;
  priority: string;
  priority_source: string;
  qualified: string;
  excluded: string;
  dangerous: string;
  logout: string;
  qualification_reason: string;
  tag: string;
  has_parameters: string;
  has_baseline: string;
  origin: string;
  state: string;
  decision: string;
  problem: string;
};

export const EMPTY_FILTERS: FilterState = {
  search: "",
  method: "",
  role: "",
  module: "",
  priority: "",
  priority_source: "",
  qualified: "",
  excluded: "",
  dangerous: "",
  logout: "",
  qualification_reason: "",
  tag: "",
  has_parameters: "",
  has_baseline: "",
  origin: "",
  state: "",
  decision: "",
  problem: "",
};

export function filtersToParams(f: FilterState): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(f)) {
    if (v) out[k] = v;
  }
  return out;
}

export function PrioritySourceBadge({
  row,
  onRuleClick,
}: {
  row: EndpointRow;
  onRuleClick?: (ruleId: string, pattern?: string) => void;
}) {
  const prio = row.effective_priority || row.manual_priority || row.auto_priority;
  const src = (row.priority_source || "AUTO").toUpperCase();
  return (
    <span className="inline-flex items-center gap-1">
      <StatusBadge value={prio} />
      {src === "RULE" && row.priority_rule_id && onRuleClick ? (
        <button
          className="badge badge-ghost badge-xs uppercase hover:badge-primary"
          onClick={(e) => {
            e.stopPropagation();
            onRuleClick(row.priority_rule_id!, row.matching_rule || undefined);
          }}
        >
          {src}
        </button>
      ) : (
        <span className="badge badge-ghost badge-xs uppercase">
          {src}
        </span>
      )}
    </span>
  );
}

export function StateBadge({ state }: { state?: string }) {
  const s = (state || "—").toUpperCase();
  const cls =
    s === "TESTABLE"
      ? "badge-success"
      : s === "EXCLUDED"
        ? "badge-ghost"
        : s === "LOGOUT" || s === "DANGEROUS"
          ? "badge-error"
          : s === "UNQUALIFIED"
            ? "badge-warning"
            : "badge-ghost";
  return <span className={`badge badge-xs ${cls}`}>{s}</span>;
}

export function DecisionBadge({ decision }: { decision?: string }) {
  const d = (decision || "—").toUpperCase();
  return (
    <span className={`badge badge-sm ${d === "TESTABLE" ? "badge-success" : "badge-ghost"}`}>
      {d}
    </span>
  );
}

export function RolesCell({ roles }: { roles: string | null | undefined }) {
  if (!roles) return <span className="text-base-content/40">—</span>;
  const parts = roles.split(",").map((s) => s.trim()).filter(Boolean);
  if (parts.length === 0) return <span className="text-base-content/40">—</span>;
  if (parts.length === 1) return <span className="text-xs">{parts[0]}</span>;
  return (
    <span className="text-xs">
      {parts[0]} <span className="text-base-content/50">+{parts.length - 1}</span>
    </span>
  );
}

export function EndpointLabel({ row }: { row: EndpointRow }) {
  return (
    <div className="min-w-0">
      <div className="mono text-xs truncate">
        {row.origin || row.host}
      </div>
      <div className="mono text-xs font-medium truncate">
        {row.normalized_path}
      </div>
    </div>
  );
}

export function SummaryChip({
  label,
  value,
  active,
  onClick,
}: {
  label: string;
  value: number;
  active?: boolean;
  onClick?: () => void;
}) {
  return (
    <button
      type="button"
      className={`btn btn-xs ${active ? "btn-primary" : "btn-ghost"} gap-1`}
      onClick={onClick}
    >
      <span className="font-semibold tabular-nums">{value}</span>
      <span className="opacity-70 font-normal">{label}</span>
    </button>
  );
}

export function CardStat({
  label,
  value,
  onClick,
}: {
  label: string;
  value: number | string;
  onClick?: () => void;
}) {
  const inner = (
    <>
      <div className="text-2xl font-semibold tabular-nums">{value}</div>
      <div className="text-[10px] uppercase tracking-wide text-base-content/50 mt-1">{label}</div>
    </>
  );
  if (onClick) {
    return (
      <button type="button" className="panel p-3 text-left hover:border-primary/40 transition" onClick={onClick}>
        {inner}
      </button>
    );
  }
  return <div className="panel p-3">{inner}</div>;
}

export function BulkResultBanner({
  result,
}: {
  result: {
    ok?: boolean;
    bulk?: { affected?: number; unchanged?: number; count?: number; action?: string };
    steps?: { ok?: boolean; stderr?: string }[];
  } | null;
}) {
  if (!result) return null;
  const bulk = result.bulk;
  const failed = result.ok === false || result.steps?.some((s) => s.ok === false);
  if (failed) {
    const err =
      result.steps
        ?.filter((s) => !s.ok)
        .map((s) => s.stderr)
        .filter(Boolean)
        .join("\n") || "The bulk operation was rejected by Talos.";
    return (
      <div className="alert alert-error text-sm py-2">
        <div>
          <div className="font-semibold">No endpoints changed</div>
          <pre className="text-xs whitespace-pre-wrap mt-1 opacity-90">{err}</pre>
          <div className="text-xs mt-1 opacity-70">The bulk operation was rejected by Talos.</div>
        </div>
      </div>
    );
  }
  if (!bulk || bulk.affected == null) return null;
  return (
    <div className="alert alert-success text-sm py-2">
      <div>
        <div className="font-semibold">
          {bulk.action ? `${bulk.action}` : "Bulk action applied"}
        </div>
        <div className="text-xs mono mt-1 space-x-4">
          <span>Affected {bulk.affected ?? 0}</span>
          <span>Unchanged {bulk.unchanged ?? 0}</span>
          <span>Total {bulk.count ?? (bulk.affected || 0) + (bulk.unchanged || 0)}</span>
        </div>
      </div>
    </div>
  );
}

/** Suggest a path glob from selected endpoint paths (operator must confirm). */
export function suggestPathPattern(paths: string[]): string {
  if (paths.length === 0) return "";
  if (paths.length === 1) {
    const p = paths[0];
    // Replace trailing UUID/numeric segments with *
    return p.replace(/\/[0-9a-f-]{8,}(?=\/|$)/gi, "/{id}").replace(/\/\d+(?=\/|$)/g, "/{id}");
  }
  const segs = paths.map((p) => p.split("/").filter(Boolean));
  const minLen = Math.min(...segs.map((s) => s.length));
  const common: string[] = [];
  for (let i = 0; i < minLen; i++) {
    const token = segs[0][i];
    if (segs.every((s) => s[i] === token)) common.push(token);
    else break;
  }
  if (common.length === 0) return "/*";
  return "/" + common.join("/") + "/*";
}

export function FilterBar({
  filters,
  options,
  onChange,
  extra,
}: {
  filters: FilterState;
  options: EndpointFilters;
  onChange: (patch: Partial<FilterState>) => void;
  extra?: ReactNode;
}) {
  return (
    <div className="flex flex-wrap gap-2 mb-3">
      <input
        className={`${inputClass} mono w-56`}
        placeholder="Search path / host…"
        value={filters.search}
        onChange={(e) => onChange({ search: e.target.value })}
      />
      <select className={selectClass} value={filters.origin} onChange={(e) => onChange({ origin: e.target.value })}>
        <option value="">origin: any</option>
        {options.origins.map((o) => (
          <option key={o} value={o}>{o}</option>
        ))}
      </select>
      <select className={selectClass} value={filters.method} onChange={(e) => onChange({ method: e.target.value })}>
        <option value="">method: any</option>
        {options.methods.map((m) => (
          <option key={m} value={m}>{m}</option>
        ))}
      </select>
      <select className={selectClass} value={filters.priority} onChange={(e) => onChange({ priority: e.target.value })}>
        <option value="">priority: any</option>
        {PRIORITIES.map((p) => (
          <option key={p} value={p}>{p}</option>
        ))}
      </select>
      <select
        className={selectClass}
        value={filters.priority_source}
        onChange={(e) => onChange({ priority_source: e.target.value })}
      >
        <option value="">priority source: any</option>
        <option value="MANUAL">Manual</option>
        <option value="RULE">Rule</option>
        <option value="AUTO">Auto</option>
      </select>
      <select className={selectClass} value={filters.excluded} onChange={(e) => onChange({ excluded: e.target.value })}>
        <option value="">included / excluded</option>
        <option value="0">Included</option>
        <option value="1">Excluded</option>
      </select>
      <select className={selectClass} value={filters.qualified} onChange={(e) => onChange({ qualified: e.target.value })}>
        <option value="">qualified: any</option>
        <option value="1">Qualified</option>
        <option value="0">Unqualified</option>
      </select>
      <select
        className={selectClass}
        value={filters.qualification_reason}
        onChange={(e) => onChange({ qualification_reason: e.target.value })}
      >
        <option value="">qualification reason</option>
        {options.qualification_reasons.map((r) => (
          <option key={r} value={r}>{r}</option>
        ))}
      </select>
      <select className={selectClass} value={filters.dangerous} onChange={(e) => onChange({ dangerous: e.target.value })}>
        <option value="">safety: any</option>
        <option value="0">Safe</option>
        <option value="1">Dangerous</option>
      </select>
      <select className={selectClass} value={filters.logout} onChange={(e) => onChange({ logout: e.target.value })}>
        <option value="">logout: any</option>
        <option value="1">Logout</option>
        <option value="0">Not logout</option>
      </select>
      <select className={selectClass} value={filters.role} onChange={(e) => onChange({ role: e.target.value })}>
        <option value="">role: any</option>
        {options.roles.map((r) => (
          <option key={r} value={r}>{r}</option>
        ))}
      </select>
      <select className={selectClass} value={filters.module} onChange={(e) => onChange({ module: e.target.value })}>
        <option value="">module: any</option>
        {options.modules.map((m) => (
          <option key={m} value={m}>{m}</option>
        ))}
      </select>
      <select className={selectClass} value={filters.tag} onChange={(e) => onChange({ tag: e.target.value })}>
        <option value="">tag: any</option>
        {options.tags.map((t) => (
          <option key={t} value={t}>{t}</option>
        ))}
      </select>
      <select
        className={selectClass}
        value={filters.has_parameters}
        onChange={(e) => onChange({ has_parameters: e.target.value })}
      >
        <option value="">parameters: any</option>
        <option value="1">Has parameters</option>
        <option value="0">No parameters</option>
      </select>
      <select
        className={selectClass}
        value={filters.has_baseline}
        onChange={(e) => onChange({ has_baseline: e.target.value })}
      >
        <option value="">baseline: any</option>
        <option value="1">Has baseline</option>
        <option value="0">No baseline</option>
      </select>
      {extra}
      <button
        type="button"
        className="btn btn-xs btn-ghost"
        onClick={() => onChange({ ...EMPTY_FILTERS })}
      >
        Clear filters
      </button>
    </div>
  );
}
