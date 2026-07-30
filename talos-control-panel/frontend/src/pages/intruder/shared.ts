/** Labels, constants, and pure helpers for Intruder UI. */

import type {
  GeneratorType,
  InjectSuggestion,
  IntruderConfig,
  IntruderSessionStatus,
  IntruderStrategy,
  IntruderTab,
  IntruderTemplate,
  IntruderTimingMode,
  TemplateVariable,
  VariableLocation,
} from "./types";

export const INTRUDER_HELP_TITLE = "How Intruder works";

export const DEFAULT_RPS = 2;
export const DEFAULT_MAX_CONCURRENCY = 1;
export const DEFAULT_MAX_ATTEMPTS = 10_000;
export const CONFIRM_THRESHOLD = 1_000;
export const STATIC_HEURISTIC_LINES = 50;
export const STATIC_HEURISTIC_BYTES = 8 * 1024;

export const ALL_STRATEGIES: IntruderStrategy[] = [
  "single",
  "sniper",
  "pitchfork",
  "zip",
  "cluster_bomb",
];

/** @deprecated alias */
export const MVP_STRATEGIES: IntruderStrategy[] = ["single", "sniper"];
export const PHASE2_STRATEGIES: IntruderStrategy[] = [
  "pitchfork",
  "zip",
  "cluster_bomb",
  "cartesian",
];

export const MULTI_SET_STRATEGIES = new Set([
  "pitchfork",
  "zip",
  "cluster_bomb",
  "cartesian",
]);

export const ALL_GENERATORS: GeneratorType[] = [
  "wordlist",
  "numbers",
  "static",
  "uuid",
  "csv",
  "json",
  "example_values",
  "pool",
  "dates",
  "bruteforce",
  "random",
  "pattern",
];

export const MVP_GENERATORS: GeneratorType[] = ["wordlist", "numbers", "static"];

export const PATH_BACKED_GENERATORS = new Set(["wordlist", "csv", "json"]);

export const KNOWN_PROCESSORS = [
  "url_encode",
  "url_decode",
  "base64_encode",
  "base64_decode",
  "to_lower",
  "to_upper",
  "html_encode",
  "html_decode",
  "md5",
  "sha1",
  "sha256",
  "strip",
] as const;

export const TIMING_MODES: IntruderTimingMode[] = [
  "fixed",
  "token_bucket",
  "adaptive",
];

export const VARIABLE_LOCATIONS = [
  "path",
  "query",
  "body",
  "header",
  "cookie",
  "raw",
] as const;

export const STORAGE_MODE_COPY: Record<string, string> = {
  metrics_only:
    "Metrics rows only. Lowest DB growth. Bodies not kept per attempt.",
  sample_flows:
    "Flow rows for a sample (plus interesting if enabled). Moderate growth.",
  all_flows:
    "Full flow row every attempt. Can grow the project DB very quickly. Confirmation required to run.",
};

export const STRATEGY_COPY: Record<string, string> = {
  single:
    "One payload set → one variable (or sole attack var). Attempts ≈ set size.",
  sniper:
    "One payload set rotates through each attack position; others use baseline/fixed. Attempts ≈ set size × positions.",
  pitchfork:
    "Multiple sets lockstep (zip by index). Attempts ≈ min(set sizes).",
  zip: "Same family as pitchfork (lockstep / zip by index).",
  cluster_bomb:
    "Cartesian product of set sizes. Attempts ≈ ∏ sizes — can explode quickly.",
  cartesian: "Alias of cluster bomb (cartesian product).",
};

export const GENERATOR_LABELS: Record<GeneratorType, string> = {
  wordlist: "Wordlist (file)",
  numbers: "Numbers range",
  static: "Static values",
  uuid: "UUIDs",
  csv: "CSV column",
  json: "JSON list",
  example_values: "Example values (param)",
  pool: "Project pool",
  dates: "Date range",
  bruteforce: "Bruteforce charset",
  random: "Random strings",
  pattern: "Pattern template",
};

export const ACTIVE_STATUSES: IntruderSessionStatus[] = [
  "queued",
  "running",
  "paused",
];

export const TERMINAL_STATUSES: IntruderSessionStatus[] = [
  "completed",
  "failed",
  "cancelled",
];

export function isIntruderTab(v: string | null): v is IntruderTab {
  return (
    v === "configure" || v === "run" || v === "results" || v === "advanced"
  );
}

export function shortId(id: string | null | undefined): string {
  if (!id) return "—";
  return id.slice(0, 8);
}

export function statusTone(
  status: string
): "info" | "success" | "warning" | "error" | "ghost" {
  switch (status) {
    case "running":
    case "queued":
      return "info";
    case "completed":
    case "configured":
      return "success";
    case "paused":
    case "draft":
      return "warning";
    case "failed":
    case "cancelled":
      return "error";
    default:
      return "ghost";
  }
}

export function attackVariables(cfg: IntruderConfig): TemplateVariable[] {
  const vars = cfg.template?.variables || [];
  return vars.filter((v) => v.fixed_value == null || v.fixed_value === undefined);
}

export function countPayloadSetSize(
  generator: string | undefined,
  options: Record<string, unknown> | undefined,
  pendingText?: string
): number | null {
  const gen = (generator || "").toLowerCase();
  const opts = options || {};
  if (gen === "numbers") {
    const start = Number(opts.start ?? 0);
    const end = Number(opts.end ?? 0);
    const step = Number(opts.step ?? 1);
    if (!step || step === 0) return null;
    if (step > 0 && end < start) return 0;
    if (step < 0 && end > start) return 0;
    return Math.floor((end - start) / step) + 1;
  }
  if (gen === "static") {
    const values = opts.values;
    if (Array.isArray(values)) return values.length;
    if (typeof values === "string") {
      return values
        .split("\n")
        .map((l) => l.trim())
        .filter(Boolean).length;
    }
    return 0;
  }
  if (gen === "wordlist" || gen === "csv" || gen === "json") {
    if (pendingText != null && pendingText.length > 0) {
      return pendingText
        .split("\n")
        .map((l) => l.trimEnd())
        .filter((l) => l.length > 0).length;
    }
    // Path-backed without local text — unknown until validate
    return null;
  }
  if (gen === "uuid" || gen === "random") {
    const n = Number(opts.count ?? (gen === "uuid" ? 10 : 100));
    return Number.isFinite(n) && n > 0 ? Math.floor(n) : null;
  }
  if (gen === "bruteforce") {
    const charset = String(opts.charset ?? "abcdefghijklmnopqrstuvwxyz0123456789");
    const chars = [...new Set(charset.split(""))];
    const minLen = Number(opts.min_len ?? opts.min ?? 1);
    const maxLen = Number(opts.max_len ?? opts.max ?? 3);
    if (chars.length === 0 || minLen < 0 || maxLen < minLen) return 0;
    let total = 0;
    for (let len = minLen; len <= maxLen; len++) {
      total += Math.pow(chars.length, len);
    }
    return total;
  }
  if (gen === "pattern") {
    const start = Number(opts.start ?? 0);
    const end = Number(opts.end ?? 99);
    const step = Number(opts.step ?? 1);
    if (!step || step === 0) return null;
    if (step > 0 && end < start) return 0;
    if (step < 0 && end > start) return 0;
    // Without placeholders, pattern yields once — but we can't know cheaply;
    // assume counter range if start/end present
    return Math.floor((end - start) / step) + 1;
  }
  if (gen === "dates") {
    // Best-effort day count; null if dates invalid
    try {
      const start = String(opts.start_date || opts.start || "");
      const end = String(opts.end_date || opts.end || "");
      if (!start || !end) return null;
      const s = Date.parse(start.slice(0, 10));
      const e = Date.parse(end.slice(0, 10));
      if (Number.isNaN(s) || Number.isNaN(e)) return null;
      const stepDays = Number(opts.step_days ?? 1) || 1;
      const days = Math.floor((e - s) / 86400000);
      if (days < 0) return 0;
      return Math.floor(days / Math.abs(stepDays)) + 1;
    } catch {
      return null;
    }
  }
  // pool / example_values / unknown — need server
  return null;
}

/** Client-side estimate preview (authoritative after Save/Validate). */
export function estimateAttemptsFromDraft(
  cfg: IntruderConfig,
  artifacts: Record<string, { text?: string }>
): number | null {
  const strategy = (cfg.strategy?.type || "single").toLowerCase();
  const attack = attackVariables(cfg);
  const sets = cfg.payload_sets || {};

  const sizesFor = (names: string[]): (number | null)[] =>
    names.map((k) => {
      const ps = sets[k];
      if (!ps) return 0;
      return countPayloadSetSize(
        ps.generator,
        ps.options as Record<string, unknown>,
        artifacts[k]?.text
      );
    });

  if (strategy === "single" || strategy === "sniper") {
    const keys =
      attack.length > 0 ? attack.map((v) => v.name) : Object.keys(sets);
    let setSize: number | null = null;
    for (const k of keys) {
      const ps = sets[k];
      if (!ps) continue;
      const n = countPayloadSetSize(
        ps.generator,
        ps.options as Record<string, unknown>,
        artifacts[k]?.text
      );
      if (n != null) {
        setSize = n;
        break;
      }
    }
    if (setSize == null) return null;
    if (strategy === "sniper") {
      const positions = Math.max(1, attack.length || 1);
      return setSize * positions;
    }
    return setSize;
  }

  // Multi-set: use ordered strategy.sets if present, else all attack vars
  const ordered =
    Array.isArray(cfg.strategy?.sets) && (cfg.strategy!.sets as string[]).length
      ? (cfg.strategy!.sets as string[])
      : attack.map((v) => v.name);
  if (!ordered.length) return null;
  const sizes = sizesFor(ordered);
  if (sizes.some((n) => n == null)) return null;
  const nums = sizes as number[];
  if (strategy === "pitchfork" || strategy === "zip") {
    return Math.min(...nums);
  }
  if (strategy === "cluster_bomb" || strategy === "cartesian") {
    return nums.reduce((a, b) => a * b, 1);
  }
  return null;
}

export function roughDurationLabel(
  attempts: number | null,
  rps: number = DEFAULT_RPS,
  concurrency: number = DEFAULT_MAX_CONCURRENCY
): string {
  if (attempts == null || attempts <= 0 || rps <= 0) return "—";
  const effective = rps * Math.max(1, concurrency);
  const seconds = attempts / effective;
  if (seconds < 60) return `~${Math.ceil(seconds)}s at ${rps} RPS`;
  if (seconds < 3600) return `~${Math.ceil(seconds / 60)} min at ${rps} RPS`;
  return `~${(seconds / 3600).toFixed(1)} h at ${rps} RPS`;
}

export function deepCloneConfig(cfg: IntruderConfig): IntruderConfig {
  return JSON.parse(JSON.stringify(cfg || {})) as IntruderConfig;
}

export function ensureConfigDefaults(cfg: IntruderConfig): IntruderConfig {
  const c = deepCloneConfig(cfg);
  c.schema_version = c.schema_version ?? 1;
  c.template = c.template || {
    method: "GET",
    url: "",
    headers: {},
    body: null,
    variables: [],
  };
  c.template.variables = c.template.variables || [];
  c.payload_sets = c.payload_sets || {};
  c.strategy = c.strategy || { type: "single", options: {} };
  c.timing = c.timing || {
    mode: "fixed",
    rps: DEFAULT_RPS,
    max_concurrency: DEFAULT_MAX_CONCURRENCY,
    jitter_ms: 0,
    timeout_s: 30,
  };
  c.storage = c.storage || { mode: "metrics_only" };
  c.safety = c.safety || {
    respect_logout: true,
    respect_dangerous: true,
    require_in_scope: true,
    skip_auth_artifacts: false,
    max_attempts: DEFAULT_MAX_ATTEMPTS,
  };
  c.findings = c.findings || {
    promote: false,
    on: "interesting",
    max_findings: 25,
    only_success: true,
    cluster_by: "session",
  };
  c.match = c.match || [];
  c.grep = c.grep || [];
  return c;
}

export function formatRelative(iso: string | null | undefined): string {
  if (!iso) return "—";
  try {
    const t = new Date(iso).getTime();
    if (Number.isNaN(t)) return iso;
    const sec = Math.round((Date.now() - t) / 1000);
    if (sec < 60) return `${sec}s ago`;
    if (sec < 3600) return `${Math.floor(sec / 60)}m ago`;
    if (sec < 86400) return `${Math.floor(sec / 3600)}h ago`;
    return `${Math.floor(sec / 86400)}d ago`;
  } catch {
    return iso;
  }
}

export function pathInjectWarning(
  location: string,
  injectName: string,
  normalizedPath: string | null | undefined
): string | null {
  if (location !== "path") return null;
  const path = normalizedPath || "";
  const needle = `{${injectName}}`;
  if (!path.includes(needle)) {
    return (
      `Path inject requires {${injectName}} in the template normalized_path ` +
      `(currently ${path || "empty"}). Validate will fail with ERR_PATH_INJECT_UNAVAILABLE.`
    );
  }
  return null;
}

export function uniqueVarName(
  base: string,
  existing: TemplateVariable[]
): string {
  const names = new Set(existing.map((v) => v.name));
  if (!names.has(base)) return base;
  let i = 2;
  while (names.has(`${base}_${i}`)) i += 1;
  return `${base}_${i}`;
}

const HOP_BY_HOP = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailers",
  "transfer-encoding",
  "upgrade",
  "content-length",
  "host",
]);

/**
 * UI-only inject suggestions from baseline template (Phase 2 click-to-mark).
 * Does not rewrite the request — maps to Add variable fields.
 */
export function discoverInjectSuggestions(
  template: IntruderTemplate | undefined,
  existing: TemplateVariable[]
): InjectSuggestion[] {
  if (!template) return [];
  const existingNames = new Set(existing.map((v) => v.name));
  const existingKeys = new Set(
    existing.map((v) => `${v.location}:${v.path || v.name}`)
  );
  const out: InjectSuggestion[] = [];

  const push = (s: InjectSuggestion) => {
    const key = `${s.location}:${s.path}`;
    if (existingKeys.has(key) || existingNames.has(s.name)) return;
    // de-dupe within suggestions
    if (out.some((x) => `${x.location}:${x.path}` === key)) return;
    out.push(s);
  };

  // Existing {{x}} raw placeholders
  const rawSources = [
    template.url || "",
    ...Object.values(template.headers || {}),
    template.body != null ? String(template.body) : "",
  ].join("\n");
  for (const m of rawSources.matchAll(/\{\{([A-Za-z0-9_]+)\}\}/g)) {
    push({
      name: m[1],
      location: "raw",
      path: m[1],
      source: "raw {{…}} placeholder",
    });
  }

  // Path braces from normalized_path
  const np = template.normalized_path || "";
  for (const m of np.matchAll(/\{([A-Za-z0-9_]+)\}/g)) {
    push({
      name: m[1],
      location: "path",
      path: m[1],
      source: "normalized_path",
    });
  }

  // Query keys from URL
  try {
    const url = template.url || "";
    const qIdx = url.indexOf("?");
    if (qIdx >= 0) {
      const qs = url.slice(qIdx + 1).split("#")[0];
      const params = new URLSearchParams(qs);
      for (const [k, v] of params.entries()) {
        if (!k) continue;
        push({
          name: k.replace(/[^A-Za-z0-9_]/g, "_") || "query",
          location: "query",
          path: k,
          original_value: v,
          source: "URL query",
        });
      }
    }
  } catch {
    /* ignore */
  }

  // Headers / cookies
  const headers = template.headers || {};
  for (const [k, v] of Object.entries(headers)) {
    const lk = k.toLowerCase();
    if (HOP_BY_HOP.has(lk)) continue;
    if (lk === "cookie") {
      const parts = String(v).split(";");
      for (const part of parts) {
        const eq = part.indexOf("=");
        if (eq <= 0) continue;
        const name = part.slice(0, eq).trim();
        const val = part.slice(eq + 1).trim();
        if (!name) continue;
        push({
          name: name.replace(/[^A-Za-z0-9_]/g, "_") || "cookie",
          location: "cookie",
          path: name,
          original_value: val,
          source: "Cookie header",
        });
      }
      continue;
    }
    push({
      name: k.replace(/[^A-Za-z0-9_]/g, "_") || "header",
      location: "header" as VariableLocation,
      path: k,
      original_value: String(v),
      source: "Header",
    });
  }

  // Body form / shallow JSON
  const body = template.body != null ? String(template.body) : "";
  const ct = Object.entries(headers).find(
    ([k]) => k.toLowerCase() === "content-type"
  )?.[1];
  if (body && ct && /application\/x-www-form-urlencoded/i.test(ct)) {
    try {
      const params = new URLSearchParams(body);
      for (const [k, v] of params.entries()) {
        if (!k) continue;
        push({
          name: k.replace(/[^A-Za-z0-9_]/g, "_") || "body",
          location: "body",
          path: k,
          original_value: v,
          source: "form body",
        });
      }
    } catch {
      /* ignore */
    }
  } else if (body && /^\s*[{[]/.test(body)) {
    try {
      const parsed = JSON.parse(body);
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
        for (const [k, v] of Object.entries(parsed)) {
          if (v != null && typeof v === "object") continue; // shallow only
          push({
            name: k.replace(/[^A-Za-z0-9_]/g, "_") || "body",
            location: "body",
            path: k,
            original_value: v == null ? null : String(v),
            source: "JSON body (top-level)",
          });
        }
      }
    } catch {
      /* ignore */
    }
  }

  return out;
}

export function suggestionToVariable(
  s: InjectSuggestion,
  existing: TemplateVariable[]
): TemplateVariable {
  const name = uniqueVarName(
    s.name.replace(/[^A-Za-z0-9_]/g, "_") || "var",
    existing
  );
  return {
    name,
    location: s.location,
    path: s.path || name,
    original_value: s.original_value ?? null,
    fixed_value: null,
  };
}
