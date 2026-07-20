/**
 * HTTP Rules workspace — workflow UI for the HTTP Manipulation Engine.
 *
 * Route: /mutations (bookmarks preserved). Sidebar label: HTTP Rules.
 * Rules live in layered config (project.yaml / ~/.talos/config.yaml).
 * All writes go through /api/mutations → talos config http.
 */
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { useProject } from "../state/ProjectContext";
import { api } from "../api/client";
import { useAction } from "../hooks/useAction";
import {
  NoProjectNotice,
  ConfirmButton,
  ModuleHelp,
  FieldHint,
  Modal,
} from "../components/Common";
import SideDrawer from "../components/SideDrawer";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface HttpAction {
  op: string;
  name?: string;
  value?: string | number;
  from?: string;
  to?: string;
  pattern?: string;
  replacement?: string;
  ms?: number;
  [key: string]: unknown;
}

interface HttpRule {
  id: string;
  name: string;
  enabled?: boolean;
  priority?: number;
  direction?: string;
  source?: string;
  scope?: string;
  match?: Record<string, unknown>;
  actions?: HttpAction[];
  description?: string;
}

interface Summary {
  active: number;
  request: number;
  response: number;
  disabled: number;
  total: number;
}

interface RuleFormState {
  name: string;
  enabled: boolean;
  priority: number;
  priorityAdvanced: boolean;
  direction: "request" | "response" | "both";
  globalScope: boolean;
  description: string;
  matchHost: string;
  matchPath: string;
  matchMethod: string;
  matchStatus: string;
  matchEndpoint: string;
  matchRole: string;
  matchModule: string;
  headerExists: string;
  actions: HttpAction[];
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const PRIORITY_PRESETS = [
  { label: "Lowest", value: 10 },
  { label: "Low", value: 25 },
  { label: "Normal", value: 50 },
  { label: "High", value: 75 },
  { label: "Highest", value: 100 },
] as const;

const ACTION_CATEGORIES = [
  {
    label: "Header",
    ops: [
      { op: "header.replace", label: "Replace" },
      { op: "header.add", label: "Add" },
      { op: "header.remove", label: "Remove" },
      { op: "header.rename", label: "Rename" },
    ],
  },
  {
    label: "Cookie",
    ops: [
      { op: "cookie.replace", label: "Replace" },
      { op: "cookie.add", label: "Add" },
      { op: "cookie.remove", label: "Remove" },
    ],
  },
  {
    label: "Query",
    ops: [
      { op: "query.replace", label: "Replace" },
      { op: "query.add", label: "Add" },
      { op: "query.remove", label: "Remove" },
    ],
  },
  {
    label: "URL / Method",
    ops: [
      { op: "url.host", label: "Rewrite host" },
      { op: "url.path", label: "Rewrite path" },
      { op: "method.replace", label: "Replace method" },
    ],
  },
  {
    label: "Body",
    ops: [
      { op: "body.regex_replace", label: "Regex replace" },
      { op: "body.append", label: "Append" },
      { op: "body.prepend", label: "Prepend" },
    ],
  },
  {
    label: "Response / Transport",
    ops: [
      { op: "status.override", label: "Status override" },
      { op: "delay", label: "Delay" },
      { op: "drop", label: "Drop" },
      { op: "abort", label: "Abort" },
    ],
  },
] as const;

const RULE_TEMPLATES: {
  id: string;
  label: string;
  description: string;
  form: Partial<RuleFormState> & { actions: HttpAction[] };
}[] = [
  {
    id: "cache-validators",
    label: "Remove Cache Validators",
    description: "Strip If-None-Match / If-Modified-Since on requests",
    form: {
      name: "Strip Validators",
      direction: "request",
      priority: 10,
      actions: [
        { op: "header.remove", name: "If-None-Match" },
        { op: "header.remove", name: "If-Modified-Since" },
      ],
    },
  },
  {
    id: "auth-replace",
    label: "Replace Authorization",
    description: "Swap the Authorization header value",
    form: {
      name: "Replace Authorization",
      direction: "request",
      priority: 50,
      actions: [{ op: "header.replace", name: "Authorization", value: "Bearer TEST" }],
    },
  },
  {
    id: "research-header",
    label: "Inject Research Header",
    description: "Add X-Research (or similar) on requests",
    form: {
      name: "Research Header",
      direction: "request",
      priority: 30,
      actions: [{ op: "header.replace", name: "X-Research", value: "talos" }],
    },
  },
  {
    id: "remove-csp",
    label: "Remove CSP",
    description: "Drop Content-Security-Policy from responses",
    form: {
      name: "Remove CSP",
      direction: "response",
      priority: 50,
      actions: [
        { op: "header.remove", name: "Content-Security-Policy" },
        { op: "header.remove", name: "Content-Security-Policy-Report-Only" },
      ],
    },
  },
  {
    id: "delay-response",
    label: "Delay Response",
    description: "Add latency for race / timeout testing",
    form: {
      name: "Delay Response",
      direction: "response",
      priority: 50,
      actions: [{ op: "delay", ms: 200 }],
    },
  },
  {
    id: "block-requests",
    label: "Block Requests",
    description: "Drop matching requests before they leave the proxy",
    form: {
      name: "Block Requests",
      direction: "request",
      priority: 10,
      actions: [{ op: "drop" }],
    },
  },
  {
    id: "rewrite-host",
    label: "Rewrite Host",
    description: "Change request host (URL host rewrite)",
    form: {
      name: "Rewrite Host",
      direction: "request",
      priority: 50,
      actions: [{ op: "url.host", value: "api.example.com" }],
    },
  },
  {
    id: "debug-header",
    label: "Add Debug Header",
    description: "Inject a debug marker header",
    form: {
      name: "Add Debug Header",
      direction: "request",
      priority: 75,
      actions: [{ op: "header.add", name: "X-Talos-Debug", value: "1" }],
    },
  },
];

const METHODS = ["", "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function emptyForm(): RuleFormState {
  return {
    name: "",
    enabled: true,
    priority: 50,
    priorityAdvanced: false,
    direction: "request",
    globalScope: false,
    description: "",
    matchHost: "",
    matchPath: "",
    matchMethod: "",
    matchStatus: "",
    matchEndpoint: "",
    matchRole: "",
    matchModule: "",
    headerExists: "",
    actions: [{ op: "header.replace", name: "", value: "" }],
  };
}

function ruleToForm(rule: HttpRule): RuleFormState {
  const match = rule.match || {};
  const asStr = (v: unknown) =>
    Array.isArray(v) ? String(v[0] ?? "") : v == null ? "" : String(v);
  const prio = Number(rule.priority ?? 50);
  const preset = PRIORITY_PRESETS.some((p) => p.value === prio);
  return {
    name: rule.name || "",
    enabled: rule.enabled !== false,
    priority: prio,
    priorityAdvanced: !preset,
    direction: (rule.direction as RuleFormState["direction"]) || "request",
    globalScope: (rule.source || "").toLowerCase() === "global",
    description: rule.description || "",
    matchHost: asStr(match.host),
    matchPath: asStr(match.path),
    matchMethod: asStr(match.method).toUpperCase(),
    matchStatus: asStr(match.status_code),
    matchEndpoint: asStr(match.endpoint_id),
    matchRole: asStr(match.role),
    matchModule: asStr(match.module),
    headerExists: Array.isArray(match.header_exists)
      ? (match.header_exists as string[]).join(", ")
      : asStr(match.header_exists),
    actions:
      rule.actions && rule.actions.length > 0
        ? rule.actions.map((a) => ({ ...a }))
        : [{ op: "header.replace", name: "", value: "" }],
  };
}

function formToMatch(form: RuleFormState): Record<string, unknown> {
  const match: Record<string, unknown> = {};
  if (form.matchHost.trim()) match.host = form.matchHost.trim();
  if (form.matchPath.trim()) match.path = form.matchPath.trim();
  if (form.matchMethod.trim()) match.method = form.matchMethod.trim().toUpperCase();
  if (form.matchStatus.trim()) {
    const n = parseInt(form.matchStatus.trim(), 10);
    if (!Number.isNaN(n)) match.status_code = n;
  }
  if (form.matchEndpoint.trim()) match.endpoint_id = form.matchEndpoint.trim();
  if (form.matchRole.trim()) match.role = form.matchRole.trim();
  if (form.matchModule.trim()) match.module = form.matchModule.trim();
  if (form.headerExists.trim()) {
    const names = form.headerExists
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
    if (names.length === 1) match.header_exists = names[0];
    else if (names.length > 1) match.header_exists = names;
  }
  return match;
}

function formToActions(form: RuleFormState): HttpAction[] {
  return form.actions
    .map((a) => {
      const op = a.op;
      const out: HttpAction = { op };
      if (
        [
          "header.add",
          "header.remove",
          "header.replace",
          "cookie.add",
          "cookie.remove",
          "cookie.replace",
          "query.add",
          "query.remove",
          "query.replace",
        ].includes(op)
      ) {
        if (a.name) out.name = String(a.name);
      }
      if (
        [
          "header.add",
          "header.replace",
          "cookie.add",
          "cookie.replace",
          "query.add",
          "query.replace",
          "url.host",
          "url.path",
          "method.replace",
          "body.append",
          "body.prepend",
        ].includes(op)
      ) {
        if (a.value !== undefined && a.value !== null) out.value = a.value as string;
      }
      if (op === "header.rename") {
        if (a.from) out.from = String(a.from);
        if (a.to) out.to = String(a.to);
      }
      if (op === "body.regex_replace") {
        if (a.pattern) out.pattern = String(a.pattern);
        out.replacement = a.replacement != null ? String(a.replacement) : "";
      }
      if (op === "status.override") {
        out.value = a.value != null ? Number(a.value) : 200;
      }
      if (op === "delay") {
        out.ms = a.ms != null ? Number(a.ms) : Number(a.value) || 0;
      }
      return out;
    })
    .filter((a) => a.op);
}

function validateForm(form: RuleFormState): string | null {
  if (!form.name.trim()) return "Name is required.";
  const actions = formToActions(form);
  if (actions.length === 0) return "Add at least one action.";
  for (const a of actions) {
    const op = a.op;
    if (
      [
        "header.add",
        "header.remove",
        "header.replace",
        "cookie.add",
        "cookie.remove",
        "cookie.replace",
        "query.add",
        "query.remove",
        "query.replace",
      ].includes(op) &&
      !a.name
    ) {
      return `Action ${op} requires a name.`;
    }
    if (
      [
        "header.add",
        "header.replace",
        "cookie.add",
        "cookie.replace",
        "query.add",
        "query.replace",
        "url.host",
        "url.path",
        "method.replace",
        "body.append",
        "body.prepend",
      ].includes(op) &&
      (a.value === undefined || a.value === null || a.value === "")
    ) {
      return `Action ${op} requires a value.`;
    }
    if (op === "header.rename" && (!a.from || !a.to)) {
      return "header.rename requires from and to.";
    }
    if (op === "body.regex_replace" && !a.pattern) {
      return "body.regex_replace requires a pattern.";
    }
    if (op === "delay" && (a.ms == null || Number(a.ms) < 0)) {
      return "delay requires ms ≥ 0.";
    }
  }
  return null;
}

function priorityLabel(n: number | undefined): string {
  const p = n ?? 100;
  const hit = PRIORITY_PRESETS.find((x) => x.value === p);
  return hit ? hit.label : String(p);
}

function directionBadgeClass(direction: string | undefined): string {
  const d = (direction || "request").toLowerCase();
  if (d === "response") return "badge-success text-success-content";
  if (d === "both") return "badge-secondary";
  return "badge-info";
}

function actionChipClass(op: string): string {
  if (op.startsWith("header.")) return "badge-info";
  if (op.startsWith("cookie.")) return "badge-warning";
  if (op.startsWith("query.") || op.startsWith("url.") || op === "method.replace")
    return "badge-accent";
  if (op.startsWith("body.")) return "badge-primary";
  if (op === "delay") return "badge-ghost";
  if (op === "drop" || op === "abort") return "badge-error";
  if (op === "status.override") return "badge-success";
  return "badge-ghost";
}

function actionSummaryLabel(a: HttpAction): string {
  const op = a.op || "";
  if (op === "header.replace") return `Replace ${a.name || "…"}`;
  if (op === "header.remove") return `Remove ${a.name || "…"}`;
  if (op === "header.add") return `Add ${a.name || "…"}`;
  if (op === "header.rename") return `Rename ${a.from || "…"}→${a.to || "…"}`;
  if (op === "cookie.replace") return `Cookie ${a.name || "…"}`;
  if (op === "cookie.remove") return `Cookie −${a.name || "…"}`;
  if (op === "delay") return `Delay ${a.ms ?? a.value ?? "?"}ms`;
  if (op === "drop") return "Drop";
  if (op === "abort") return "Abort";
  if (op === "status.override") return `Status ${a.value}`;
  if (op === "body.regex_replace") return "Regex replace";
  if (op === "url.host") return `Host → ${a.value}`;
  if (op === "url.path") return `Path → ${a.value}`;
  return op;
}

function matchSummary(match: Record<string, unknown> | undefined): string {
  if (!match || Object.keys(match).length === 0) return "All traffic";
  const parts: string[] = [];
  if (match.host != null) {
    const h = Array.isArray(match.host) ? match.host.join(", ") : String(match.host);
    parts.push(h);
  }
  if (match.path != null) {
    const p = Array.isArray(match.path) ? match.path.join(", ") : String(match.path);
    parts.push(p);
  } else if (!match.host) {
    parts.push("All paths");
  }
  if (match.method != null) {
    const m = Array.isArray(match.method) ? match.method.join(",") : String(match.method);
    parts.push(m.toUpperCase());
  }
  if (match.status_code != null) parts.push(`status ${match.status_code}`);
  return parts.join(" · ") || "All traffic";
}

function originLabel(rule: HttpRule): string {
  const src = (rule.source || rule.scope || "project").toLowerCase();
  if (src === "global" || src === "default") return "Global";
  return "Project";
}

function isGlobalRule(rule: HttpRule): boolean {
  return (rule.source || "").toLowerCase() === "global";
}

/** Default-layer rules are not stored in project/global YAML — not editable here. */
function isDefaultLayerRule(rule: HttpRule): boolean {
  return (rule.source || "").toLowerCase() === "default";
}

function isMutableRule(rule: HttpRule): boolean {
  return !isDefaultLayerRule(rule);
}

function moveItem<T>(list: T[], index: number, delta: number): T[] {
  const next = [...list];
  const target = index + delta;
  if (target < 0 || target >= next.length) return list;
  const [item] = next.splice(index, 1);
  next.splice(target, 0, item);
  return next;
}

// ---------------------------------------------------------------------------
// Subcomponents
// ---------------------------------------------------------------------------

function ActionChips({ actions }: { actions: HttpAction[] | undefined }) {
  if (!actions || actions.length === 0) {
    return <span className="text-base-content/40 text-xs">—</span>;
  }
  return (
    <div className="flex flex-wrap gap-1">
      {actions.map((a, i) => (
        <span key={i} className={`badge badge-sm ${actionChipClass(a.op)}`}>
          {actionSummaryLabel(a)}
        </span>
      ))}
    </div>
  );
}

function ActionEditor({
  actions,
  onChange,
}: {
  actions: HttpAction[];
  onChange: (next: HttpAction[]) => void;
}) {
  const update = (index: number, patch: Partial<HttpAction>) => {
    const next = actions.map((a, i) => (i === index ? { ...a, ...patch } : a));
    onChange(next);
  };

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <span className="text-sm font-medium">Actions</span>
        <button
          type="button"
          className="btn btn-xs"
          onClick={() =>
            onChange([...actions, { op: "header.replace", name: "", value: "" }])
          }
        >
          + Add action
        </button>
      </div>
      <p className="text-xs text-base-content/50">
        Actions run in order. Use ↑↓ to reorder.
      </p>
      {actions.map((action, index) => (
        <div
          key={index}
          className="rounded-md border border-base-300 bg-base-200/30 p-3 space-y-2"
        >
          <div className="flex items-center justify-between gap-2">
            <span className="text-xs font-medium text-base-content/60">{index + 1}.</span>
            <div className="flex gap-1">
              <button
                type="button"
                className="btn btn-xs btn-ghost"
                disabled={index === 0}
                onClick={() => onChange(moveItem(actions, index, -1))}
                aria-label="Move up"
              >
                ↑
              </button>
              <button
                type="button"
                className="btn btn-xs btn-ghost"
                disabled={index === actions.length - 1}
                onClick={() => onChange(moveItem(actions, index, 1))}
                aria-label="Move down"
              >
                ↓
              </button>
              <button
                type="button"
                className="btn btn-xs btn-ghost text-error"
                disabled={actions.length <= 1}
                onClick={() => onChange(actions.filter((_, i) => i !== index))}
              >
                Remove
              </button>
            </div>
          </div>
          <label className="form-control">
            <span className="label-text text-xs">Operation</span>
            <select
              className="select select-sm select-bordered"
              value={action.op}
              onChange={(e) => update(index, { op: e.target.value })}
            >
              {ACTION_CATEGORIES.map((cat) => (
                <optgroup key={cat.label} label={cat.label}>
                  {cat.ops.map((o) => (
                    <option key={o.op} value={o.op}>
                      {cat.label} · {o.label}
                    </option>
                  ))}
                </optgroup>
              ))}
            </select>
          </label>
          <ActionFields action={action} onChange={(patch) => update(index, patch)} />
        </div>
      ))}
    </div>
  );
}

function ActionFields({
  action,
  onChange,
}: {
  action: HttpAction;
  onChange: (patch: Partial<HttpAction>) => void;
}) {
  const op = action.op;
  if (op === "drop" || op === "abort") {
    return (
      <p className="text-xs text-base-content/50">
        No parameters — {op === "drop" ? "silently drops" : "aborts"} the message.
      </p>
    );
  }
  if (op === "delay") {
    return (
      <label className="form-control">
        <span className="label-text text-xs">
          Delay (ms)
          <FieldHint text="Milliseconds to sleep before continuing the pipeline." />
        </span>
        <input
          type="number"
          className="input input-sm input-bordered mono"
          min={0}
          value={action.ms ?? action.value ?? 0}
          onChange={(e) => onChange({ ms: Number(e.target.value) })}
        />
      </label>
    );
  }
  if (op === "header.rename") {
    return (
      <div className="grid grid-cols-2 gap-2">
        <label className="form-control">
          <span className="label-text text-xs">From</span>
          <input
            className="input input-sm input-bordered mono"
            value={String(action.from || "")}
            onChange={(e) => onChange({ from: e.target.value })}
          />
        </label>
        <label className="form-control">
          <span className="label-text text-xs">To</span>
          <input
            className="input input-sm input-bordered mono"
            value={String(action.to || "")}
            onChange={(e) => onChange({ to: e.target.value })}
          />
        </label>
      </div>
    );
  }
  if (op === "body.regex_replace") {
    return (
      <div className="space-y-2">
        <label className="form-control">
          <span className="label-text text-xs">Pattern (regex)</span>
          <input
            className="input input-sm input-bordered mono"
            value={String(action.pattern || "")}
            onChange={(e) => onChange({ pattern: e.target.value })}
          />
        </label>
        <label className="form-control">
          <span className="label-text text-xs">Replacement</span>
          <input
            className="input input-sm input-bordered mono"
            value={String(action.replacement ?? "")}
            onChange={(e) => onChange({ replacement: e.target.value })}
          />
        </label>
      </div>
    );
  }
  if (
    ["url.host", "url.path", "method.replace", "body.append", "body.prepend", "status.override"].includes(
      op
    )
  ) {
    return (
      <label className="form-control">
        <span className="label-text text-xs">
          {op === "status.override" ? "Status code" : "Value"}
        </span>
        <input
          className="input input-sm input-bordered mono"
          value={String(action.value ?? "")}
          onChange={(e) => onChange({ value: e.target.value })}
        />
      </label>
    );
  }
  // name + optional value for header/cookie/query
  const needsValue = ![
    "header.remove",
    "cookie.remove",
    "query.remove",
  ].includes(op);
  return (
    <div className="grid grid-cols-1 gap-2">
      <label className="form-control">
        <span className="label-text text-xs">
          {op.startsWith("cookie") ? "Cookie name" : op.startsWith("query") ? "Param" : "Header"}
        </span>
        <input
          className="input input-sm input-bordered mono"
          value={String(action.name || "")}
          onChange={(e) => onChange({ name: e.target.value })}
          placeholder={op.startsWith("header") ? "X-Test" : "name"}
        />
      </label>
      {needsValue && (
        <label className="form-control">
          <span className="label-text text-xs">Value</span>
          <input
            className="input input-sm input-bordered mono"
            value={String(action.value ?? "")}
            onChange={(e) => onChange({ value: e.target.value })}
          />
        </label>
      )}
    </div>
  );
}

function RulePreview({ form }: { form: RuleFormState }) {
  const match = formToMatch(form);
  const actions = formToActions(form);
  return (
    <div className="rounded-md border border-base-300 bg-base-200/40 p-3 text-xs space-y-2">
      <div className="font-medium text-sm">Preview</div>
      <div>
        <span className="text-base-content/50">Matches</span>
        <div className="mono mt-0.5">
          Host: {String(match.host || "any")}
          <br />
          Path: {String(match.path || "any")}
          {match.method ? (
            <>
              <br />
              Method: {String(match.method)}
            </>
          ) : null}
        </div>
      </div>
      <div>
        <span className="text-base-content/50">Actions</span>
        <ul className="mt-0.5 space-y-0.5">
          {actions.map((a, i) => (
            <li key={i} className="mono">
              {actionSummaryLabel(a)}
              {a.value != null && a.op?.includes("replace") ? (
                <span className="text-base-content/50"> → {String(a.value)}</span>
              ) : null}
            </li>
          ))}
        </ul>
      </div>
      <div className="text-base-content/50">
        Stored in{" "}
        <span className="mono text-base-content/70">
          {form.globalScope ? "~/.talos/config.yaml" : "project.yaml"}
        </span>
        {" · "}
        Priority {priorityLabel(form.priority)} ({form.priority}) · {form.direction}
      </div>
    </div>
  );
}

function RuleFormFields({
  form,
  onChange,
  allowScopeChange,
}: {
  form: RuleFormState;
  onChange: (next: RuleFormState) => void;
  allowScopeChange: boolean;
}) {
  const set = <K extends keyof RuleFormState>(key: K, value: RuleFormState[K]) =>
    onChange({ ...form, [key]: value });

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        <label className="form-control sm:col-span-2">
          <span className="label-text text-xs">Name</span>
          <input
            className="input input-sm input-bordered"
            value={form.name}
            onChange={(e) => set("name", e.target.value)}
            placeholder="Strip Validators"
          />
        </label>
        <label className="form-control">
          <span className="label-text text-xs">Enabled</span>
          <input
            type="checkbox"
            className="toggle toggle-sm toggle-success mt-1"
            checked={form.enabled}
            onChange={(e) => set("enabled", e.target.checked)}
          />
        </label>
        <label className="form-control">
          <span className="label-text text-xs">Direction</span>
          <select
            className="select select-sm select-bordered"
            value={form.direction}
            onChange={(e) =>
              set("direction", e.target.value as RuleFormState["direction"])
            }
          >
            <option value="request">Request</option>
            <option value="response">Response</option>
            <option value="both">Both</option>
          </select>
        </label>
        <label className="form-control">
          <span className="label-text text-xs">
            Priority
            <FieldHint text="Lower number runs first. Presets map to 10–100." />
          </span>
          {form.priorityAdvanced ? (
            <input
              type="number"
              className="input input-sm input-bordered mono"
              value={form.priority}
              onChange={(e) => set("priority", Number(e.target.value))}
            />
          ) : (
            <select
              className="select select-sm select-bordered"
              value={form.priority}
              onChange={(e) => set("priority", Number(e.target.value))}
            >
              {PRIORITY_PRESETS.map((p) => (
                <option key={p.value} value={p.value}>
                  {p.label} ({p.value})
                </option>
              ))}
            </select>
          )}
          <button
            type="button"
            className="link link-primary text-[11px] mt-0.5 self-start"
            onClick={() => set("priorityAdvanced", !form.priorityAdvanced)}
          >
            {form.priorityAdvanced ? "Use presets" : "Advanced (numeric)"}
          </button>
        </label>
        <div className="form-control">
          <span className="label-text text-xs mb-1">
            Scope
            <FieldHint text="Project rules live in project.yaml; global in ~/.talos/config.yaml." />
          </span>
          <div className="flex flex-col gap-1 text-sm">
            <label className="flex items-center gap-2 cursor-pointer">
              <input
                type="radio"
                className="radio radio-xs"
                name="rule-scope"
                checked={!form.globalScope}
                disabled={!allowScopeChange && form.globalScope}
                onChange={() => set("globalScope", false)}
              />
              Project
            </label>
            <label className="flex items-center gap-2 cursor-pointer">
              <input
                type="radio"
                className="radio radio-xs"
                name="rule-scope"
                checked={form.globalScope}
                disabled={!allowScopeChange && !form.globalScope}
                onChange={() => set("globalScope", true)}
              />
              Global
            </label>
            <span className="text-[11px] text-base-content/50 mono">
              Stored in {form.globalScope ? "~/.talos/config.yaml" : "project.yaml"}
            </span>
          </div>
        </div>
      </div>

      <div className="divider my-1 text-xs text-base-content/40">Match conditions</div>
      <p className="text-xs text-base-content/50 -mt-2">
        Empty fields mean “any”. Host accepts exact, suffix, or glob (
        <span className="mono">*.example.com</span>). Path accepts globs (
        <span className="mono">/v1/*</span>).
      </p>
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
        <label className="form-control">
          <span className="label-text text-xs">Host</span>
          <input
            className="input input-sm input-bordered mono"
            value={form.matchHost}
            onChange={(e) => set("matchHost", e.target.value)}
            placeholder="api.example.com"
          />
        </label>
        <label className="form-control">
          <span className="label-text text-xs">Path</span>
          <input
            className="input input-sm input-bordered mono"
            value={form.matchPath}
            onChange={(e) => set("matchPath", e.target.value)}
            placeholder="/v1/*"
          />
        </label>
        <label className="form-control">
          <span className="label-text text-xs">Method</span>
          <select
            className="select select-sm select-bordered"
            value={form.matchMethod}
            onChange={(e) => set("matchMethod", e.target.value)}
          >
            <option value="">Any</option>
            {METHODS.filter(Boolean).map((m) => (
              <option key={m} value={m}>
                {m}
              </option>
            ))}
          </select>
        </label>
        <label className="form-control">
          <span className="label-text text-xs">Status (response)</span>
          <input
            className="input input-sm input-bordered mono"
            value={form.matchStatus}
            onChange={(e) => set("matchStatus", e.target.value)}
            placeholder="Any"
          />
        </label>
        <label className="form-control">
          <span className="label-text text-xs">Endpoint ID</span>
          <input
            className="input input-sm input-bordered mono"
            value={form.matchEndpoint}
            onChange={(e) => set("matchEndpoint", e.target.value)}
            placeholder="Optional"
          />
        </label>
        <label className="form-control">
          <span className="label-text text-xs">Header exists</span>
          <input
            className="input input-sm input-bordered mono"
            value={form.headerExists}
            onChange={(e) => set("headerExists", e.target.value)}
            placeholder="Authorization (comma-separated)"
          />
        </label>
        <label className="form-control">
          <span className="label-text text-xs">Role</span>
          <input
            className="input input-sm input-bordered"
            value={form.matchRole}
            onChange={(e) => set("matchRole", e.target.value)}
            placeholder="Optional"
          />
        </label>
        <label className="form-control">
          <span className="label-text text-xs">Module</span>
          <input
            className="input input-sm input-bordered"
            value={form.matchModule}
            onChange={(e) => set("matchModule", e.target.value)}
            placeholder="Optional"
          />
        </label>
      </div>

      <div className="divider my-1 text-xs text-base-content/40">Actions</div>
      <ActionEditor
        actions={form.actions}
        onChange={(actions) => onChange({ ...form, actions })}
      />

      <RulePreview form={form} />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export default function Mutations() {
  const { selected } = useProject();
  const [rules, setRules] = useState<HttpRule[]>([]);
  const [summary, setSummary] = useState<Summary | null>(null);
  const [engineOn, setEngineOn] = useState<boolean | null>(null);
  const [loading, setLoading] = useState(false);

  // Filters
  const [filterDirection, setFilterDirection] = useState("all");
  const [filterScope, setFilterScope] = useState("all");
  const [filterHost, setFilterHost] = useState("");
  const [filterSearch, setFilterSearch] = useState("");

  // Drawers / modals
  const [selectedRule, setSelectedRule] = useState<HttpRule | null>(null);
  const [editing, setEditing] = useState(false);
  const [creating, setCreating] = useState(false);
  const [form, setForm] = useState<RuleFormState>(emptyForm());
  const [formError, setFormError] = useState<string | null>(null);
  const [importOpen, setImportOpen] = useState(false);
  const [importText, setImportText] = useState("");
  const [importReplace, setImportReplace] = useState(false);
  const [templateMenu, setTemplateMenu] = useState(false);
  const templateRef = useRef<HTMLDivElement>(null);

  const load = useCallback(() => {
    if (!selected) return;
    setLoading(true);
    api
      .get<{
        enabled: boolean;
        rules: HttpRule[];
        mutations?: HttpRule[];
        summary?: Summary;
      }>("/api/mutations", { project_id: selected.id })
      .then((r) => {
        const list = r.rules || r.mutations || [];
        setRules(list);
        setEngineOn(r.enabled !== false);
        setSummary(
          r.summary || {
            active: list.filter((x) => x.enabled !== false).length,
            request: 0,
            response: 0,
            disabled: list.filter((x) => x.enabled === false).length,
            total: list.length,
          }
        );
      })
      .catch(() => {
        setRules([]);
        setEngineOn(null);
        setSummary(null);
      })
      .finally(() => setLoading(false));
  }, [selected]);

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    if (!selectedRule) return;
    const fresh = rules.find((r) => r.id === selectedRule.id);
    if (fresh) setSelectedRule(fresh);
  }, [rules]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    const onDoc = (e: MouseEvent) => {
      if (templateRef.current && !templateRef.current.contains(e.target as Node)) {
        setTemplateMenu(false);
      }
    };
    document.addEventListener("mousedown", onDoc);
    return () => document.removeEventListener("mousedown", onDoc);
  }, []);

  const filtered = useMemo(() => {
    return rules.filter((rule) => {
      const dir = (rule.direction || "request").toLowerCase();
      if (filterDirection !== "all") {
        if (filterDirection === "request" && dir !== "request" && dir !== "both")
          return false;
        if (filterDirection === "response" && dir !== "response" && dir !== "both")
          return false;
        if (filterDirection === "both" && dir !== "both") return false;
      }
      if (filterScope !== "all") {
        const origin = originLabel(rule).toLowerCase();
        if (filterScope === "project" && origin !== "project") return false;
        if (filterScope === "global" && origin !== "global") return false;
      }
      if (filterHost.trim()) {
        const host = String(
          Array.isArray(rule.match?.host) ? rule.match?.host[0] : rule.match?.host || ""
        ).toLowerCase();
        if (!host.includes(filterHost.trim().toLowerCase())) return false;
      }
      if (filterSearch.trim()) {
        const q = filterSearch.trim().toLowerCase();
        const hay = `${rule.name} ${rule.id} ${JSON.stringify(rule.actions || [])} ${JSON.stringify(rule.match || [])}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  }, [rules, filterDirection, filterScope, filterHost, filterSearch]);

  const toggleEngine = useAction("Toggle HTTP engine", (enabled: boolean) =>
    api.post("/api/mutations/engine", { enabled }, { project_id: selected!.id })
  );

  const createRule = useAction("Create HTTP rule", () => {
    const match = formToMatch(form);
    const actions = formToActions(form);
    return api.post(
      "/api/mutations",
      {
        name: form.name.trim(),
        direction: form.direction,
        priority: form.priority,
        description: form.description,
        enabled: form.enabled,
        global_scope: form.globalScope,
        match,
        actions,
      },
      { project_id: selected!.id }
    );
  });

  const updateRule = useAction("Update HTTP rule", () => {
    const match = formToMatch(form);
    const actions = formToActions(form);
    return api.post(
      `/api/mutations/${selectedRule!.id}/update`,
      {
        name: form.name.trim(),
        direction: form.direction,
        priority: form.priority,
        description: form.description,
        enabled: form.enabled,
        match,
        actions,
        global_scope: isGlobalRule(selectedRule!),
      },
      { project_id: selected!.id }
    );
  });

  const removeRule = useAction("Delete HTTP rule", (rule: HttpRule) =>
    api
      .del(`/api/mutations/${rule.id}`, {
        project_id: selected!.id,
        global_scope: isGlobalRule(rule) ? true : undefined,
      })
      .then((r) => ({ steps: r.steps || [r] }))
  );

  const enableRule = useAction("Enable HTTP rule", (rule: HttpRule) =>
    api.post(
      `/api/mutations/${rule.id}/enable`,
      {},
      {
        project_id: selected!.id,
        global_scope: isGlobalRule(rule) ? true : undefined,
      }
    )
  );

  const disableRule = useAction("Disable HTTP rule", (rule: HttpRule) =>
    api.post(
      `/api/mutations/${rule.id}/disable`,
      {},
      {
        project_id: selected!.id,
        global_scope: isGlobalRule(rule) ? true : undefined,
      }
    )
  );

  const duplicateRule = useAction("Duplicate HTTP rule", (rule: HttpRule) =>
    api.post(
      `/api/mutations/${rule.id}/duplicate`,
      {},
      {
        project_id: selected!.id,
        global_scope: isGlobalRule(rule) ? true : undefined,
      }
    )
  );

  const reorderRules = useAction("Reorder HTTP rules", () =>
    api.post("/api/mutations/reorder", { global_scope: false }, { project_id: selected!.id })
  );

  const [exporting, setExporting] = useState(false);

  const importRules = useAction("Import HTTP rules", () => {
    let content: unknown = importText;
    try {
      content = JSON.parse(importText);
    } catch {
      // raw string — backend accepts string too
    }
    return api.post(
      "/api/mutations/import",
      { content, replace: importReplace, global_scope: false },
      { project_id: selected!.id }
    );
  });

  const openCreate = (template?: (typeof RULE_TEMPLATES)[number]) => {
    const base = emptyForm();
    if (template) {
      Object.assign(base, template.form);
      base.actions = template.form.actions.map((a) => ({ ...a }));
    }
    setForm(base);
    setFormError(null);
    setCreating(true);
    setEditing(false);
    setSelectedRule(null);
    setTemplateMenu(false);
  };

  const openEdit = (rule: HttpRule) => {
    setSelectedRule(rule);
    setForm(ruleToForm(rule));
    setFormError(null);
    setEditing(true);
    setCreating(false);
  };

  const openDetails = (rule: HttpRule) => {
    setSelectedRule(rule);
    setEditing(false);
    setCreating(false);
  };

  const saveCreate = async () => {
    const err = validateForm(form);
    if (err) {
      setFormError(err);
      return;
    }
    setFormError(null);
    try {
      const result = (await createRule.run()) as { error?: string; steps?: unknown[] };
      if (result?.error) {
        setFormError(result.error);
        return;
      }
      setCreating(false);
      await load();
    } catch {
      // useAction already logged failure
    }
  };

  const saveEdit = async () => {
    const err = validateForm(form);
    if (err) {
      setFormError(err);
      return;
    }
    setFormError(null);
    try {
      const result = (await updateRule.run()) as { error?: string; steps?: unknown[] };
      if (result?.error) {
        setFormError(result.error);
        return;
      }
      setEditing(false);
      await load();
    } catch {
      // useAction already logged failure
    }
  };

  const doExport = async () => {
    if (!selected) return;
    setExporting(true);
    try {
      const r = await api.get<{ payload: unknown; steps?: unknown[] }>(
        "/api/mutations/export",
        { project_id: selected.id, layer: "effective" }
      );
      if (!r?.payload) return;
      const blob = new Blob([JSON.stringify(r.payload, null, 2)], {
        type: "application/json",
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `talos-http-rules-${selected.id}.json`;
      a.click();
      URL.revokeObjectURL(url);
    } finally {
      setExporting(false);
    }
  };

  if (!selected) return <NoProjectNotice />;

  return (
    <div>
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-3 mb-3">
        <h1 className="text-xl font-semibold">HTTP Rules</h1>
        <div className="flex items-center gap-3">
          <span className="text-sm text-base-content/60">Engine</span>
          <span
            className={`badge badge-sm ${
              engineOn == null ? "badge-ghost" : engineOn ? "badge-success" : "badge-error"
            }`}
          >
            {engineOn == null ? "…" : engineOn ? "ON" : "OFF"}
          </span>
          <input
            type="checkbox"
            className="toggle toggle-sm toggle-success"
            checked={!!engineOn}
            disabled={engineOn == null || toggleEngine.running}
            onChange={async (e) => {
              await toggleEngine.run(e.target.checked);
              await load();
            }}
            aria-label="Master switch for the HTTP Manipulation Engine (http.enabled)"
          />
        </div>
      </div>

      <div className="mb-4">
        <ModuleHelp title="How HTTP Rules work">
          <p>
            HTTP Rules are Talos&apos; traffic pipeline: every proxied request and
            response passes through the HTTP Manipulation Engine before capture.
            Rules are declarative match + ordered actions (header/cookie/query/body,
            delay, drop).
          </p>
          <p>
            Rules are layered configuration — project rules in{" "}
            <span className="mono">project.yaml</span>, global rules in{" "}
            <span className="mono">~/.talos/config.yaml</span>. Lower priority numbers
            run first. Empty match conditions apply to all traffic for that direction.
          </p>
          <p>
            Example: strip cache validators so you always see full responses — match
            host <span className="mono">*.example.com</span>, remove{" "}
            <span className="mono">If-None-Match</span> and{" "}
            <span className="mono">If-Modified-Since</span>.
          </p>
          <p>
            CLI parity: <span className="mono">talos config http</span>. Also see{" "}
            <Link className="link link-primary" to="/talos-config?tab=settings&section=http">
              Talos Config → HTTP
            </Link>{" "}
            and the compact status card on the{" "}
            <Link className="link link-primary" to="/proxy">
              Proxy
            </Link>{" "}
            page.
          </p>
        </ModuleHelp>
      </div>

      {/* Global summary */}
      <div className="panel p-3 mb-4">
        <div className="text-xs uppercase tracking-wide text-base-content/50 mb-2">
          Global summary
        </div>
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-sm">
          <div>
            <div className="text-base-content/50 text-xs">Active rules</div>
            <div className="text-lg font-semibold">{summary?.active ?? "—"}</div>
          </div>
          <div>
            <div className="text-base-content/50 text-xs">Request rules</div>
            <div className="text-lg font-semibold text-info">{summary?.request ?? "—"}</div>
          </div>
          <div>
            <div className="text-base-content/50 text-xs">Response rules</div>
            <div className="text-lg font-semibold text-success">
              {summary?.response ?? "—"}
            </div>
          </div>
          <div>
            <div className="text-base-content/50 text-xs">Disabled rules</div>
            <div className="text-lg font-semibold text-base-content/50">
              {summary?.disabled ?? "—"}
            </div>
          </div>
        </div>
        {!engineOn && engineOn !== null && (
          <p className="text-xs text-warning mt-2">
            Engine is OFF — rules are stored but not applied to traffic.
          </p>
        )}
      </div>

      {/* Toolbar */}
      <div className="flex flex-wrap items-center gap-2 mb-3">
        <div className="relative" ref={templateRef}>
          <div className="join">
            <button className="btn btn-sm btn-primary join-item" onClick={() => openCreate()}>
              + New Rule
            </button>
            <button
              className="btn btn-sm btn-primary join-item px-2"
              onClick={() => setTemplateMenu((v) => !v)}
              aria-label="Rule templates"
            >
              ▾
            </button>
          </div>
          {templateMenu && (
            <div className="absolute z-20 mt-1 w-72 panel p-1 shadow-lg">
              <div className="text-[11px] uppercase text-base-content/40 px-2 py-1">
                Templates
              </div>
              {RULE_TEMPLATES.map((t) => (
                <button
                  key={t.id}
                  type="button"
                  className="w-full text-left px-2 py-1.5 rounded hover:bg-base-200 text-sm"
                  onClick={() => openCreate(t)}
                >
                  <div className="font-medium">{t.label}</div>
                  <div className="text-[11px] text-base-content/50">{t.description}</div>
                </button>
              ))}
            </div>
          )}
        </div>
        <button className="btn btn-sm" disabled={exporting} onClick={() => void doExport()}>
          {exporting ? <span className="loading loading-spinner loading-xs" /> : "Export"}
        </button>
        <button className="btn btn-sm" onClick={() => setImportOpen(true)}>
          Import
        </button>
        <button
          className="btn btn-sm"
          disabled={reorderRules.running || rules.length === 0}
          onClick={async () => {
            await reorderRules.run();
            await load();
          }}
        >
          Reorder
        </button>
        {loading && <span className="loading loading-spinner loading-xs ml-2" />}
      </div>

      {/* Filters */}
      <div className="panel p-3 mb-4">
        <div className="text-xs uppercase tracking-wide text-base-content/50 mb-2">
          Filters
        </div>
        <div className="flex flex-wrap gap-2 items-end">
          <label className="form-control">
            <span className="label-text text-xs">Direction</span>
            <select
              className="select select-sm select-bordered"
              value={filterDirection}
              onChange={(e) => setFilterDirection(e.target.value)}
            >
              <option value="all">All</option>
              <option value="request">Request</option>
              <option value="response">Response</option>
              <option value="both">Both</option>
            </select>
          </label>
          <label className="form-control">
            <span className="label-text text-xs">Scope</span>
            <select
              className="select select-sm select-bordered"
              value={filterScope}
              onChange={(e) => setFilterScope(e.target.value)}
            >
              <option value="all">All</option>
              <option value="project">Project</option>
              <option value="global">Global</option>
            </select>
          </label>
          <label className="form-control">
            <span className="label-text text-xs">Host</span>
            <input
              className="input input-sm input-bordered mono w-40"
              value={filterHost}
              onChange={(e) => setFilterHost(e.target.value)}
              placeholder="example.com"
            />
          </label>
          <label className="form-control flex-1 min-w-[12rem]">
            <span className="label-text text-xs">Search</span>
            <input
              className="input input-sm input-bordered w-full"
              value={filterSearch}
              onChange={(e) => setFilterSearch(e.target.value)}
              placeholder="Name, action, id…"
            />
          </label>
        </div>
      </div>

      {/* Rule table */}
      <div className="panel overflow-x-auto">
        <table className="table table-sm">
          <thead>
            <tr className="text-xs text-base-content/50">
              <th>Priority</th>
              <th>Enabled</th>
              <th>Name</th>
              <th>Direction</th>
              <th>Match</th>
              <th>Actions</th>
              <th>Scope</th>
              <th>Origin</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 && (
              <tr>
                <td colSpan={9} className="text-center text-sm text-base-content/50 py-8">
                  {rules.length === 0
                    ? "No HTTP rules configured. Traffic is not modified."
                    : "No rules match the current filters."}
                </td>
              </tr>
            )}
            {filtered.map((rule) => {
              const enabled = rule.enabled !== false;
              return (
                <tr
                  key={rule.id}
                  className="hover:bg-base-200/50 cursor-pointer"
                  onClick={() => openDetails(rule)}
                >
                  <td className="mono text-xs whitespace-nowrap">
                    {rule.priority ?? 100}
                    <span className="text-base-content/40 ml-1">
                      {priorityLabel(rule.priority)}
                    </span>
                  </td>
                  <td onClick={(e) => e.stopPropagation()}>
                    <input
                      type="checkbox"
                      className="toggle toggle-xs toggle-success"
                      checked={enabled}
                      disabled={
                        enableRule.running ||
                        disableRule.running ||
                        !isMutableRule(rule)
                      }
                      onChange={async () => {
                        if (enabled) await disableRule.run(rule);
                        else await enableRule.run(rule);
                        await load();
                      }}
                    />
                  </td>
                  <td>
                    <div className="font-medium text-sm">{rule.name}</div>
                    <div className="text-[10px] mono text-base-content/40">
                      {rule.id.slice(0, 8)}
                    </div>
                  </td>
                  <td>
                    <span
                      className={`badge badge-sm capitalize ${directionBadgeClass(
                        rule.direction
                      )}`}
                    >
                      {rule.direction || "request"}
                    </span>
                  </td>
                  <td className="text-xs max-w-[10rem] truncate">
                    {matchSummary(rule.match)}
                  </td>
                  <td className="max-w-[14rem]">
                    <ActionChips actions={rule.actions} />
                  </td>
                  <td className="text-xs capitalize">{rule.scope || originLabel(rule)}</td>
                  <td>
                    <span className="badge badge-sm badge-outline">{originLabel(rule)}</span>
                  </td>
                  <td onClick={(e) => e.stopPropagation()}>
                    <div className="flex gap-1 flex-wrap justify-end">
                      <button
                        className="btn btn-xs"
                        disabled={!isMutableRule(rule)}
                        onClick={() => openEdit(rule)}
                      >
                        Edit
                      </button>
                      <button
                        className="btn btn-xs"
                        disabled={duplicateRule.running || !isMutableRule(rule)}
                        onClick={async () => {
                          await duplicateRule.run(rule);
                          await load();
                        }}
                      >
                        Duplicate
                      </button>
                      <ConfirmButton
                        className="btn btn-xs btn-error"
                        confirmText="Delete this rule?"
                        onConfirm={async () => {
                          if (!isMutableRule(rule)) return;
                          await removeRule.run(rule);
                          if (selectedRule?.id === rule.id) setSelectedRule(null);
                          await load();
                        }}
                      >
                        Delete
                      </ConfirmButton>
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {/* Details drawer (view) */}
      <SideDrawer
        open={!!selectedRule && !editing && !creating}
        onClose={() => setSelectedRule(null)}
        title={selectedRule?.name || "Rule"}
        wide
      >
        {selectedRule && (
          <div className="space-y-4 text-sm">
            <div className="flex flex-wrap gap-2 items-center">
              <span
                className={`badge badge-sm ${
                  selectedRule.enabled !== false ? "badge-success" : "badge-ghost"
                }`}
              >
                {selectedRule.enabled !== false ? "Enabled" : "Disabled"}
              </span>
              <span
                className={`badge badge-sm capitalize ${directionBadgeClass(
                  selectedRule.direction
                )}`}
              >
                {selectedRule.direction || "request"}
              </span>
              <span className="badge badge-sm badge-outline">
                {originLabel(selectedRule)}
              </span>
              <span className="badge badge-sm badge-ghost">
                prio {selectedRule.priority ?? 100} ({priorityLabel(selectedRule.priority)})
              </span>
            </div>
            <dl className="grid grid-cols-[6rem_1fr] gap-y-1.5 text-sm">
              <dt className="text-base-content/50">ID</dt>
              <dd className="mono text-xs break-all">{selectedRule.id}</dd>
              <dt className="text-base-content/50">Scope</dt>
              <dd>
                {originLabel(selectedRule)} — stored in{" "}
                <span className="mono text-xs">
                  {isGlobalRule(selectedRule) ? "~/.talos/config.yaml" : "project.yaml"}
                </span>
              </dd>
            </dl>

            <div>
              <div className="text-xs uppercase tracking-wide text-base-content/50 mb-1">
                Match conditions
              </div>
              {selectedRule.match && Object.keys(selectedRule.match).length > 0 ? (
                <dl className="grid grid-cols-[6rem_1fr] gap-y-1 text-xs">
                  {Object.entries(selectedRule.match).map(([k, v]) => (
                    <div key={k} className="contents">
                      <dt className="text-base-content/50 capitalize">{k.replace(/_/g, " ")}</dt>
                      <dd className="mono">{JSON.stringify(v)}</dd>
                    </div>
                  ))}
                </dl>
              ) : (
                <p className="text-xs text-base-content/50">
                  No match conditions — applies to all traffic for this direction.
                </p>
              )}
            </div>

            <div>
              <div className="text-xs uppercase tracking-wide text-base-content/50 mb-2">
                Actions
              </div>
              <div className="space-y-2">
                {(selectedRule.actions || []).map((a, i) => (
                  <div
                    key={i}
                    className="rounded border border-base-300 p-2 flex items-start gap-2"
                  >
                    <span className="text-base-content/40 text-xs w-4">{i + 1}.</span>
                    <div>
                      <span className={`badge badge-sm ${actionChipClass(a.op)}`}>
                        {a.op}
                      </span>
                      <div className="mono text-xs mt-1 text-base-content/70">
                        {actionSummaryLabel(a)}
                        {a.value != null && !String(a.op).includes("remove")
                          ? ` = ${JSON.stringify(a.value)}`
                          : ""}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <div>
              <div className="text-xs uppercase tracking-wide text-base-content/50 mb-1">
                Statistics
              </div>
              <p className="text-xs text-base-content/50">
                Match counters are not exposed by the proxy yet. When available: last
                matched, matches today, last modified.
              </p>
              <dl className="grid grid-cols-[7rem_1fr] gap-y-1 text-xs mt-2">
                <dt className="text-base-content/50">Last matched</dt>
                <dd>—</dd>
                <dt className="text-base-content/50">Matches today</dt>
                <dd>—</dd>
                <dt className="text-base-content/50">Created by</dt>
                <dd>{originLabel(selectedRule)}</dd>
              </dl>
            </div>

            <div className="flex flex-wrap gap-2 pt-2 border-t border-base-300">
              <button
                className="btn btn-sm btn-primary"
                disabled={!isMutableRule(selectedRule)}
                onClick={() => openEdit(selectedRule)}
              >
                Edit
              </button>
              <button
                className="btn btn-sm"
                disabled={duplicateRule.running || !isMutableRule(selectedRule)}
                onClick={async () => {
                  await duplicateRule.run(selectedRule);
                  await load();
                }}
              >
                Duplicate
              </button>
              {selectedRule.enabled !== false ? (
                <button
                  className="btn btn-sm"
                  disabled={disableRule.running || !isMutableRule(selectedRule)}
                  onClick={async () => {
                    await disableRule.run(selectedRule);
                    await load();
                  }}
                >
                  Disable
                </button>
              ) : (
                <button
                  className="btn btn-sm"
                  disabled={enableRule.running || !isMutableRule(selectedRule)}
                  onClick={async () => {
                    await enableRule.run(selectedRule);
                    await load();
                  }}
                >
                  Enable
                </button>
              )}
              <ConfirmButton
                className="btn btn-sm btn-error"
                confirmText="Delete this rule?"
                onConfirm={async () => {
                  if (!isMutableRule(selectedRule)) return;
                  await removeRule.run(selectedRule);
                  setSelectedRule(null);
                  await load();
                }}
              >
                Delete
              </ConfirmButton>
            </div>
            {isDefaultLayerRule(selectedRule) && (
              <p className="text-xs text-warning">
                This rule comes from the default layer and cannot be changed here.
              </p>
            )}
          </div>
        )}
      </SideDrawer>

      {/* Create modal */}
      <Modal
        open={creating}
        onClose={() => setCreating(false)}
        title="New HTTP Rule"
        wide
      >
        <RuleFormFields form={form} onChange={setForm} allowScopeChange />
        {formError && (
          <div className="alert alert-error text-xs mt-3 py-2">{formError}</div>
        )}
        <div className="flex justify-end gap-2 mt-4">
          <button className="btn btn-sm" onClick={() => setCreating(false)}>
            Cancel
          </button>
          <button
            className="btn btn-sm btn-primary"
            disabled={createRule.running}
            onClick={() => void saveCreate()}
          >
            {createRule.running ? (
              <span className="loading loading-spinner loading-xs" />
            ) : (
              "Create rule"
            )}
          </button>
        </div>
      </Modal>

      {/* Edit drawer */}
      <SideDrawer
        open={editing && !!selectedRule}
        onClose={() => setEditing(false)}
        title={`Edit · ${selectedRule?.name || "Rule"}`}
        wide
      >
        <RuleFormFields form={form} onChange={setForm} allowScopeChange={false} />
        {formError && (
          <div className="alert alert-error text-xs mt-3 py-2">{formError}</div>
        )}
        <div className="flex justify-end gap-2 mt-4 sticky bottom-0 bg-base-100 py-2">
          <button className="btn btn-sm" onClick={() => setEditing(false)}>
            Cancel
          </button>
          <button
            className="btn btn-sm btn-primary"
            disabled={updateRule.running}
            onClick={() => void saveEdit()}
          >
            {updateRule.running ? (
              <span className="loading loading-spinner loading-xs" />
            ) : (
              "Save changes"
            )}
          </button>
        </div>
      </SideDrawer>

      {/* Import modal */}
      <Modal open={importOpen} onClose={() => setImportOpen(false)} title="Import HTTP Rules" wide>
        <p className="text-xs text-base-content/50 mb-2">
          Paste JSON from Export (or CLI). Shape: list of rules,{" "}
          <span className="mono">{"{ rules: [...] }"}</span>, or{" "}
          <span className="mono">{"{ http: { rules: [...] } }"}</span>.
        </p>
        <textarea
          className="textarea textarea-bordered mono text-xs w-full h-48"
          value={importText}
          onChange={(e) => setImportText(e.target.value)}
          placeholder='{"http":{"rules":[...]}}'
        />
        <label className="flex items-center gap-2 mt-2 text-sm cursor-pointer">
          <input
            type="checkbox"
            className="checkbox checkbox-sm"
            checked={importReplace}
            onChange={(e) => setImportReplace(e.target.checked)}
          />
          Replace all project-layer rules (destructive)
        </label>
        <div className="flex justify-end gap-2 mt-4">
          <button className="btn btn-sm" onClick={() => setImportOpen(false)}>
            Cancel
          </button>
          <button
            className="btn btn-sm btn-primary"
            disabled={!importText.trim() || importRules.running}
            onClick={async () => {
              await importRules.run();
              setImportOpen(false);
              setImportText("");
              await load();
            }}
          >
            {importRules.running ? (
              <span className="loading loading-spinner loading-xs" />
            ) : (
              "Import"
            )}
          </button>
        </div>
      </Modal>
    </div>
  );
}
