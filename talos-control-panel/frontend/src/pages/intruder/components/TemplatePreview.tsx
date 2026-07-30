import type { ReactNode } from "react";
import type { IntruderTemplate, TemplateVariable } from "../types";

function highlightVars(text: string, vars: TemplateVariable[]): ReactNode {
  if (!text) return <span className="text-base-content/40">—</span>;
  // Highlight {{name}} tokens
  const parts = text.split(/(\{\{[A-Za-z0-9_]+\}\})/g);
  return parts.map((p, i) => {
    const m = p.match(/^\{\{([A-Za-z0-9_]+)\}\}$/);
    if (m) {
      const known = vars.some((v) => v.name === m[1]);
      return (
        <span
          key={i}
          className={
            known
              ? "bg-primary/20 text-primary px-0.5 rounded"
              : "bg-warning/20 text-warning px-0.5 rounded"
          }
        >
          {p}
        </span>
      );
    }
    return <span key={i}>{p}</span>;
  });
}

export default function TemplatePreview({
  template,
}: {
  template: IntruderTemplate | undefined;
}) {
  const t = template || {};
  const vars = t.variables || [];
  const headers = t.headers || {};
  const method = t.method || "GET";
  const url = t.url || "";

  return (
    <div className="rounded-md border border-base-300 bg-base-200/30 overflow-hidden">
      <div className="px-3 py-1.5 border-b border-base-300 text-xs font-medium text-base-content/60 flex justify-between">
        <span>Baseline request (read-only)</span>
        {t.normalized_path && (
          <span className="mono text-base-content/40">
            path: {t.normalized_path}
          </span>
        )}
      </div>
      <pre className="p-3 text-xs mono whitespace-pre-wrap break-all max-h-56 overflow-auto leading-relaxed">
        <span className="text-info font-semibold">{method}</span>{" "}
        {highlightVars(url, vars)}
        {"\n"}
        {Object.entries(headers).map(([k, v]) => (
          <span key={k}>
            <span className="text-base-content/50">{k}:</span>{" "}
            {highlightVars(String(v), vars)}
            {"\n"}
          </span>
        ))}
        {t.body != null && t.body !== "" && (
          <>
            {"\n"}
            {highlightVars(String(t.body), vars)}
          </>
        )}
      </pre>
      {vars.length === 0 && (
        <div className="px-3 py-2 text-xs text-base-content/50 border-t border-base-300">
          No inject variables yet. Named query/header/body injects do not need{" "}
          <code className="mono">{"{{braces}}"}</code> in the raw URL — chips
          are the source of truth.
        </div>
      )}
    </div>
  );
}
