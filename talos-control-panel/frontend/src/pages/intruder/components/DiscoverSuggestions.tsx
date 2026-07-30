/**
 * Click-to-mark style inject discovery from baseline template (UI-only).
 */

import { useMemo, useState } from "react";
import {
  discoverInjectSuggestions,
  suggestionToVariable,
} from "../shared";
import type { InjectSuggestion, IntruderTemplate, TemplateVariable } from "../types";

export default function DiscoverSuggestions({
  template,
  existing,
  onAdd,
  disabled,
}: {
  template: IntruderTemplate | undefined;
  existing: TemplateVariable[];
  onAdd: (vars: TemplateVariable[]) => void;
  disabled?: boolean;
}) {
  const suggestions = useMemo(
    () => discoverInjectSuggestions(template, existing),
    [template, existing]
  );
  const [picked, setPicked] = useState<Set<string>>(() => new Set());
  const [open, setOpen] = useState(false);

  if (disabled) return null;
  if (suggestions.length === 0) {
    return (
      <div className="text-xs text-base-content/50">
        No auto-discovered inject points from the baseline. Use{" "}
        <strong>Add variable</strong> or <strong>From parameters</strong> when
        an endpoint is linked.
      </div>
    );
  }

  const keyOf = (s: InjectSuggestion) => `${s.location}:${s.path}`;

  const toggle = (s: InjectSuggestion) => {
    const k = keyOf(s);
    setPicked((prev) => {
      const next = new Set(prev);
      if (next.has(k)) next.delete(k);
      else next.add(k);
      return next;
    });
  };

  const addSelected = () => {
    const selected = suggestions.filter((s) => picked.has(keyOf(s)));
    if (!selected.length) return;
    let acc = [...existing];
    const added: TemplateVariable[] = [];
    for (const s of selected) {
      const v = suggestionToVariable(s, acc);
      acc = [...acc, v];
      added.push(v);
    }
    onAdd(added);
    setPicked(new Set());
    setOpen(false);
  };

  const addAll = () => {
    let acc = [...existing];
    const added: TemplateVariable[] = [];
    for (const s of suggestions) {
      const v = suggestionToVariable(s, acc);
      acc = [...acc, v];
      added.push(v);
    }
    onAdd(added);
    setPicked(new Set());
    setOpen(false);
  };

  if (!open) {
    return (
      <button
        type="button"
        className="btn btn-sm btn-outline"
        onClick={() => setOpen(true)}
      >
        Discover inject points ({suggestions.length})
      </button>
    );
  }

  return (
    <div className="rounded-md border border-base-300 bg-base-100 p-3 space-y-2">
      <div className="flex items-center justify-between gap-2">
        <div className="text-sm font-medium">
          Discover inject points
          <span className="ml-2 text-xs font-normal text-base-content/50">
            from baseline URL / headers / body
          </span>
        </div>
        <button
          type="button"
          className="btn btn-ghost btn-xs"
          onClick={() => setOpen(false)}
        >
          Close
        </button>
      </div>
      <p className="text-xs text-base-content/60">
        Suggestions become attack variables in the local draft. Named injects
        do not rewrite the baseline — the engine injects by key at render time.
      </p>
      <ul className="max-h-48 overflow-y-auto divide-y divide-base-300 border border-base-300 rounded-md">
        {suggestions.map((s) => {
          const k = keyOf(s);
          return (
            <li key={k}>
              <label className="flex items-start gap-2 px-2 py-1.5 text-xs cursor-pointer hover:bg-base-200/50">
                <input
                  type="checkbox"
                  className="checkbox checkbox-xs mt-0.5"
                  checked={picked.has(k)}
                  onChange={() => toggle(s)}
                />
                <span className="min-w-0">
                  <span className="mono font-medium">{s.path}</span>
                  <span className="text-base-content/40 ml-1">
                    {s.location}
                  </span>
                  <span className="block text-base-content/50 truncate">
                    {s.source}
                    {s.original_value != null && s.original_value !== ""
                      ? ` · ${String(s.original_value).slice(0, 40)}`
                      : ""}
                  </span>
                </span>
              </label>
            </li>
          );
        })}
      </ul>
      <div className="flex flex-wrap gap-2 justify-end">
        <button type="button" className="btn btn-xs btn-ghost" onClick={addAll}>
          Add all
        </button>
        <button
          type="button"
          className="btn btn-xs btn-primary"
          disabled={picked.size === 0}
          onClick={addSelected}
        >
          Add selected ({picked.size})
        </button>
      </div>
    </div>
  );
}
