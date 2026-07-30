/**
 * Inline editor for a selected variable chip (fixed value / location / path).
 */

import { useEffect, useState } from "react";
import { pathInjectWarning, VARIABLE_LOCATIONS } from "../shared";
import type { TemplateVariable, VariableLocation } from "../types";

export default function VariableEditPanel({
  variable,
  normalizedPath,
  onChange,
  onClose,
}: {
  variable: TemplateVariable;
  normalizedPath?: string | null;
  onChange: (v: TemplateVariable) => void;
  onClose: () => void;
}) {
  const [location, setLocation] = useState<VariableLocation>(variable.location);
  const [path, setPath] = useState(variable.path || "");
  const [mode, setMode] = useState<"attack" | "fixed">(
    variable.fixed_value == null ? "attack" : "fixed"
  );
  const [fixedValue, setFixedValue] = useState(variable.fixed_value ?? "");
  const [original, setOriginal] = useState(variable.original_value ?? "");

  useEffect(() => {
    setLocation(variable.location);
    setPath(variable.path || "");
    setMode(variable.fixed_value == null ? "attack" : "fixed");
    setFixedValue(variable.fixed_value ?? "");
    setOriginal(variable.original_value ?? "");
  }, [variable]);

  const inject = (path.trim() || variable.name);
  const warn = pathInjectWarning(location, inject, normalizedPath);

  const apply = () => {
    onChange({
      ...variable,
      location,
      path: (path.trim() || variable.name) || null,
      original_value: original.trim() || null,
      fixed_value: mode === "fixed" ? fixedValue : null,
    });
  };

  return (
    <div className="rounded-md border border-primary/30 bg-primary/5 p-3 space-y-2">
      <div className="flex items-center justify-between gap-2">
        <div className="text-sm font-medium">
          Edit <span className="mono">{variable.name}</span>
        </div>
        <button type="button" className="btn btn-ghost btn-xs" onClick={onClose}>
          Close
        </button>
      </div>
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
        <label className="form-control">
          <span className="label-text text-xs">Location</span>
          <select
            className="select select-bordered select-sm"
            value={location}
            onChange={(e) => setLocation(e.target.value as VariableLocation)}
          >
            {VARIABLE_LOCATIONS.map((loc) => (
              <option key={loc} value={loc}>
                {loc}
              </option>
            ))}
          </select>
        </label>
        <label className="form-control">
          <span className="label-text text-xs">Inject path</span>
          <input
            className="input input-bordered input-sm mono"
            value={path}
            onChange={(e) => setPath(e.target.value)}
            placeholder={variable.name}
          />
        </label>
        <label className="form-control">
          <span className="label-text text-xs">Mode</span>
          <select
            className="select select-bordered select-sm"
            value={mode}
            onChange={(e) => setMode(e.target.value as "attack" | "fixed")}
          >
            <option value="attack">Attack (strategy-driven)</option>
            <option value="fixed">Fixed value</option>
          </select>
        </label>
        {mode === "fixed" && (
          <label className="form-control">
            <span className="label-text text-xs">Fixed value</span>
            <input
              className="input input-bordered input-sm"
              value={fixedValue}
              onChange={(e) => setFixedValue(e.target.value)}
            />
          </label>
        )}
        <label className="form-control sm:col-span-2">
          <span className="label-text text-xs">Original value (optional)</span>
          <input
            className="input input-bordered input-sm"
            value={original}
            onChange={(e) => setOriginal(e.target.value)}
          />
        </label>
      </div>
      {warn && <div className="alert alert-warning text-xs py-2">{warn}</div>}
      <div className="flex justify-end">
        <button type="button" className="btn btn-sm btn-primary" onClick={apply}>
          Apply to draft
        </button>
      </div>
    </div>
  );
}
