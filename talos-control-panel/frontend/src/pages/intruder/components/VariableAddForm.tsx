import { useEffect, useState } from "react";
import { FieldHint } from "../../../components/Common";
import {
  pathInjectWarning,
  uniqueVarName,
  VARIABLE_LOCATIONS,
} from "../shared";
import type { TemplateVariable, VariableLocation } from "../types";

export default function VariableAddForm({
  existing,
  normalizedPath,
  onAdd,
  forceOpen,
  onOpenChange,
}: {
  existing: TemplateVariable[];
  normalizedPath?: string | null;
  onAdd: (v: TemplateVariable) => void;
  /** Controlled open from empty-draft CTA. */
  forceOpen?: boolean;
  onOpenChange?: (open: boolean) => void;
}) {
  const [name, setName] = useState("");
  const [location, setLocation] = useState<VariableLocation>("query");
  const [path, setPath] = useState("");
  const [mode, setMode] = useState<"attack" | "fixed">("attack");
  const [fixedValue, setFixedValue] = useState("");
  const [original, setOriginal] = useState("");
  const [open, setOpen] = useState(false);

  useEffect(() => {
    if (forceOpen) setOpen(true);
  }, [forceOpen]);

  const setOpenBoth = (v: boolean) => {
    setOpen(v);
    onOpenChange?.(v);
  };

  const inject = path.trim() || name.trim() || "var";
  const warn = pathInjectWarning(location, inject, normalizedPath);

  const reset = () => {
    setName("");
    setPath("");
    setFixedValue("");
    setOriginal("");
    setMode("attack");
    setLocation("query");
  };

  const submit = () => {
    const base = name.trim();
    if (!base) return;
    // Sanitize for artifact path safety (letters, digits, underscore)
    const sanitized = base.replace(/[^A-Za-z0-9_]/g, "_");
    if (!sanitized) return;
    const finalName = uniqueVarName(sanitized, existing);
    onAdd({
      name: finalName,
      location,
      path: (path.trim() || finalName) || null,
      original_value: original.trim() || null,
      fixed_value: mode === "fixed" ? fixedValue : null,
    });
    reset();
    setOpenBoth(false);
  };

  if (!open) {
    return (
      <button
        type="button"
        className="btn btn-sm btn-outline"
        onClick={() => setOpenBoth(true)}
      >
        + Add variable
      </button>
    );
  }

  return (
    <div className="rounded-md border border-base-300 bg-base-100 p-3 space-y-2">
      <div className="flex items-center justify-between">
        <div className="text-sm font-medium">Add variable</div>
        <button
          type="button"
          className="btn btn-ghost btn-xs"
          onClick={() => {
            reset();
            setOpenBoth(false);
          }}
        >
          Cancel
        </button>
      </div>
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
        <label className="form-control">
          <span className="label-text text-xs">
            Name
            <FieldHint text="Payload set key for attack vars; letters, digits, underscore. Defaults to inject path when free." />
          </span>
          <input
            className="input input-bordered input-sm mono"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="user_id"
            autoFocus
          />
        </label>
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
          <span className="label-text text-xs">
            Inject path
            <FieldHint text="Query key / header name / JSON field. Defaults to name." />
          </span>
          <input
            className="input input-bordered input-sm mono"
            value={path}
            onChange={(e) => setPath(e.target.value)}
            placeholder={name || "same as name"}
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
          <label className="form-control sm:col-span-2">
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
            placeholder="Baseline value for display"
          />
        </label>
      </div>
      {warn && (
        <div className="alert alert-warning text-xs py-2">{warn}</div>
      )}
      <div className="flex justify-end">
        <button
          type="button"
          className="btn btn-sm btn-primary"
          disabled={!name.trim()}
          onClick={submit}
        >
          Add to draft
        </button>
      </div>
    </div>
  );
}
