import { useEffect, useState } from "react";
import { api } from "../api/client";

interface ParamOption {
  id: string;
  name: string;
  location: string;
  param_type: string;
  endpoint_id: string;
  method: string;
  host: string;
  normalized_path: string;
}

/**
 * Searchable parameter dropdown — replaces raw-UUID text inputs across
 * Input Validation scoping/characterization. Loads a bounded parameter list
 * for the project once and filters client-side as the operator types.
 */
export default function ParameterPicker({
  projectId, value, onChange, placeholder = "Search parameters…",
}: {
  projectId: string;
  value: string;
  onChange: (parameterId: string) => void;
  placeholder?: string;
}) {
  const [options, setOptions] = useState<ParamOption[]>([]);
  const [query, setQuery] = useState("");
  const [open, setOpen] = useState(false);

  useEffect(() => {
    api.get<{ parameters: ParamOption[] }>("/api/endpoints/parameters/search", { project_id: projectId, limit: 500 })
      .then((r) => setOptions(r.parameters));
  }, [projectId]);

  const selected = options.find((o) => o.id === value);
  const filtered = query
    ? options.filter((o) =>
        o.name.toLowerCase().includes(query.toLowerCase()) ||
        o.normalized_path.toLowerCase().includes(query.toLowerCase())
      )
    : options;

  return (
    <div className="relative">
      <input
        className="input input-sm input-bordered mono w-80"
        placeholder={placeholder}
        value={open ? query : selected ? `${selected.name} — ${selected.method} ${selected.normalized_path}` : query}
        onFocus={() => { setOpen(true); setQuery(""); }}
        onChange={(e) => setQuery(e.target.value)}
        onBlur={() => setTimeout(() => setOpen(false), 150)}
      />
      {open && (
        <div className="absolute z-30 mt-1 w-[28rem] max-h-72 overflow-y-auto panel border border-base-300 shadow-lg">
          {filtered.length === 0 && <div className="p-3 text-sm text-base-content/40">No matching parameters.</div>}
          {filtered.map((o) => (
            <button
              key={o.id}
              className="w-full text-left px-3 py-2 text-xs hover:bg-base-300/50 border-b border-base-300 last:border-0"
              onMouseDown={(e) => {
                e.preventDefault();
                onChange(o.id);
                setOpen(false);
              }}
            >
              <div className="font-medium mono">{o.name} <span className="text-base-content/40">({o.location})</span></div>
              <div className="text-base-content/50 mono">{o.method} {o.host}{o.normalized_path}</div>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
