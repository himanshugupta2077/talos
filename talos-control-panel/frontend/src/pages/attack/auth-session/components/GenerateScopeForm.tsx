import { useState } from "react";
import { useAction } from "../../../../hooks/useAction";
import { api } from "../../../../api/client";
import { FieldHint, Section } from "../../../../components/Common";
import {
  KNOWN_FAMILIES,
  inputClass,
  selectClass,
  type AuthSessionBinding,
  type GenerateScopeMode,
} from "../shared";

/**
 * Generate form — four scope modes matching CLI mutex (project / endpoint /
 * module / flow). No HTTP; creates pending candidates only.
 */
export default function GenerateScopeForm({
  projectId,
  bindings,
  onDone,
}: {
  projectId: string;
  bindings: AuthSessionBinding[];
  onDone: () => void;
}) {
  const [scope, setScope] = useState<GenerateScopeMode>("project");
  const [endpointId, setEndpointId] = useState("");
  const [module, setModule] = useState("");
  const [flowId, setFlowId] = useState("");
  const [bindingId, setBindingId] = useState("");
  const [role, setRole] = useState("");
  const [families, setFamilies] = useState<string[]>([]);
  const [testIds, setTestIds] = useState("");
  const [forceRefresh, setForceRefresh] = useState(false);
  const [includeUnsafe, setIncludeUnsafe] = useState(false);

  const generate = useAction("Generate auth-session candidates", () => {
    const body: Record<string, unknown> = {
      force_refresh: forceRefresh,
      include_unsafe_methods: includeUnsafe,
    };
    if (bindingId) body.binding_id = bindingId;
    if (role.trim()) body.role = role.trim();
    if (families.length) body.families = families;
    const tids = testIds
      .split(/[\s,]+/)
      .map((s) => s.trim())
      .filter(Boolean);
    if (tids.length) body.test_ids = tids;

    if (scope === "endpoint") body.endpoint_id = endpointId.trim();
    else if (scope === "module") body.module = module.trim();
    else if (scope === "flow") body.flow_id = flowId.trim();
    // project: no scope flags

    return api.post("/api/attack/auth-session/generate", body, {
      project_id: projectId,
    });
  });

  const scopeReady =
    scope === "project" ||
    (scope === "endpoint" && endpointId.trim()) ||
    (scope === "module" && module.trim()) ||
    (scope === "flow" && flowId.trim());

  const toggleFamily = (fam: string) => {
    setFamilies((prev) =>
      prev.includes(fam) ? prev.filter((f) => f !== fam) : [...prev, fam]
    );
  };

  return (
    <Section title="Generate candidates">
      <p className="text-xs text-base-content/60 mb-3">
        Create pending mutation candidates from captured baselines. No HTTP is
        sent — review and approve (CLI or Phase 3 UI) before run.
      </p>

      <div className="flex flex-wrap gap-2 mb-3" role="radiogroup" aria-label="Generate scope">
        {(
          [
            ["project", "Project"],
            ["endpoint", "Endpoint"],
            ["module", "Module"],
            ["flow", "Flow"],
          ] as const
        ).map(([id, label]) => (
          <label key={id} className="label cursor-pointer gap-1 py-0">
            <input
              type="radio"
              className="radio radio-xs"
              name="gen-scope"
              checked={scope === id}
              onChange={() => setScope(id)}
            />
            <span className="label-text text-xs">{label}</span>
          </label>
        ))}
      </div>
      <FieldHint text="Scope modes match CLI: project (no flags), --endpoint, --module, or --flow. Endpoint and module are mutually exclusive." />

      <div className="flex flex-wrap items-end gap-3 mt-3 mb-3">
        {scope === "endpoint" && (
          <label className="form-control min-w-[14rem]">
            <span className="label-text text-xs">Endpoint UUID</span>
            <input
              className={`${inputClass} mono`}
              value={endpointId}
              onChange={(e) => setEndpointId(e.target.value)}
              placeholder="endpoint id"
            />
          </label>
        )}
        {scope === "module" && (
          <label className="form-control min-w-[10rem]">
            <span className="label-text text-xs">Module name or UUID</span>
            <input
              className={inputClass}
              value={module}
              onChange={(e) => setModule(e.target.value)}
            />
          </label>
        )}
        {scope === "flow" && (
          <label className="form-control min-w-[14rem]">
            <span className="label-text text-xs">Baseline flow UUID</span>
            <input
              className={`${inputClass} mono`}
              value={flowId}
              onChange={(e) => setFlowId(e.target.value)}
              placeholder="flow id"
            />
          </label>
        )}

        <label className="form-control min-w-[10rem]">
          <span className="label-text text-xs">Binding (optional)</span>
          <select
            className={selectClass}
            value={bindingId}
            onChange={(e) => setBindingId(e.target.value)}
          >
            <option value="">All bindings</option>
            {bindings.map((b) => (
              <option key={b.id} value={b.id}>
                {b.location}:{b.name}
              </option>
            ))}
          </select>
        </label>

        <label className="form-control min-w-[8rem]">
          <span className="label-text text-xs">Role prefer</span>
          <input
            className={inputClass}
            value={role}
            onChange={(e) => setRole(e.target.value)}
            placeholder="optional"
          />
        </label>
      </div>

      <div className="mb-3">
        <span className="text-xs text-base-content/60 block mb-1">
          Families (optional multi-select)
        </span>
        <div className="flex flex-wrap gap-2">
          {KNOWN_FAMILIES.map((fam) => (
            <label key={fam} className="label cursor-pointer gap-1 py-0">
              <input
                type="checkbox"
                className="checkbox checkbox-xs"
                checked={families.includes(fam)}
                onChange={() => toggleFamily(fam)}
              />
              <span className="label-text text-xs mono">{fam}</span>
            </label>
          ))}
        </div>
      </div>

      <label className="form-control mb-3 max-w-xl">
        <span className="label-text text-xs">Test IDs (optional, comma/space separated)</span>
        <input
          className={`${inputClass} mono`}
          value={testIds}
          onChange={(e) => setTestIds(e.target.value)}
          placeholder="jwt.alg_none jwt.sig_empty"
        />
      </label>

      <div className="flex flex-wrap items-center gap-4 mb-3">
        <label className="label cursor-pointer gap-2 py-0">
          <input
            type="checkbox"
            className="checkbox checkbox-xs"
            checked={forceRefresh}
            onChange={(e) => setForceRefresh(e.target.checked)}
          />
          <span className="label-text text-xs">Force refresh pending/rejected</span>
        </label>
        <label className="label cursor-pointer gap-2 py-0">
          <input
            type="checkbox"
            className="checkbox checkbox-xs"
            checked={includeUnsafe}
            onChange={(e) => setIncludeUnsafe(e.target.checked)}
          />
          <span className="label-text text-xs">Include unsafe methods</span>
        </label>
      </div>

      {includeUnsafe && (
        <div className="alert alert-error text-xs py-2 mb-3">
          <span>
            <strong>Elevated risk.</strong>{" "}
            <span className="mono">--include-unsafe-methods</span> allows
            POST/PUT/PATCH/DELETE baselines. Prefer GET/HEAD/OPTIONS unless you
            intentionally need write-method baselines. Hub risk badge stays
            medium; this is a local warning only.
          </span>
        </div>
      )}

      <button
        type="button"
        className="btn btn-sm btn-primary"
        disabled={!scopeReady || generate.running || bindings.length === 0}
        onClick={async () => {
          try {
            await generate.run();
            onDone();
          } catch {
            /* logged */
          }
        }}
      >
        {generate.running ? (
          <span className="loading loading-spinner loading-xs" />
        ) : (
          "Generate"
        )}
      </button>
      {bindings.length === 0 && (
        <span className="text-xs text-warning ml-2">
          Bind at least one field first.
        </span>
      )}
    </Section>
  );
}
