import { useEffect, useMemo, useState } from "react";
import { api } from "../../api/client";
import DataTable, { Column } from "../../components/DataTable";
import { RuleRow, selectClass } from "./shared";

export default function RulesTab({ projectId }: { projectId: string }) {
  const [rules, setRules] = useState<RuleRow[]>([]);
  const [loadErrors, setLoadErrors] = useState<{ pack: string; message: string }[]>(
    [],
  );
  const [pack, setPack] = useState("");
  const [family, setFamily] = useState("");
  const [enabledOnly, setEnabledOnly] = useState(false);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    setLoading(true);
    api
      .get<{
        rules: RuleRow[];
        load_errors: { pack: string; message: string }[];
      }>("/api/passive/rules", { project_id: projectId })
      .then((r) => {
        setRules(r.rules || []);
        setLoadErrors(r.load_errors || []);
      })
      .catch(() => {
        setRules([]);
        setLoadErrors([]);
      })
      .finally(() => setLoading(false));
  }, [projectId]);

  const packs = useMemo(
    () => [...new Set(rules.map((r) => r.pack).filter(Boolean))].sort(),
    [rules],
  );
  const families = useMemo(
    () => [...new Set(rules.map((r) => r.family).filter(Boolean))].sort(),
    [rules],
  );

  const filtered = rules.filter(
    (r) =>
      (!pack || r.pack === pack) &&
      (!family || r.family === family) &&
      (!enabledOnly || r.enabled),
  );

  const columns: Column<RuleRow>[] = [
    {
      key: "id",
      header: "ID",
      render: (r) => <span className="mono text-xs">{r.id}</span>,
    },
    { key: "name", header: "Name" },
    {
      key: "confidence_level",
      header: "Level",
      render: (r) => (
        <span className="badge badge-ghost badge-xs">{r.confidence_level}</span>
      ),
    },
    {
      key: "pack",
      header: "Pack",
      render: (r) => <span className="text-xs">{r.pack}</span>,
    },
    {
      key: "family",
      header: "Family",
      render: (r) => <span className="text-xs">{r.family}</span>,
    },
    {
      key: "enabled",
      header: "On",
      render: (r) =>
        r.enabled ? (
          <span className="badge badge-success badge-xs">yes</span>
        ) : (
          <span className="badge badge-ghost badge-xs">no</span>
        ),
    },
    {
      key: "finding_title",
      header: "Finding title",
      render: (r) => (
        <span className="text-xs text-base-content/70">{r.finding_title || "—"}</span>
      ),
    },
  ];

  return (
    <div>
      <p className="text-xs text-base-content/60 mb-3">
        Package-shipped detector rules (YAML packs). Not project-editable in v1 —
        bump scanner version and rescan after rule upgrades.
      </p>

      {loadErrors.length > 0 && (
        <div className="alert alert-warning text-xs mb-3">
          <div>
            <div className="font-medium">Rule pack load errors</div>
            {loadErrors.map((e) => (
              <div key={e.pack}>
                {e.pack}: {e.message}
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="flex flex-wrap gap-2 mb-4 items-center">
        <select className={selectClass} value={pack} onChange={(e) => setPack(e.target.value)}>
          <option value="">pack: any</option>
          {packs.map((p) => (
            <option key={p} value={p}>
              {p}
            </option>
          ))}
        </select>
        <select
          className={selectClass}
          value={family}
          onChange={(e) => setFamily(e.target.value)}
        >
          <option value="">family: any</option>
          {families.map((f) => (
            <option key={f} value={f}>
              {f}
            </option>
          ))}
        </select>
        <label className="label cursor-pointer gap-1 py-0">
          <input
            type="checkbox"
            className="checkbox checkbox-xs"
            checked={enabledOnly}
            onChange={(e) => setEnabledOnly(e.target.checked)}
          />
          <span className="label-text text-xs">enabled only</span>
        </label>
        <span className="text-xs text-base-content/50">
          {loading ? "Loading…" : `${filtered.length} / ${rules.length} rules`}
        </span>
      </div>

      <DataTable
        columns={columns}
        rows={filtered}
        rowKey={(r) => r.id}
        emptyLabel="No rules loaded."
        storageKey="passive-rules"
      />
    </div>
  );
}
