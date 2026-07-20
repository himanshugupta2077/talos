import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useProject } from "../state/ProjectContext";
import { api } from "../api/client";
import { useAction } from "../hooks/useAction";
import { NoProjectNotice, Section, ConfirmButton } from "../components/Common";
import DataTable, { Column } from "../components/DataTable";
import StatusBadge from "../components/StatusBadge";
import { formatIST } from "../lib/time";
import { Finding, FindingGroup } from "../types";

const STATUSES = ["TRIAGING", "CONFIRMED", "REJECTED", "DUPLICATE"];

export default function Findings() {
  const { selected } = useProject();
  const [findings, setFindings] = useState<Finding[]>([]);
  const [status, setStatus] = useState("");
  const [attackType, setAttackType] = useState("");
  const [verdict, setVerdict] = useState("");
  const [role, setRole] = useState("");
  const [module, setModule] = useState("");
  const [groups, setGroups] = useState<FindingGroup[]>([]);
  const [groupName, setGroupName] = useState("");
  const navigate = useNavigate();

  const load = () => {
    if (!selected) return;
    api.get<{ findings: Finding[] }>("/api/findings", { project_id: selected.id, status: status || undefined }).then((r) => setFindings(r.findings));
    api.get<{ groups: FindingGroup[] }>("/api/findings/groups/list", { project_id: selected.id }).then((r) => setGroups(r.groups));
  };
  useEffect(load, [selected, status]);

  const createGroup = useAction("Create finding group", () =>
    api.post("/api/findings/groups", { name: groupName }, { project_id: selected!.id })
  );
  const deleteGroup = useAction("Delete finding group", (name: string) =>
    api.post("/api/findings/groups/delete", { group: name, remove_findings: false }, { project_id: selected!.id })
  );
  const genGroupReport = useAction("Generate group report", (name: string) =>
    api.get<{ steps: any[] }>(`/api/findings/groups/report/${name}`, { project_id: selected!.id })
  );
  const [groupReport, setGroupReport] = useState<{ name: string; text: string } | null>(null);

  if (!selected) return <NoProjectNotice />;

  const attackTypes = [...new Set(findings.map((f) => f.attack_type).filter(Boolean))];
  const verdicts = [...new Set(findings.map((f) => f.verdict).filter(Boolean))];
  const roles = [...new Set(findings.map((f) => f.role_name).filter(Boolean))] as string[];
  const modules = [...new Set(findings.map((f) => f.module_name).filter(Boolean))] as string[];

  const filtered = findings.filter((f) =>
    (!attackType || f.attack_type === attackType) &&
    (!verdict || f.verdict === verdict) &&
    (!role || f.role_name === role) &&
    (!module || f.module_name === module)
  );

  const columns: Column<Finding>[] = [
    { key: "title", header: "Title", render: (f) => <span className="font-medium">{f.title || "(untitled)"}</span> },
    { key: "attack_type", header: "Type" },
    { key: "verdict", header: "Verdict", render: (f) => <StatusBadge value={f.verdict} /> },
    { key: "status", header: "Status", render: (f) => <StatusBadge value={f.status} /> },
    { key: "role_name", header: "Role", render: (f) => f.role_name || <span className="text-base-content/30">—</span> },
    { key: "module_name", header: "Module", render: (f) => f.module_name || <span className="text-base-content/30">—</span> },
    { key: "created_at", header: "Created", className: "text-xs", sortValue: (f) => f.created_at, render: (f) => formatIST(f.created_at) },
  ];

  const selectClass = "select select-sm select-bordered";

  return (
    <div>
      <div className="flex items-center justify-between mb-4">
        <h1 className="text-xl font-semibold">Findings ({filtered.length})</h1>
      </div>

      <div className="flex flex-wrap gap-2 mb-4">
        <select className={selectClass} value={status} onChange={(e) => setStatus(e.target.value)}>
          <option value="">All statuses</option>
          {STATUSES.map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
        <select className={selectClass} value={attackType} onChange={(e) => setAttackType(e.target.value)}>
          <option value="">type: any</option>
          {attackTypes.map((t) => <option key={t} value={t}>{t}</option>)}
        </select>
        <select className={selectClass} value={verdict} onChange={(e) => setVerdict(e.target.value)}>
          <option value="">verdict: any</option>
          {verdicts.map((v) => <option key={v} value={v}>{v}</option>)}
        </select>
        <select className={selectClass} value={role} onChange={(e) => setRole(e.target.value)}>
          <option value="">role: any</option>
          {roles.map((r) => <option key={r} value={r}>{r}</option>)}
        </select>
        <select className={selectClass} value={module} onChange={(e) => setModule(e.target.value)}>
          <option value="">module: any</option>
          {modules.map((m) => <option key={m} value={m}>{m}</option>)}
        </select>
      </div>

      <DataTable
        columns={columns}
        rows={filtered}
        rowKey={(f) => f.id}
        storageKey="findings"
        onRowClick={(f) => navigate(`/findings/${f.id}`)}
        emptyLabel="No findings yet — they're created automatically from POSSIBLE_BAC / BYPASS verdicts."
      />

      <Section title="Groups" action={
        <div className="flex gap-2">
          <input className="input input-xs input-bordered" placeholder="New group name" value={groupName} onChange={(e) => setGroupName(e.target.value)} />
          <button className="btn btn-xs btn-primary" onClick={async () => { await createGroup.run(); setGroupName(""); load(); }}>Create</button>
        </div>
      }>
        <div className="flex flex-wrap gap-2">
          {groups.map((g) => (
            <div key={g.id} className="badge badge-outline gap-2 py-4">
              {g.name} ({g.member_count})
              <button
                className="btn btn-xs btn-ghost"
                onClick={async () => {
                  const r: any = await genGroupReport.run(g.name);
                  const step = r?.steps?.[0];
                  setGroupReport({ name: g.name, text: step?.stdout || step?.stderr || "" });
                }}
              >
                report
              </button>
              <ConfirmButton className="btn btn-xs btn-ghost" onConfirm={async () => { await deleteGroup.run(g.name); load(); }} confirmText="delete?">
                ✕
              </ConfirmButton>
            </div>
          ))}
          {groups.length === 0 && <span className="text-sm text-base-content/40">No groups yet.</span>}
        </div>
        {groupReport && (
          <div className="mt-3">
            <div className="text-xs uppercase text-base-content/50 mb-1">Report: {groupReport.name}</div>
            <pre className="panel p-3 mono text-xs whitespace-pre-wrap max-h-96 overflow-y-auto">{groupReport.text}</pre>
          </div>
        )}
      </Section>
    </div>
  );
}
