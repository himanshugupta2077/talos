import { useEffect, useMemo, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { useProject } from "../state/ProjectContext";
import { api } from "../api/client";
import { useAction } from "../hooks/useAction";
import { NoProjectNotice, Section, ConfirmButton } from "../components/Common";
import DataTable, { Column } from "../components/DataTable";
import StatusBadge from "../components/StatusBadge";
import { attackTypeLabel } from "../lib/attackDisplay";
import { formatIST } from "../lib/time";
import { Finding, FindingGroup } from "../types";
import FindingsBulkBar from "./findings/BulkBar";

const STATUSES = ["TRIAGING", "CONFIRMED", "REJECTED", "DUPLICATE"];

type RelationView = "primary" | "linked" | "all";

interface BulkResult {
  action?: string;
  requested: number;
  ok: number;
  failed: number;
  linked?: boolean;
}

export default function Findings() {
  const { selected } = useProject();
  const [searchParams] = useSearchParams();
  const [findings, setFindings] = useState<Finding[]>([]);
  const [status, setStatus] = useState("");
  const [view, setView] = useState<RelationView>("primary");
  const [attackType, setAttackType] = useState(
    () => searchParams.get("attack_type") || ""
  );
  const [verdict, setVerdict] = useState(
    () => searchParams.get("verdict") || ""
  );
  const [role, setRole] = useState("");
  const [module, setModule] = useState("");
  const [groups, setGroups] = useState<FindingGroup[]>([]);
  const [groupName, setGroupName] = useState("");
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [applyLinked, setApplyLinked] = useState(false);
  const [bulkResult, setBulkResult] = useState<BulkResult | null>(null);
  const navigate = useNavigate();

  // Hydrate filters when deep-link query changes (K18)
  useEffect(() => {
    const at = searchParams.get("attack_type");
    const vd = searchParams.get("verdict");
    if (at !== null) setAttackType(at);
    if (vd !== null) setVerdict(vd);
  }, [searchParams]);

  const load = () => {
    if (!selected) return;
    api
      .get<{ findings: Finding[] }>("/api/findings", {
        project_id: selected.id,
        status: status || undefined,
        view,
      })
      .then((r) => setFindings(r.findings));
    api
      .get<{ groups: FindingGroup[] }>("/api/findings/groups/list", {
        project_id: selected.id,
      })
      .then((r) => setGroups(r.groups));
  };
  useEffect(load, [selected, status, view]);

  // Drop selection for rows no longer visible
  useEffect(() => {
    setSelectedIds((prev) => {
      if (prev.size === 0) return prev;
      const visible = new Set(findings.map((f) => f.id));
      const next = new Set([...prev].filter((id) => visible.has(id)));
      return next.size === prev.size ? prev : next;
    });
  }, [findings]);

  const createGroup = useAction("Create finding group", () =>
    api.post(
      "/api/findings/groups",
      { name: groupName },
      { project_id: selected!.id }
    )
  );
  const deleteGroup = useAction("Delete finding group", (name: string) =>
    api.post(
      "/api/findings/groups/delete",
      { group: name, remove_findings: false },
      { project_id: selected!.id }
    )
  );
  const genGroupReport = useAction("Generate group report", (name: string) =>
    api.get<{ steps: any[] }>(`/api/findings/groups/report/${name}`, {
      project_id: selected!.id,
    })
  );
  const [groupReport, setGroupReport] = useState<{
    name: string;
    text: string;
  } | null>(null);

  const bulkAction = useAction(
    "Bulk findings",
    async (path: string, body: object) => {
      const res = await api.post<
        BulkResult & { results?: { steps?: any[] }[] }
      >(path, body, {
        project_id: selected!.id,
      });
      setBulkResult(res);
      // Flatten per-id CLI steps for the command log (useAction expects StepsResponse).
      const steps = (res.results || []).flatMap((r) => r.steps || []);
      if (steps.length === 0) {
        steps.push({
          cmd: [],
          cmd_str: `bulk ${res.action || path}`,
          stdout: `${res.ok}/${res.requested} ok`,
          stderr: res.failed ? `${res.failed} failed` : "",
          exit_code: res.failed ? 1 : 0,
          duration_ms: 0,
          ok: !res.failed,
        });
      }
      return { steps };
    }
  );

  const filtered = useMemo(
    () =>
      findings.filter(
        (f) =>
          (!attackType || f.attack_type === attackType) &&
          (!verdict || f.verdict === verdict) &&
          (!role || f.role_name === role) &&
          (!module || f.module_name === module)
      ),
    [findings, attackType, verdict, role, module]
  );

  const filteredIds = useMemo(() => filtered.map((f) => f.id), [filtered]);
  const allFilteredSelected =
    filteredIds.length > 0 && filteredIds.every((id) => selectedIds.has(id));

  if (!selected) return <NoProjectNotice />;

  const attackTypes = [
    ...new Set(findings.map((f) => f.attack_type).filter(Boolean)),
  ];
  const verdicts = [
    ...new Set(findings.map((f) => f.verdict).filter(Boolean)),
  ];
  const roles = [
    ...new Set(findings.map((f) => f.role_name).filter(Boolean)),
  ] as string[];
  const modules = [
    ...new Set(findings.map((f) => f.module_name).filter(Boolean)),
  ] as string[];

  const toggleRow = (id: string) => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const toggleAllFiltered = () => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (allFilteredSelected) {
        filteredIds.forEach((id) => next.delete(id));
      } else {
        filteredIds.forEach((id) => next.add(id));
      }
      return next;
    });
  };

  const clearSelection = () => {
    setSelectedIds(new Set());
    setBulkResult(null);
  };

  const selectedList = [...selectedIds];

  const afterBulk = async () => {
    clearSelection();
    load();
  };

  const runBulkLifecycle = async (action: "confirm" | "reject" | "reopen") => {
    if (!selectedList.length) return;
    await bulkAction.run("/api/findings/bulk", {
      action,
      finding_ids: selectedList,
      linked: applyLinked,
    });
    await afterBulk();
  };

  const columns: Column<Finding>[] = [
    {
      key: "select",
      header: (
        <input
          type="checkbox"
          className="checkbox checkbox-xs"
          checked={allFilteredSelected}
          onChange={toggleAllFiltered}
          title="Select all filtered"
          onClick={(e) => e.stopPropagation()}
        />
      ),
      sortable: false,
      alwaysVisible: true,
      defaultWidth: 48,
      minWidth: 40,
      render: (f) => (
        <input
          type="checkbox"
          className="checkbox checkbox-xs"
          checked={selectedIds.has(f.id)}
          onChange={() => toggleRow(f.id)}
          onClick={(e) => e.stopPropagation()}
        />
      ),
    },
    {
      key: "relation",
      header: "Rel",
      render: (f) => {
        const rel = (f.relation_type || "PRIMARY").toUpperCase();
        if (rel === "LINKED") {
          return <span className="badge badge-ghost badge-xs">LINKED</span>;
        }
        const n = f.linked_count ?? 0;
        return (
          <span
            className="badge badge-outline badge-xs"
            title={n ? `${n} linked variant(s)` : "PRIMARY"}
          >
            PRIMARY{n > 0 ? ` +${n}` : ""}
          </span>
        );
      },
    },
    {
      key: "title",
      header: "Title",
      render: (f) => (
        <span className="font-medium">{f.title || "(untitled)"}</span>
      ),
    },
    {
      key: "attack_type",
      header: "Type",
      render: (f) => (
        <span title={f.attack_type || undefined}>
          {attackTypeLabel(f.attack_type)}
        </span>
      ),
    },
    {
      key: "verdict",
      header: "Verdict",
      render: (f) => <StatusBadge value={f.verdict} />,
    },
    {
      key: "status",
      header: "Status",
      render: (f) => <StatusBadge value={f.status} />,
    },
    {
      key: "notes",
      header: "Notes",
      render: (f) =>
        f.notes?.trim() ? (
          <span
            className="text-xs text-base-content/70 truncate max-w-[8rem] inline-block"
            title={f.notes}
          >
            {f.notes.trim().slice(0, 40)}
            {f.notes.trim().length > 40 ? "…" : ""}
          </span>
        ) : (
          <span className="text-base-content/30">—</span>
        ),
    },
    {
      key: "role_name",
      header: "Role",
      render: (f) =>
        f.role_name || <span className="text-base-content/30">—</span>,
    },
    {
      key: "module_name",
      header: "Module",
      render: (f) =>
        f.module_name || <span className="text-base-content/30">—</span>,
    },
    {
      key: "created_at",
      header: "Created",
      className: "text-xs",
      sortValue: (f) => f.created_at,
      render: (f) => formatIST(f.created_at),
    },
  ];

  const selectClass = "select select-sm select-bordered";

  return (
    <div>
      <div className="flex items-center justify-between mb-4">
        <h1 className="text-xl font-semibold">Findings ({filtered.length})</h1>
        {selectedIds.size > 0 && (
          <span className="text-xs text-base-content/50">
            {selectedIds.size} selected
          </span>
        )}
      </div>

      <div className="flex flex-wrap gap-2 mb-4">
        <select
          className={selectClass}
          value={view}
          onChange={(e) => setView(e.target.value as RelationView)}
          title="CLI: default PRIMARY · --linked · --all"
        >
          <option value="primary">PRIMARY (default)</option>
          <option value="linked">LINKED only</option>
          <option value="all">All (PRIMARY + LINKED)</option>
        </select>
        <select
          className={selectClass}
          value={status}
          onChange={(e) => setStatus(e.target.value)}
        >
          <option value="">All statuses</option>
          {STATUSES.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
        <select
          className={selectClass}
          value={attackType}
          onChange={(e) => setAttackType(e.target.value)}
        >
          <option value="">type: any</option>
          {attackTypes.map((t) => (
            <option key={t} value={t}>
              {attackTypeLabel(t)}
            </option>
          ))}
        </select>
        <button
          type="button"
          className={`btn btn-xs ${
            attackType === "passive_secret" ? "btn-primary" : "btn-ghost"
          }`}
          onClick={() =>
            setAttackType(attackType === "passive_secret" ? "" : "passive_secret")
          }
        >
          Secrets only
        </button>
        <select
          className={selectClass}
          value={verdict}
          onChange={(e) => setVerdict(e.target.value)}
        >
          <option value="">verdict: any</option>
          {verdicts.map((v) => (
            <option key={v} value={v}>
              {v}
            </option>
          ))}
        </select>
        <select
          className={selectClass}
          value={role}
          onChange={(e) => setRole(e.target.value)}
        >
          <option value="">role: any</option>
          {roles.map((r) => (
            <option key={r} value={r}>
              {r}
            </option>
          ))}
        </select>
        <select
          className={selectClass}
          value={module}
          onChange={(e) => setModule(e.target.value)}
        >
          <option value="">module: any</option>
          {modules.map((m) => (
            <option key={m} value={m}>
              {m}
            </option>
          ))}
        </select>
        {filteredIds.length > 0 && (
          <button
            type="button"
            className="btn btn-xs btn-outline"
            onClick={toggleAllFiltered}
            title="Select all currently filtered rows"
          >
            {allFilteredSelected ? "Deselect filtered" : "Select filtered"}
          </button>
        )}
      </div>

      {bulkResult && (
        <div className="alert alert-info text-sm py-2 mb-3">
          Bulk: {bulkResult.ok}/{bulkResult.requested} ok
          {bulkResult.failed ? ` · ${bulkResult.failed} failed` : ""}
          {bulkResult.action ? ` · ${bulkResult.action}` : ""}
          {bulkResult.linked ? " · with linked" : ""}
        </div>
      )}

      <DataTable
        columns={columns}
        rows={filtered}
        rowKey={(f) => f.id}
        storageKey="findings"
        onRowClick={(f) => navigate(`/findings/${f.id}`)}
        emptyLabel="No findings yet — created from POSSIBLE_BAC / BYPASS / WEAK_VALIDATION (and other attack modules)."
      />

      <FindingsBulkBar
        count={selectedIds.size}
        busy={bulkAction.running}
        groups={groups}
        applyLinked={applyLinked}
        onApplyLinkedChange={setApplyLinked}
        onClear={clearSelection}
        onConfirm={() => runBulkLifecycle("confirm")}
        onReject={() => runBulkLifecycle("reject")}
        onReopen={() => runBulkLifecycle("reopen")}
        onAddToGroup={async (group) => {
          await bulkAction.run("/api/findings/bulk/group", {
            group,
            finding_ids: selectedList,
          });
          await afterBulk();
        }}
        onSetNotes={async (notes) => {
          await bulkAction.run("/api/findings/bulk/notes", {
            notes,
            finding_ids: selectedList,
          });
          await afterBulk();
        }}
      />

      <Section
        title="Groups"
        action={
          <div className="flex gap-2">
            <input
              className="input input-xs input-bordered"
              placeholder="New group name"
              value={groupName}
              onChange={(e) => setGroupName(e.target.value)}
            />
            <button
              className="btn btn-xs btn-primary"
              onClick={async () => {
                await createGroup.run();
                setGroupName("");
                load();
              }}
            >
              Create
            </button>
          </div>
        }
      >
        <div className="flex flex-wrap gap-2">
          {groups.map((g) => (
            <div key={g.id} className="badge badge-outline gap-2 py-4">
              {g.name} ({g.member_count})
              <button
                className="btn btn-xs btn-ghost"
                onClick={async () => {
                  const r: any = await genGroupReport.run(g.name);
                  const step = r?.steps?.[0];
                  setGroupReport({
                    name: g.name,
                    text: step?.stdout || step?.stderr || "",
                  });
                }}
              >
                report
              </button>
              <ConfirmButton
                className="btn btn-xs btn-ghost"
                onConfirm={async () => {
                  await deleteGroup.run(g.name);
                  load();
                }}
                confirmText="delete?"
              >
                ✕
              </ConfirmButton>
            </div>
          ))}
          {groups.length === 0 && (
            <span className="text-sm text-base-content/40">No groups yet.</span>
          )}
        </div>
        {groupReport && (
          <div className="mt-3">
            <div className="text-xs uppercase text-base-content/50 mb-1">
              Report: {groupReport.name}
            </div>
            <pre className="panel p-3 mono text-xs whitespace-pre-wrap max-h-96 overflow-y-auto">
              {groupReport.text}
            </pre>
          </div>
        )}
      </Section>
    </div>
  );
}
