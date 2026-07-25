import { useCallback, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../../api/client";
import DataTable, { Column } from "../../components/DataTable";
import SideDrawer from "../../components/SideDrawer";
import PolicyExplain from "../../components/PolicyExplain";
import StatusBadge from "../../components/StatusBadge";
import { UuidChip } from "../../components/Common";
import {
  EndpointPolicyExplanation,
  EndpointPolicySummary,
  EndpointRow,
} from "../../types";
import {
  CardStat,
  DecisionBadge,
  EndpointLabel,
  FilterState,
  PAGE_SIZE,
  PrioritySourceBadge,
} from "./shared";

const PROBLEM_FILTERS: { key: string; label: string }[] = [
  { key: "why_not_testable", label: "Why not testable?" },
  { key: "no_baseline", label: "No baseline" },
  { key: "no_2xx_response", label: "No 2xx response" },
  { key: "only_redirects", label: "Only redirects" },
  { key: "dangerous", label: "Dangerous" },
  { key: "logout", label: "Logout" },
  { key: "excluded_by_endpoint", label: "Excluded by endpoint" },
  { key: "excluded_by_rule", label: "Excluded by rule" },
  { key: "manual_overrides", label: "Manual overrides" },
];

export default function PolicyTab({
  projectId,
  onOpenRules,
  onJumpInventory,
}: {
  projectId: string;
  onOpenRules: (ruleId?: string) => void;
  onJumpInventory: (filters: Partial<FilterState>) => void;
}) {
  const navigate = useNavigate();
  const [summary, setSummary] = useState<EndpointPolicySummary | null>(null);
  const [rows, setRows] = useState<EndpointRow[]>([]);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [problem, setProblem] = useState("");
  const [search, setSearch] = useState("");
  const [loading, setLoading] = useState(false);
  const [explainId, setExplainId] = useState<string | null>(null);
  const [explain, setExplain] = useState<EndpointPolicyExplanation | null>(null);

  const load = useCallback(() => {
    setLoading(true);
    const params = {
      project_id: projectId,
      limit: PAGE_SIZE,
      offset,
      search,
      problem,
    };
    Promise.all([
      api.get<{ endpoints: EndpointRow[]; total: number }>("/api/endpoints", params),
      api.get<EndpointPolicySummary>("/api/endpoints/policy-summary", {
        project_id: projectId,
      }),
    ])
      .then(([list, sum]) => {
        setRows(list.endpoints);
        setTotal(list.total);
        setSummary(sum);
      })
      .finally(() => setLoading(false));
  }, [projectId, offset, search, problem]);

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    setOffset(0);
  }, [problem, search]);

  const openExplain = async (id: string) => {
    setExplainId(id);
    const data = await api.get<EndpointPolicyExplanation>(`/api/endpoints/${id}/policy`, {
      project_id: projectId,
    });
    setExplain(data);
  };

  const s = summary;
  const byP = s?.by_priority || {};

  const columns: Column<EndpointRow>[] = [
    {
      key: "endpoint",
      header: "Endpoint",
      sortValue: (r) => `${r.method} ${r.normalized_path}`,
      render: (r) => (
        <div className="flex items-start gap-2">
          <span className="badge badge-outline badge-xs mono mt-0.5">{r.method}</span>
          <EndpointLabel row={r} />
        </div>
      ),
    },
    {
      key: "priority",
      header: "Effective Priority",
      sortValue: (r) => r.effective_priority || "",
      render: (r) => (
        <PrioritySourceBadge row={r} onRuleClick={(id) => onOpenRules(id)} />
      ),
    },
    {
      key: "source",
      header: "Source",
      sortValue: (r) => r.priority_source || "",
      render: (r) => {
        const src = r.priority_source || "AUTO";
        if (src === "RULE" && r.matching_rule) {
          return (
            <button
              className="text-xs mono link link-hover"
              onClick={(e) => {
                e.stopPropagation();
                if (r.priority_rule_id) onOpenRules(r.priority_rule_id);
              }}
            >
              RULE · {r.matching_rule}
            </button>
          );
        }
        return <span className="badge badge-ghost badge-xs">{src}</span>;
      },
    },
    {
      key: "exclusion",
      header: "Exclusion",
      render: (r) =>
        r.excluded ? (
          <span className="text-xs">
            Excluded
            {r.exclusion_source ? (
              <span className="text-base-content/50"> · {(r.exclusion_source || "").replace("path_rule", "RULE")}</span>
            ) : null}
          </span>
        ) : (
          <span className="text-xs text-base-content/60">Included</span>
        ),
    },
    {
      key: "qualification",
      header: "Qualification",
      render: (r) => (
        <span className="text-xs">
          {r.qualified ? "Qualified" : "Unqualified"}
          {r.qualification_reason ? (
            <span className="text-base-content/50"> · {r.qualification_reason}</span>
          ) : null}
        </span>
      ),
    },
    {
      key: "baseline",
      header: "Baseline",
      render: (r) =>
        r.baseline_flow_id ? (
          <span className="text-xs mono flex items-center gap-1">
            {r.baseline_status != null && <StatusBadge value={r.baseline_status} />}
            <UuidChip value={r.baseline_flow_id} />
          </span>
        ) : (
          <span className="text-base-content/40 text-xs">—</span>
        ),
    },
    {
      key: "decision",
      header: "Decision",
      render: (r) => <DecisionBadge decision={r.decision} />,
    },
    {
      key: "actions",
      header: "Actions",
      sortable: false,
      alwaysVisible: true,
      defaultWidth: 88,
      minWidth: 64,
      render: (r) => (
        <button
          className="btn btn-xs btn-ghost"
          onClick={(e) => {
            e.stopPropagation();
            openExplain(r.id);
          }}
        >
          Explain
        </button>
      ),
    },
  ];

  return (
    <div>
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2 mb-4">
        <CardStat label="Testable" value={s?.testable ?? "—"} onClick={() => onJumpInventory({ decision: "TESTABLE" })} />
        <CardStat label="Excluded" value={s?.excluded ?? "—"} onClick={() => onJumpInventory({ excluded: "1" })} />
        <CardStat label="Unqualified" value={s?.unqualified ?? "—"} onClick={() => onJumpInventory({ qualified: "0" })} />
        <CardStat label="Manual overrides" value={s?.manual_overrides ?? "—"} onClick={() => onJumpInventory({ priority_source: "MANUAL" })} />
        <CardStat label="Rule controlled" value={s?.rule_controlled ?? "—"} onClick={() => onJumpInventory({ priority_source: "RULE" })} />
        <CardStat label="Auto controlled" value={s?.auto_controlled ?? "—"} onClick={() => onJumpInventory({ priority_source: "AUTO" })} />
      </div>

      <div className="panel p-3 mb-4">
        <div className="text-[10px] uppercase tracking-wide text-base-content/50 font-semibold mb-2">
          Effective priority
        </div>
        <div className="flex flex-wrap gap-4 text-sm">
          {(["CRITICAL", "HIGH", "NORMAL", "LOW"] as const).map((p) => (
            <button
              key={p}
              className="flex items-center gap-2 hover:opacity-80"
              onClick={() => onJumpInventory({ priority: p })}
            >
              <StatusBadge value={p} />
              <span className="tabular-nums font-semibold">{byP[p] ?? 0}</span>
            </button>
          ))}
        </div>
      </div>

      <div className="mb-3">
        <div className="text-xs text-base-content/50 mb-1">Policy problem filters</div>
        <div className="flex flex-wrap gap-1">
          {PROBLEM_FILTERS.map((p) => (
            <button
              key={p.key}
              className={`btn btn-xs ${problem === p.key ? "btn-primary" : "btn-ghost"}`}
              onClick={() => setProblem(problem === p.key ? "" : p.key)}
            >
              {p.label}
            </button>
          ))}
        </div>
      </div>

      <div className="flex gap-2 mb-3">
        <input
          className="input input-xs input-bordered mono w-64"
          placeholder="Search path / host…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
        <span className="text-xs text-base-content/50 self-center">{total} decisions</span>
      </div>

      <DataTable
        columns={columns}
        rows={rows}
        rowKey={(r) => r.id}
        loading={loading}
        storageKey="endpoints-policy"
        onRowClick={(r) => openExplain(r.id)}
        emptyLabel="No policy decisions match these filters."
      />

      {total > PAGE_SIZE && (
        <div className="flex justify-center gap-2 mt-3">
          <button className="btn btn-xs" disabled={offset === 0} onClick={() => setOffset((o) => Math.max(0, o - PAGE_SIZE))}>
            Prev
          </button>
          <button className="btn btn-xs" disabled={offset + PAGE_SIZE >= total} onClick={() => setOffset((o) => o + PAGE_SIZE)}>
            Next
          </button>
        </div>
      )}

      <SideDrawer
        open={!!explainId}
        onClose={() => {
          setExplainId(null);
          setExplain(null);
        }}
        title="Explain policy"
        wide
      >
        <div className="mb-3 flex gap-2">
          <button className="btn btn-xs" onClick={() => explainId && navigate(`/endpoints/${explainId}`)}>
            Open endpoint
          </button>
        </div>
        <PolicyExplain data={explain} />
      </SideDrawer>
    </div>
  );
}
