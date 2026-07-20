import { useEffect, useState } from "react";
import { useParams, Link } from "react-router-dom";
import { useProject } from "../state/ProjectContext";
import { api } from "../api/client";
import { useAction } from "../hooks/useAction";
import { Section, UuidChip } from "../components/Common";
import StatusBadge from "../components/StatusBadge";
import { formatIST } from "../lib/time";
import { Finding, FindingGroup } from "../types";

interface Bundle {
  finding: Finding;
  evidence: { id: string; evidence_type: string; reference_id: string | null; label: string; data: any; created_at: string }[];
  timeline: { id: string; event: string; actor: string; created_at: string }[];
  duplicates: Finding[];
}

export default function FindingDetail() {
  const { findingId } = useParams();
  const { selected } = useProject();
  const [bundle, setBundle] = useState<Bundle | null>(null);
  const [groups, setGroups] = useState<FindingGroup[]>([]);
  const [duplicateOf, setDuplicateOf] = useState("");
  const [reportText, setReportText] = useState("");

  const load = () => {
    if (!selected || !findingId) return;
    api.get<Bundle>(`/api/findings/${findingId}`, { project_id: selected.id }).then(setBundle);
    api.get<{ groups: FindingGroup[] }>("/api/findings/groups/list", { project_id: selected.id }).then((r) => setGroups(r.groups));
  };
  useEffect(load, [selected, findingId]);

  const confirm = useAction("Confirm finding", () => api.post(`/api/findings/${findingId}/confirm`, {}, { project_id: selected!.id }));
  const reject = useAction("Reject finding", () => api.post(`/api/findings/${findingId}/reject`, {}, { project_id: selected!.id }));
  const reopen = useAction("Reopen finding", () => api.post(`/api/findings/${findingId}/reopen`, {}, { project_id: selected!.id }));
  const duplicate = useAction("Mark duplicate", () => api.post(`/api/findings/${findingId}/duplicate`, { of: duplicateOf }, { project_id: selected!.id }));
  const addToGroup = useAction("Add to group", (group: string) => api.post("/api/findings/groups/add", { group, finding: findingId }, { project_id: selected!.id }));
  const genReport = useAction("Generate report", async () => {
    const r = await api.get<{ steps: any[] }>(`/api/findings/${findingId}/report`, { project_id: selected!.id });
    return r;
  });

  if (!bundle) return <div className="loading loading-spinner" />;
  const { finding, evidence, timeline, duplicates } = bundle;

  return (
    <div>
      <Link to="/findings" className="link link-sm mb-4 inline-block">back to findings</Link>

      <div className="mb-4">
        <h1 className="text-xl font-semibold mb-1">{finding.title || "(untitled finding)"}</h1>
        <div className="flex items-center gap-2 flex-wrap">
          <StatusBadge value={finding.verdict} />
          <StatusBadge value={finding.status} />
          <span className="text-xs text-base-content/50">{finding.attack_type}</span>
          {finding.role_name && <span className="badge badge-outline badge-sm">role: {finding.role_name}</span>}
          {finding.module_name && <span className="badge badge-outline badge-sm">module: {finding.module_name}</span>}
          {finding.endpoint_id && <Link to={`/endpoints/${finding.endpoint_id}`} className="link text-xs">endpoint</Link>}
        </div>
      </div>

      <Section title="Lifecycle">
        <div className="flex gap-2 flex-wrap items-center">
          {finding.status === "TRIAGING" && (
            <>
              <button className="btn btn-xs btn-success" onClick={async () => { await confirm.run(); load(); }}>Confirm</button>
              <button className="btn btn-xs btn-error" onClick={async () => { await reject.run(); load(); }}>Reject</button>
            </>
          )}
          {finding.status !== "TRIAGING" && (
            <button className="btn btn-xs" onClick={async () => { await reopen.run(); load(); }}>Reopen</button>
          )}
          <div className="flex gap-1 items-center">
            <input className="input input-xs input-bordered mono w-40" placeholder="duplicate-of uuid" value={duplicateOf} onChange={(e) => setDuplicateOf(e.target.value)} />
            <button className="btn btn-xs" disabled={!duplicateOf} onClick={async () => { await duplicate.run(); setDuplicateOf(""); load(); }}>Mark duplicate</button>
          </div>
        </div>
      </Section>

      <Section title="Groups" action={
        <select className="select select-xs select-bordered" value="" onChange={async (e) => { if (e.target.value) { await addToGroup.run(e.target.value); e.target.value = ""; } }}>
          <option value="">Add to group…</option>
          {groups.map((g) => <option key={g.id} value={g.name}>{g.name}</option>)}
        </select>
      }>
        <p className="text-xs text-base-content/50">Manage groups from the Findings list page.</p>
      </Section>

      <Section title="Report" action={
        <button className="btn btn-xs" onClick={async () => {
          const r: any = await genReport.run();
          const step = r?.steps?.[0];
          setReportText(step?.stdout || step?.stderr || "");
        }}>Generate</button>
      }>
        {reportText && <pre className="panel p-3 mono text-xs whitespace-pre-wrap max-h-96 overflow-y-auto">{reportText}</pre>}
      </Section>

      <Section title={`Evidence (${evidence.length})`}>
        <div className="space-y-2">
          {evidence.map((e) => {
            const isFlowRef = ["original_flow", "replay_flow", "diff"].includes(e.evidence_type);
            return (
              <div key={e.id} className="panel p-3">
                <div className="flex items-center gap-2 text-xs mb-1">
                  <span className="badge badge-outline badge-xs">{e.evidence_type}</span>
                  <span className="text-base-content/50">{e.created_at}</span>
                  {e.reference_id && (
                    isFlowRef ? (
                      <Link to={`/flows/${e.reference_id}`} className="link">
                        <UuidChip value={e.reference_id} />
                      </Link>
                    ) : (
                      <UuidChip value={e.reference_id} />
                    )
                  )}
                </div>
                <div className="text-sm">{e.label}</div>
                {Object.keys(e.data || {}).length > 0 && (
                  <pre className="mono text-xs mt-1 text-base-content/60">{JSON.stringify(e.data, null, 2)}</pre>
                )}
              </div>
            );
          })}
          {evidence.length === 0 && <div className="text-sm text-base-content/40">No evidence recorded.</div>}
        </div>
      </Section>

      <Section title="Timeline">
        <ul className="space-y-1">
          {timeline.map((t) => (
            <li key={t.id} className="text-sm flex gap-2">
              <span className="text-base-content/40 text-xs mono w-40 shrink-0">{formatIST(t.created_at)}</span>
              <span className={`badge badge-xs ${t.actor === "system" ? "badge-ghost" : "badge-info"}`}>{t.actor}</span>
              <span>{t.event}</span>
            </li>
          ))}
          {timeline.length === 0 && <div className="text-sm text-base-content/40">No timeline events.</div>}
        </ul>
      </Section>

      {duplicates.length > 0 && (
        <Section title="Duplicates of this finding">
          <ul className="space-y-1">
            {duplicates.map((d) => (
              <li key={d.id}>
                <Link to={`/findings/${d.id}`} className="link text-sm">{d.title || d.id}</Link>
              </li>
            ))}
          </ul>
        </Section>
      )}
    </div>
  );
}
