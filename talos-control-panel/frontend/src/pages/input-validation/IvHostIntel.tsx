import { useEffect, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { useProject } from "../../state/ProjectContext";
import { api } from "../../api/client";
import { NoProjectNotice, Section } from "../../components/Common";
import CapabilityBadges from "./components/CapabilityBadges";
import CandidateScore from "./components/CandidateScore";
import IvDisclaimer from "./components/IvDisclaimer";
import { CandidateRow, downloadJson, ProfileRow } from "./shared";

export default function IvHostIntel() {
  const { host: hostParam = "" } = useParams();
  const host = decodeURIComponent(hostParam);
  const { selected } = useProject();
  const navigate = useNavigate();
  const [data, setData] = useState<any>(null);

  useEffect(() => {
    if (!selected || !host) return;
    api
      .get(`/api/input-validation/hosts/${encodeURIComponent(host)}`, {
        project_id: selected.id,
      })
      .then(setData)
      .catch(() => setData(null));
  }, [selected, host]);

  if (!selected) return <NoProjectNotice />;

  const profile = data?.profile;
  const endpoints = data?.endpoints || [];
  const params: ProfileRow[] = data?.parameters || [];
  const candidates: CandidateRow[] = data?.candidates || [];
  const lines: string[] = data?.summary_lines || [];

  return (
    <div>
      <button
        className="btn btn-ghost btn-xs mb-1"
        onClick={() => navigate("/input-validation?tab=multi-level")}
      >
        ← Multi-level
      </button>
      <div className="flex flex-wrap items-start justify-between gap-2 mb-4">
        <div>
          <h1 className="text-xl font-semibold mono">{host}</h1>
          <p className="text-xs text-base-content/50">Application / host intelligence</p>
        </div>
        <button
          className="btn btn-xs"
          onClick={() =>
            downloadJson(`iv-host-${host}.json`, data || {})
          }
        >
          Download JSON
        </button>
      </div>

      <IvDisclaimer />

      <Section title="Summary">
        {lines.length ? (
          <pre className="text-xs whitespace-pre-wrap mono">{lines.join("\n")}</pre>
        ) : (
          <p className="text-xs text-base-content/50">No host profile yet.</p>
        )}
        {profile && (
          <div className="mt-2">
            <CapabilityBadges caps={profile.capabilities} />
          </div>
        )}
      </Section>

      <Section title={`Candidates on host (${candidates.length})`}>
        <div className="overflow-x-auto panel">
          <table className="table table-tight table-xs">
            <thead>
              <tr>
                <th>Name</th>
                <th>Attack</th>
                <th>Score</th>
                <th>Reason</th>
              </tr>
            </thead>
            <tbody>
              {candidates.map((c, i) => (
                <tr
                  key={`${c.param_uuid}-${c.attack}-${i}`}
                  className="cursor-pointer hover:bg-base-200"
                  onClick={() =>
                    c.param_uuid &&
                    navigate(`/input-validation/params/${c.param_uuid}`)
                  }
                >
                  <td className="mono">{c.name}</td>
                  <td className="mono">{c.attack}</td>
                  <td>
                    <CandidateScore score={c.score} confidence={c.confidence} />
                  </td>
                  <td className="text-xs max-w-xs truncate">
                    {(c.reasons || [])[0] || "—"}
                  </td>
                </tr>
              ))}
              {candidates.length === 0 && (
                <tr>
                  <td colSpan={4} className="text-center text-base-content/40 py-4">
                    No candidates for this host.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </Section>

      <Section title={`Endpoint profiles (${endpoints.length})`}>
        <div className="overflow-x-auto panel">
          <table className="table table-tight table-xs">
            <thead>
              <tr>
                <th>Method</th>
                <th>Path</th>
                <th>Caps</th>
              </tr>
            </thead>
            <tbody>
              {endpoints.map((e: any) => (
                <tr
                  key={e.endpoint_id}
                  className="cursor-pointer hover:bg-base-200"
                  onClick={() =>
                    e.endpoint_id &&
                    navigate(`/input-validation/endpoints/${e.endpoint_id}`)
                  }
                >
                  <td>{e.method || "—"}</td>
                  <td className="mono text-xs">{e.path || "—"}</td>
                  <td>
                    <CapabilityBadges caps={e.capabilities} limit={3} />
                  </td>
                </tr>
              ))}
              {endpoints.length === 0 && (
                <tr>
                  <td colSpan={3} className="text-center text-base-content/40 py-4">
                    No endpoint profiles on this host.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </Section>

      <Section title={`Parameter profiles (${params.length})`}>
        <div className="overflow-x-auto panel">
          <table className="table table-tight table-xs">
            <thead>
              <tr>
                <th>Name</th>
                <th>Loc</th>
                <th>Caps</th>
                <th>Top candidate</th>
              </tr>
            </thead>
            <tbody>
              {params.map((p) => (
                <tr
                  key={p.param_uuid}
                  className="cursor-pointer hover:bg-base-200"
                  onClick={() =>
                    p.param_uuid &&
                    navigate(`/input-validation/params/${p.param_uuid}`)
                  }
                >
                  <td className="mono">{p.name}</td>
                  <td>{p.location}</td>
                  <td>
                    <CapabilityBadges caps={p.capabilities} limit={3} />
                  </td>
                  <td className="mono text-xs">
                    {p.top_candidate
                      ? `${p.top_candidate.attack} ${p.top_candidate.score}`
                      : "—"}
                  </td>
                </tr>
              ))}
              {params.length === 0 && (
                <tr>
                  <td colSpan={4} className="text-center text-base-content/40 py-4">
                    No parameter profiles.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </Section>
    </div>
  );
}
