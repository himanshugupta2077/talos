import { useEffect, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { useProject } from "../../state/ProjectContext";
import { api } from "../../api/client";
import { NoProjectNotice, Section, UuidChip } from "../../components/Common";
import CapabilityBadges from "./components/CapabilityBadges";
import StateChip from "./components/StateChip";
import type { ProfileRow } from "./shared";
import { IV_BASE } from "./shared";

export default function IvEndpointIntel() {
  const { endpointId = "" } = useParams();
  const { selected } = useProject();
  const navigate = useNavigate();
  const [data, setData] = useState<any>(null);

  useEffect(() => {
    if (!selected || !endpointId) return;
    api
      .get(`/api/input-validation/endpoints/${endpointId}`, {
        project_id: selected.id,
      })
      .then(setData)
      .catch(() => setData(null));
  }, [selected, endpointId]);

  if (!selected) return <NoProjectNotice />;

  const meta = data?.meta || {};
  const profile = data?.profile;
  const params: ProfileRow[] = data?.parameters || [];
  const lines: string[] = data?.summary_lines || [];

  return (
    <div>
      <button
        className="btn btn-ghost btn-xs mb-1"
        onClick={() => navigate(`${IV_BASE}?tab=multi-level`)}
      >
        ← Multi-level
      </button>
      <h1 className="text-xl font-semibold mb-1">
        Endpoint intelligence{" "}
        <span className="text-sm font-normal text-base-content/50 mono">
          {meta.method} {meta.path || ""}
        </span>
      </h1>
      <div className="flex flex-wrap gap-2 text-xs mb-4">
        <span className="mono">{meta.host || profile?.host || "—"}</span>
        <UuidChip value={endpointId} />
      </div>

      {data?.error && (
        <div className="alert alert-warning text-xs mb-3">{data.error}</div>
      )}

      <Section title="Summary">
        {lines.length ? (
          <pre className="text-xs whitespace-pre-wrap mono">{lines.join("\n")}</pre>
        ) : (
          <p className="text-xs text-base-content/50">
            No endpoint profile yet. Synthesize after probing parameters on this endpoint.
          </p>
        )}
        {profile && (
          <div className="mt-2">
            <CapabilityBadges caps={profile.capabilities} />
          </div>
        )}
      </Section>

      <Section title={`Parameters on endpoint (${params.length})`}>
        <div className="overflow-x-auto panel">
          <table className="table table-tight table-xs">
            <thead>
              <tr>
                <th>Name</th>
                <th>Loc</th>
                <th>Reflection</th>
                <th>Caps</th>
                <th>Updated</th>
              </tr>
            </thead>
            <tbody>
              {params.map((p) => (
                <tr
                  key={p.param_uuid}
                  className="cursor-pointer hover:bg-base-200"
                  onClick={() =>
                    p.param_uuid &&
                    navigate(`${IV_BASE}/params/${p.param_uuid}`)                  }
                >
                  <td className="mono">{p.name}</td>
                  <td>{p.location}</td>
                  <td>
                    <StateChip state={p.reflection_state} kind="reflection" />
                  </td>
                  <td>
                    <CapabilityBadges caps={p.capabilities} limit={3} />
                  </td>
                  <td className="text-xs">{(p.updated_at || "").slice(0, 19)}</td>
                </tr>
              ))}
              {params.length === 0 && (
                <tr>
                  <td colSpan={5} className="text-center text-base-content/40 py-4">
                    No linked parameter profiles.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </Section>

      <details>
        <summary className="cursor-pointer text-xs text-base-content/50">
          Raw endpoint profile JSON
        </summary>
        <pre className="text-[10px] panel p-3 mt-2 overflow-auto max-h-80">
          {JSON.stringify(profile, null, 2)}
        </pre>
      </details>
    </div>
  );
}
