import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../../api/client";
import { Section } from "../../components/Common";
import CapabilityBadges from "./components/CapabilityBadges";
import { IV_BASE } from "./shared";

interface EpRow {
  endpoint_id?: string;
  host?: string;
  method?: string;
  path?: string;
  tested_count?: number;
  parser_known?: boolean;
  capabilities?: string[];
  updated_at?: string;
}

interface HostRow {
  host?: string;
  tested_count?: number;
  capability_count?: number;
  capabilities?: string[];
  endpoint_profile_count?: number;
  updated_at?: string;
}

export default function MultiLevelTab({ projectId }: { projectId: string }) {
  const navigate = useNavigate();
  const [endpoints, setEndpoints] = useState<EpRow[]>([]);
  const [hosts, setHosts] = useState<HostRow[]>([]);

  const load = () => {
    api
      .get<{ endpoints: EpRow[] }>("/api/input-validation/endpoints", {
        project_id: projectId,
        limit: 200,
      })
      .then((r) => setEndpoints(r.endpoints || []))
      .catch(() => setEndpoints([]));
    api
      .get<{ hosts: HostRow[] }>("/api/input-validation/hosts", {
        project_id: projectId,
        limit: 200,
      })
      .then((r) => setHosts(r.hosts || []))
      .catch(() => setHosts([]));
  };

  useEffect(load, [projectId]);

  return (
    <div className="space-y-6">
      <p className="text-xs text-base-content/60">
        Multi-level learning (Module 10): endpoint and host profiles inherit shared
        validation/parser behavior so new parameters spend fewer requests.
      </p>

      <Section title={`Endpoint profiles (${endpoints.length})`}>
        <div className="overflow-x-auto panel">
          <table className="table table-tight table-xs">
            <thead>
              <tr>
                <th>Host</th>
                <th>Method</th>
                <th>Path</th>
                <th>Tested</th>
                <th>Parser</th>
                <th>Caps</th>
                <th>Updated</th>
              </tr>
            </thead>
            <tbody>
              {endpoints.map((e) => (
                <tr
                  key={e.endpoint_id}
                  className="cursor-pointer hover:bg-base-200"
                  onClick={() => {
                    if (e.endpoint_id) {
                      navigate(`${IV_BASE}/endpoints/${e.endpoint_id}`);
                    }
                  }}
                >
                  <td className="mono text-xs">{e.host}</td>
                  <td>{e.method || "—"}</td>
                  <td className="mono text-xs max-w-xs truncate">{e.path || "—"}</td>
                  <td>{e.tested_count ?? 0}</td>
                  <td>{e.parser_known ? "yes" : "—"}</td>
                  <td>
                    <CapabilityBadges caps={e.capabilities} limit={3} />
                  </td>
                  <td className="text-xs">{(e.updated_at || "").slice(0, 19)}</td>
                </tr>
              ))}
              {endpoints.length === 0 && (
                <tr>
                  <td colSpan={7} className="text-center text-base-content/40 py-4">
                    No endpoint profiles. Synthesize after probing parameters on endpoints.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </Section>

      <Section title={`Application / host profiles (${hosts.length})`}>
        <div className="overflow-x-auto panel">
          <table className="table table-tight table-xs">
            <thead>
              <tr>
                <th>Host</th>
                <th>Tested families</th>
                <th>Endpoint profiles</th>
                <th>Caps</th>
                <th>Updated</th>
              </tr>
            </thead>
            <tbody>
              {hosts.map((h) => (
                <tr
                  key={h.host}
                  className="cursor-pointer hover:bg-base-200"
                  onClick={() => {
                    if (h.host) {
                      navigate(`${IV_BASE}/hosts/${encodeURIComponent(h.host)}`);
                    }
                  }}
                >
                  <td className="mono">{h.host}</td>
                  <td>{h.tested_count ?? 0}</td>
                  <td>{h.endpoint_profile_count ?? 0}</td>
                  <td>
                    <CapabilityBadges caps={h.capabilities} limit={4} />
                  </td>
                  <td className="text-xs">{(h.updated_at || "").slice(0, 19)}</td>
                </tr>
              ))}
              {hosts.length === 0 && (
                <tr>
                  <td colSpan={5} className="text-center text-base-content/40 py-4">
                    No host profiles yet.
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
