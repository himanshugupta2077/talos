import { useEffect, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { api } from "../../api/client";
import { Section } from "../../components/Common";
import {
  InventoryOnlyBadge,
  NrsBadge,
  UrlScoreChip,
} from "../../components/url-sink";
import CapabilityBadges from "./components/CapabilityBadges";
import CandidateScore from "./components/CandidateScore";
import StateChip from "./components/StateChip";
import {
  CAPABILITY_HINTS,
  LOCATIONS,
  ProfileRow,
  inputClass,
  IV_BASE,
  selectClass,
} from "./shared";

export default function ParametersTab({ projectId }: { projectId: string }) {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const [profiles, setProfiles] = useState<ProfileRow[]>([]);
  const [host, setHost] = useState(searchParams.get("host") || "");
  const [location, setLocation] = useState(searchParams.get("location") || "");
  const [capability, setCapability] = useState(searchParams.get("capability") || "");
  const [search, setSearch] = useState(searchParams.get("q") || "");
  const [hasCands, setHasCands] = useState(searchParams.get("has_candidates") || "");
  const [loading, setLoading] = useState(false);

  const load = () => {
    setLoading(true);
    const q: Record<string, string | number | boolean> = {
      project_id: projectId,
      limit: 300,
    };
    if (host) q.host = host;
    if (location) q.location = location;
    if (capability) q.capability = capability;
    if (search) q.search = search;
    if (hasCands === "1") q.has_candidates = true;
    if (hasCands === "0") q.has_candidates = false;
    api
      .get<{ profiles: ProfileRow[]; count: number }>(
        "/api/input-validation/profiles",
        q as any,
      )
      .then((r) => setProfiles(r.profiles || []))
      .catch(() => setProfiles([]))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [projectId]);

  const apply = () => {
    const next = new URLSearchParams(searchParams);
    next.set("tab", "parameters");
    if (host) next.set("host", host);
    else next.delete("host");
    if (location) next.set("location", location);
    else next.delete("location");
    if (capability) next.set("capability", capability);
    else next.delete("capability");
    if (search) next.set("q", search);
    else next.delete("q");
    if (hasCands) next.set("has_candidates", hasCands);
    else next.delete("has_candidates");
    setSearchParams(next, { replace: true });
    load();
  };

  return (
    <Section title={`Parameter intelligence (${profiles.length})`}>
      <div className="flex flex-wrap gap-2 mb-3 items-center">
        <input
          className={`${inputClass} w-40 mono`}
          value={host}
          onChange={(e) => setHost(e.target.value)}
          placeholder="host"
        />
        <select className={selectClass} value={location} onChange={(e) => setLocation(e.target.value)}>
          {LOCATIONS.map((l) => (
            <option key={l || "all"} value={l}>
              {l || "all locations"}
            </option>
          ))}
        </select>
        <input
          className={`${inputClass} w-36 mono`}
          value={capability}
          onChange={(e) => setCapability(e.target.value)}
          placeholder="capability"
          list="iv-param-capability-hints"
          title="Filter by capability (e.g. network_resource_sink)"
        />
        <datalist id="iv-param-capability-hints">
          {CAPABILITY_HINTS.map((h) => (
            <option key={h} value={h} />
          ))}
        </datalist>
        <select className={selectClass} value={hasCands} onChange={(e) => setHasCands(e.target.value)}>
          <option value="">candidates: any</option>
          <option value="1">has candidates</option>
          <option value="0">no candidates</option>
        </select>
        <input
          className={`${inputClass} w-40`}
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="search name…"
        />
        <button className="btn btn-xs btn-primary" onClick={apply} disabled={loading}>
          Apply
        </button>
        <button className="btn btn-xs" onClick={load} disabled={loading}>
          Refresh
        </button>
      </div>

      <div className="overflow-x-auto panel">
        <table className="table table-tight table-xs">
          <thead>
            <tr>
              <th>Host</th>
              <th>Name</th>
              <th>Loc</th>
              <th title="Passive URL sink score">URL</th>
              <th title="possible_network_resource">NRS</th>
              <th>Reflection</th>
              <th>Type</th>
              <th>Length</th>
              <th>Caps</th>
              <th>Top candidate</th>
              <th>Req</th>
              <th>Updated</th>
            </tr>
          </thead>
          <tbody>
            {profiles.map((p) => (
              <tr
                key={p.param_uuid}
                className="cursor-pointer hover:bg-base-200"
                onClick={() => {
                  if (p.param_uuid) {
                    navigate(`${IV_BASE}/params/${p.param_uuid}`);
                  }
                }}
              >
                <td className="mono text-xs">{p.host}</td>
                <td className="mono">
                  <span className="inline-flex items-center gap-1">
                    {p.name}
                    {p.inventory_only && <InventoryOnlyBadge />}
                  </span>
                </td>
                <td>{p.location}</td>
                <td>
                  <UrlScoreChip score={p.url_score} />
                </td>
                <td>
                  <NrsBadge nrs={p.possible_network_resource} />
                </td>
                <td>
                  <StateChip state={p.reflection_state} kind="reflection" />
                  <span className="text-base-content/40 ml-1">
                    {p.reflection_confidence ?? ""}
                  </span>
                </td>
                <td className="mono text-xs">{p.primary_type || "—"}</td>
                <td className="text-xs">
                  {p.length_state || "—"}
                  {p.max_accepted_length != null ? ` ≤${p.max_accepted_length}` : ""}
                </td>
                <td>
                  <CapabilityBadges caps={p.capabilities} limit={3} />
                </td>
                <td>
                  {p.top_candidate ? (
                    <div className="flex items-center gap-2">
                      <span className="mono text-xs">{p.top_candidate.attack}</span>
                      <CandidateScore
                        score={p.top_candidate.score}
                        confidence={p.top_candidate.confidence}
                        showLabel={false}
                      />
                      <span className="text-xs">{p.top_candidate.score}</span>
                    </div>
                  ) : (
                    "—"
                  )}
                </td>
                <td>{p.requests_used ?? "—"}</td>
                <td className="text-xs">{(p.updated_at || "").slice(0, 19)}</td>
              </tr>
            ))}
            {profiles.length === 0 && (
              <tr>
                <td colSpan={12} className="text-center text-base-content/40 py-6">
                  No profiles yet. Run IV then Synthesize.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </Section>
  );
}
