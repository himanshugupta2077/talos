import { Fragment, useEffect, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { api } from "../../api/client";
import { Section } from "../../components/Common";
import CandidateScore from "./components/CandidateScore";
import IvDisclaimer from "./components/IvDisclaimer";
import {
  ATTACKS,
  CAPABILITY_HINTS,
  CandidateRow,
  downloadJson,
  inputClass,
  IV_BASE,
  selectClass,
} from "./shared";

export default function CandidatesTab({ projectId }: { projectId: string }) {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const [candidates, setCandidates] = useState<CandidateRow[]>([]);
  const [note, setNote] = useState("");
  const [attack, setAttack] = useState(searchParams.get("attack") || "");
  const [minScore, setMinScore] = useState(searchParams.get("min_score") || "60");
  const [minConf, setMinConf] = useState(searchParams.get("min_confidence") || "0");
  const [host, setHost] = useState(searchParams.get("host") || "");
  const [capability, setCapability] = useState(searchParams.get("capability") || "");
  const [search, setSearch] = useState(searchParams.get("q") || "");
  const [expanded, setExpanded] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const load = () => {
    setLoading(true);
    const q: Record<string, string | number> = {
      project_id: projectId,
      min_score: Number(minScore) || 0,
      min_confidence: Number(minConf) || 0,
      limit: 200,
    };
    if (attack) q.attack = attack;
    if (host) q.host = host;
    if (capability) q.capability = capability;
    if (search) q.search = search;
    api
      .get<{ candidates: CandidateRow[]; count: number; note?: string }>(
        "/api/input-validation/candidates",
        q,
      )
      .then((r) => {
        setCandidates(r.candidates || []);
        setNote(r.note || "");
      })
      .catch(() => setCandidates([]))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [projectId]);

  const applyFilters = () => {
    const next = new URLSearchParams(searchParams);
    next.set("tab", "candidates");
    if (attack) next.set("attack", attack);
    else next.delete("attack");
    next.set("min_score", minScore);
    if (host) next.set("host", host);
    else next.delete("host");
    if (capability) next.set("capability", capability);
    else next.delete("capability");
    if (search) next.set("q", search);
    else next.delete("q");
    setSearchParams(next, { replace: true });
    load();
  };

  return (
    <div>
      <IvDisclaimer />
      <Section title={`Attack candidates (${candidates.length})`}>
        <div className="flex flex-wrap gap-2 mb-3 items-center">
          <select className={selectClass} value={attack} onChange={(e) => setAttack(e.target.value)}>
            {ATTACKS.map((a) => (
              <option key={a || "all"} value={a}>
                {a || "all attacks"}
              </option>
            ))}
          </select>
          <input
            className={`${inputClass} w-24`}
            value={minScore}
            onChange={(e) => setMinScore(e.target.value)}
            placeholder="min score"
            title="min score"
          />
          <input
            className={`${inputClass} w-24`}
            value={minConf}
            onChange={(e) => setMinConf(e.target.value)}
            placeholder="min conf"
            title="min confidence"
          />
          <input
            className={`${inputClass} w-40 mono`}
            value={host}
            onChange={(e) => setHost(e.target.value)}
            placeholder="host"
          />
          <input
            className={`${inputClass} w-44 mono`}
            value={capability}
            onChange={(e) => setCapability(e.target.value)}
            placeholder="capability (e.g. network_resource_sink)"
            list="iv-capability-hints"
            title="Filter by capability flag (server-side). Sink caps are prioritization only."
          />
          <datalist id="iv-capability-hints">
            {CAPABILITY_HINTS.map((h) => (
              <option key={h} value={h} />
            ))}
          </datalist>
          <div className="flex flex-wrap gap-1 text-[10px]">
            <button
              type="button"
              className="btn btn-ghost btn-xs"
              title="Preset: SSRF candidates ≥60"
              onClick={() => {
                setAttack("ssrf");
                setMinScore("60");
                setCapability("");
              }}
            >
              ssrf≥60
            </button>
            <button
              type="button"
              className="btn btn-ghost btn-xs"
              title="Preset: open redirect candidates ≥60"
              onClick={() => {
                setAttack("open_redirect");
                setMinScore("60");
                setCapability("");
              }}
            >
              redirect≥60
            </button>
            <button
              type="button"
              className="btn btn-ghost btn-xs"
              title="Preset: network_resource_sink capability"
              onClick={() => {
                setAttack("");
                setCapability("network_resource_sink");
                setMinScore("60");
              }}
            >
              NRS cap
            </button>
          </div>
          <input
            className={`${inputClass} w-40`}
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="search name…"
          />
          <button className="btn btn-xs btn-primary" onClick={applyFilters} disabled={loading}>
            Apply
          </button>
          <button className="btn btn-xs" onClick={load} disabled={loading}>
            Refresh
          </button>
          <button
            className="btn btn-xs"
            onClick={() =>
              downloadJson(`iv-candidates-${projectId}.json`, {
                candidates,
                note,
              })
            }
          >
            Download JSON
          </button>
        </div>
        {note && <p className="text-xs text-base-content/50 mb-2">{note}</p>}

        <div className="overflow-x-auto panel">
          <table className="table table-tight table-xs">
            <thead>
              <tr>
                <th>Host</th>
                <th>Name</th>
                <th>Loc</th>
                <th>Attack</th>
                <th>Score</th>
                <th>Reason</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {candidates.map((c, i) => {
                const key = `${c.param_uuid}-${c.attack}-${i}`;
                const open = expanded === key;
                return (
                  <Fragment key={key}>
                    <tr
                      className="cursor-pointer hover:bg-base-200"
                      onClick={() => setExpanded(open ? null : key)}
                    >
                      <td className="mono text-xs">{c.host}</td>
                      <td className="mono">{c.name}</td>
                      <td>{c.location}</td>
                      <td className="mono">{c.attack}</td>
                      <td>
                        <CandidateScore score={c.score} confidence={c.confidence} />
                      </td>
                      <td className="max-w-xs truncate text-xs">
                        <div className="truncate">{(c.reasons || [])[0] || "—"}</div>
                        {(c.reflection_modes || []).includes("cross_flow") && (
                          <span className="badge badge-warning badge-outline badge-xs mt-0.5">
                            stored
                          </span>
                        )}
                      </td>
                      <td>
                        {c.param_uuid && (
                          <button
                            className="btn btn-ghost btn-xs"
                            onClick={(e) => {
                              e.stopPropagation();
                              navigate(`${IV_BASE}/params/${c.param_uuid}`);
                            }}
                          >
                            Open
                          </button>
                        )}
                      </td>
                    </tr>
                    {open && (
                      <tr className="bg-base-200/40">
                        <td colSpan={7} className="text-xs p-3">
                          {(c.reflection_modes || []).length > 0 && (
                            <>
                              <div className="font-medium mb-1">Reflection modes</div>
                              <div className="flex flex-wrap gap-1 mb-2">
                                {(c.reflection_modes || []).map((m) => (
                                  <span key={m} className="badge badge-ghost badge-xs mono">
                                    {m}
                                  </span>
                                ))}
                              </div>
                            </>
                          )}
                          <div className="font-medium mb-1">Reasons</div>
                          <ul className="list-disc list-inside mb-2">
                            {(c.reasons || []).map((r, j) => (
                              <li key={j}>{r}</li>
                            ))}
                            {!(c.reasons || []).length && <li className="text-base-content/40">—</li>}
                          </ul>
                          {c.stored_reflection &&
                            (c.stored_reflection.sinks || []).length > 0 && (
                              <>
                                <div className="font-medium mb-1">
                                  Stored / cross-page sinks{" "}
                                  <span className="font-normal text-base-content/50">
                                    (data-flow evidence, not XSS)
                                  </span>
                                </div>
                                <ul className="list-disc list-inside mb-2 mono">
                                  {(c.stored_reflection.sinks || []).map((s, j) => (
                                    <li key={j}>
                                      {s.reason ||
                                        `${s.method || ""} ${s.path || ""} (${s.context || "other"}, ${s.encoding || "raw"})`.trim()}
                                      {s.flow_id && (
                                        <>
                                          {" "}
                                          <Link className="link" to={`/flows/${s.flow_id}`}>
                                            {s.flow_id.slice(0, 8)}
                                          </Link>
                                        </>
                                      )}
                                    </li>
                                  ))}
                                </ul>
                              </>
                            )}
                          {(c.evidence_flow_ids || []).length > 0 && (
                            <>
                              <div className="font-medium mb-1">Evidence flows</div>
                              <div className="flex flex-wrap gap-2">
                                {(c.evidence_flow_ids || []).map((fid) => (
                                  <Link key={fid} className="link mono" to={`/flows/${fid}`}>
                                    {fid.slice(0, 8)}
                                  </Link>
                                ))}
                              </div>
                            </>
                          )}
                        </td>
                      </tr>
                    )}
                  </Fragment>
                );
              })}
              {candidates.length === 0 && (
                <tr>
                  <td colSpan={7} className="text-center text-base-content/40 py-6">
                    No candidates. Run IV, synthesize, or lower min score.
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
