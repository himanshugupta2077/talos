import { useEffect, useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useProject } from "../../state/ProjectContext";
import { api } from "../../api/client";
import { useAction } from "../../hooks/useAction";
import { NoProjectNotice, Section, UuidChip } from "../../components/Common";
import { formatIST } from "../../lib/time";
import SeverityBadge from "./components/SeverityBadge";
import CategoryBadge from "./components/CategoryBadge";
import TechFlags from "./components/TechFlags";
import AttackTypeChip from "./components/AttackTypeChip";
import EvidenceSnippet from "./components/EvidenceSnippet";
import type { ErrorClusterRow, ErrorObservationRow } from "./shared";
import {
  ATTACK_TYPES,
  ERRORS_BASE,
  clusterTitle,
  selectClass,
  shortId,
} from "./shared";
import { IV_BASE, TESTING_BASE } from "../attack/registry";

interface DetailPayload {
  error: ErrorClusterRow;
  observations: ErrorObservationRow[];
  sibling_clusters: ErrorClusterRow[];
}

export default function ErrorClusterDetail() {
  const { errorId } = useParams();
  const { selected } = useProject();
  const [data, setData] = useState<DetailPayload | null>(null);
  const [error, setError] = useState("");
  const [attackFilter, setAttackFilter] = useState("");

  const load = () => {
    if (!selected || !errorId) return;
    api
      .get<DetailPayload>(`/api/error-intel/errors/${errorId}`, {
        project_id: selected.id,
      })
      .then(setData)
      .catch(() => {
        setData(null);
        setError("Error cluster not found");
      });
  };

  useEffect(load, [selected, errorId]);

  const firstFlowId = useMemo(() => {
    const obs = data?.observations || [];
    const withFlow = obs.find((o) => o.flow_id);
    return withFlow?.flow_id || null;
  }, [data]);

  const rescanFlow = useAction("Rescan flow", () =>
    api.post(
      "/api/error-intel/rescan",
      { mode: "flow", id: firstFlowId!, force: false },
      { project_id: selected!.id },
    ),
  );

  const filteredObs = useMemo(() => {
    const obs = data?.observations || [];
    if (!attackFilter) return obs;
    return obs.filter((o) => o.attack_type === attackFilter);
  }, [data, attackFilter]);

  if (!selected) return <NoProjectNotice />;
  if (error && !data) {
    return (
      <div>
        <Link to={`${ERRORS_BASE}?tab=errors`} className="link link-sm">
          back to errors
        </Link>
        <p className="mt-4 text-error">{error}</p>
      </div>
    );
  }
  if (!data) return <div className="loading loading-spinner" />;

  const { error: c, observations, sibling_clusters: siblings } = data;

  return (
    <div>
      <Link
        to={`${ERRORS_BASE}?tab=errors`}
        className="link link-sm mb-4 inline-block"
      >
        ← back to errors
      </Link>

      <div className="mb-4">
        <h1 className="text-xl font-semibold mb-1 flex flex-wrap items-center gap-2">
          {clusterTitle(c)}
        </h1>
        <div className="flex flex-wrap items-center gap-2">
          <SeverityBadge severity={c.severity} />
          <CategoryBadge category={c.category} />
          <span className="badge badge-ghost badge-sm">
            confidence {c.confidence ?? "—"}
          </span>
          <span className="badge badge-ghost badge-sm">
            {c.observation_count} obs
          </span>
          {c.scanner_version && (
            <span className="badge badge-ghost badge-sm mono">
              scanner {c.scanner_version}
            </span>
          )}
        </div>
        <div className="text-xs text-base-content/50 mt-2 flex flex-wrap gap-3 items-center">
          <span className="flex items-center gap-1">
            id <UuidChip value={c.id} />
          </span>
          <span>
            first {c.first_seen ? formatIST(c.first_seen) : "—"} · last{" "}
            {c.last_seen ? formatIST(c.last_seen) : "—"}
          </span>
        </div>
        {c.fingerprint && (
          <div className="mt-2 text-xs">
            <span className="text-base-content/50">fingerprint </span>
            <button
              type="button"
              className="mono link link-hover break-all"
              title="Copy fingerprint"
              onClick={() => navigator.clipboard.writeText(c.fingerprint)}
            >
              {c.fingerprint.length > 24
                ? `${c.fingerprint.slice(0, 24)}…`
                : c.fingerprint}
            </button>
          </div>
        )}
      </div>

      <Section
        title="Actions"
        action={
          <div className="flex flex-wrap gap-2">
            {firstFlowId && (
              <>
                <Link
                  to={`/flows/${firstFlowId}#section=errors`}
                  className="btn btn-xs"
                >
                  Open first flow
                </Link>
                <button
                  className="btn btn-xs"
                  disabled={rescanFlow.running}
                  onClick={async () => {
                    await rescanFlow.run();
                    load();
                  }}
                >
                  Rescan first flow
                </button>
              </>
            )}
            <Link to={`${ERRORS_BASE}?tab=errors`} className="btn btn-xs btn-ghost">
              All errors
            </Link>
          </div>
        }
      >
        <p className="text-xs text-base-content/50">
          Intelligence only — no Findings promotion in v1.
        </p>
      </Section>

      <Section title="Technology">
        <TechFlags cluster={c} />
        {c.technologies?.length > 0 && (
          <div className="flex flex-wrap gap-1 mt-2">
            {c.technologies.map((t) => (
              <span key={t} className="badge badge-outline badge-xs mono">
                {t}
              </span>
            ))}
          </div>
        )}
        {c.message_norm && (
          <p className="text-sm mt-2 text-base-content/70">{c.message_norm}</p>
        )}
      </Section>

      <Section title="Evidence">
        <EvidenceSnippet snippet={c.evidence_snippet} />
      </Section>

      {siblings.length > 0 && (
        <Section title="Sibling clusters (same exception_type)">
          <p className="text-xs text-base-content/50 mb-2">
            Fingerprint may fork by HTTP status bucket — review siblings for the
            same exception (not a full merge).
          </p>
          <ul className="space-y-1 text-sm">
            {siblings.map((s) => (
              <li key={s.id} className="flex flex-wrap items-center gap-2">
                <SeverityBadge severity={s.severity} />
                <Link to={`${ERRORS_BASE}/${s.id}`} className="link">
                  {clusterTitle(s)}
                </Link>
                <span className="text-xs text-base-content/40 mono">
                  {shortId(s.id)} · {s.observation_count} obs
                </span>
              </li>
            ))}
          </ul>
        </Section>
      )}

      <Section
        title="Observations"
        action={
          <select
            className={selectClass}
            value={attackFilter}
            onChange={(e) => setAttackFilter(e.target.value)}
          >
            <option value="">attack_type: any</option>
            {ATTACK_TYPES.map((a) => (
              <option key={a} value={a}>
                {a}
              </option>
            ))}
          </select>
        }
      >
        {filteredObs.length === 0 ? (
          <p className="text-sm text-base-content/50">
            {observations.length === 0
              ? "No observations."
              : "No observations match attack filter."}
          </p>
        ) : (
          <div className="overflow-x-auto">
            <table className="table table-xs">
              <thead>
                <tr>
                  <th>When</th>
                  <th>Attack</th>
                  <th>Status</th>
                  <th>Flow</th>
                  <th>Endpoint</th>
                  <th>Parameter</th>
                  <th>Payload</th>
                  <th>Detectors</th>
                </tr>
              </thead>
              <tbody>
                {filteredObs.map((o) => (
                  <tr key={o.id} className="hover">
                    <td className="text-xs whitespace-nowrap">
                      {o.observed_at ? formatIST(o.observed_at) : "—"}
                    </td>
                    <td>
                      <AttackTypeChip attackType={o.attack_type} />
                    </td>
                    <td className="mono">{o.response_status ?? "—"}</td>
                    <td>
                      {o.flow_id ? (
                        <Link
                          to={`/flows/${o.flow_id}#section=errors`}
                          className="link mono text-xs"
                        >
                          {shortId(o.flow_id)}
                        </Link>
                      ) : (
                        "—"
                      )}
                    </td>
                    <td>
                      {o.endpoint_id ? (
                        <Link
                          to={`/endpoints/${o.endpoint_id}`}
                          className="link mono text-xs"
                        >
                          {shortId(o.endpoint_id)}
                        </Link>
                      ) : (
                        "—"
                      )}
                    </td>
                    <td>
                      {o.parameter_uuid ? (
                        <Link
                          to={`${IV_BASE}/params/${o.parameter_uuid}`}
                          className="link mono text-xs"
                        >
                          {o.parameter_name || shortId(o.parameter_uuid)}
                        </Link>
                      ) : (
                        "—"
                      )}
                    </td>
                    <td className="mono text-xs max-w-[8rem] truncate" title={o.payload_redacted || undefined}>
                      {o.payload_redacted || "—"}
                    </td>
                    <td className="text-xs max-w-[10rem] truncate">
                      {o.detectors?.join(", ") || "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Section>

      <div className="text-xs text-base-content/40 flex flex-wrap gap-3 mt-4">
        <Link to={`${TESTING_BASE}/bac`} className="link">
          BAC workspace
        </Link>
        <Link to={`${TESTING_BASE}/unauth`} className="link">
          Unauth workspace
        </Link>
        <Link to={IV_BASE} className="link">
          Input Validation
        </Link>
      </div>
    </div>
  );
}
