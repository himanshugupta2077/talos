import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useProject } from "../../state/ProjectContext";
import { api } from "../../api/client";
import { useAction } from "../../hooks/useAction";
import { NoProjectNotice, Section, UuidChip } from "../../components/Common";
import { formatIST } from "../../lib/time";
import ConfidenceChip from "./components/ConfidenceChip";
import CategoryBadge from "./components/CategoryBadge";
import RedactedValue from "./components/RedactedValue";
import type { DetectionRow, DocumentRow, OccurrenceRow } from "./shared";
import { shortId } from "./shared";

interface DetailPayload {
  detection: DetectionRow;
  siblings: DetectionRow[];
  document: DocumentRow | null;
  occurrence: OccurrenceRow | null;
}

export default function DetectionDetail() {
  const { detectionId } = useParams();
  const { selected } = useProject();
  const [data, setData] = useState<DetailPayload | null>(null);
  const [error, setError] = useState("");

  const load = () => {
    if (!selected || !detectionId) return;
    api
      .get<DetailPayload>(`/api/passive/detections/${detectionId}`, {
        project_id: selected.id,
      })
      .then(setData)
      .catch(() => {
        setData(null);
        setError("Detection not found");
      });
  };

  useEffect(load, [selected, detectionId]);

  const rescanDoc = useAction("Rescan document", () =>
    api.post(
      "/api/passive/rescan",
      { mode: "document", id: data!.detection.document_id, force: true },
      { project_id: selected!.id },
    ),
  );

  if (!selected) return <NoProjectNotice />;
  if (error && !data) {
    return (
      <div>
        <Link to="/secret-detection?tab=detections" className="link link-sm">
          back to detections
        </Link>
        <p className="mt-4 text-error">{error}</p>
      </div>
    );
  }
  if (!data) return <div className="loading loading-spinner" />;

  const { detection: d, siblings, document: doc, occurrence: occ } = data;

  return (
    <div>
      <Link to="/secret-detection?tab=detections" className="link link-sm mb-4 inline-block">
        back to detections
      </Link>

      <div className="mb-4">
        <h1 className="text-xl font-semibold mb-1 flex flex-wrap items-center gap-2">
          <RedactedValue value={d.redacted_value} className="text-base" />
        </h1>
        <div className="flex flex-wrap items-center gap-2">
          <CategoryBadge category={d.category} />
          <ConfidenceChip level={d.confidence_level} score={d.confidence_score} />
          <span className="badge badge-ghost badge-sm mono">{d.detector_id}</span>
          {d.suppressed && (
            <span className="badge badge-warning badge-sm">
              suppressed{d.suppression_reason ? `: ${d.suppression_reason}` : ""}
            </span>
          )}
        </div>
      </div>

      <Section
        title="Actions"
        action={
          <div className="flex gap-2">
            {d.finding_id && (
              <Link to={`/findings/${d.finding_id}`} className="btn btn-xs btn-primary">
                Open finding
              </Link>
            )}
            {occ?.flow_id && (
              <Link to={`/flows/${occ.flow_id}`} className="btn btn-xs">
                Open flow
              </Link>
            )}
            <button
              className="btn btn-xs"
              disabled={rescanDoc.running || !d.document_id}
              onClick={async () => {
                await rescanDoc.run();
                load();
              }}
            >
              Rescan document
            </button>
          </div>
        }
      >
        <p className="text-xs text-base-content/50">
          Secrets are redacted. Raw values are not stored on detection rows.
        </p>
      </Section>

      <Section title="Details">
        <dl className="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-2 text-sm">
          <div>
            <dt className="text-xs text-base-content/50">ID</dt>
            <dd>
              <UuidChip value={d.id} />
            </dd>
          </div>
          <div>
            <dt className="text-xs text-base-content/50">Fingerprint</dt>
            <dd className="mono text-xs break-all">{d.value_fingerprint}</dd>
          </div>
          <div>
            <dt className="text-xs text-base-content/50">Family / type</dt>
            <dd>
              {d.detector_family} · {d.secret_type || "—"}
            </dd>
          </div>
          <div>
            <dt className="text-xs text-base-content/50">Matched key</dt>
            <dd className="mono text-xs">{d.matched_key || "—"}</dd>
          </div>
          <div>
            <dt className="text-xs text-base-content/50">Encoding chain</dt>
            <dd className="mono text-xs">
              {d.encoding_chain?.length ? d.encoding_chain.join(" → ") : "—"}
            </dd>
          </div>
          <div>
            <dt className="text-xs text-base-content/50">Entropy / decode depth</dt>
            <dd>
              {d.entropy ?? "—"} / {d.decode_depth ?? 0}
            </dd>
          </div>
          <div>
            <dt className="text-xs text-base-content/50">Offsets</dt>
            <dd className="mono text-xs">
              {d.match_start ?? 0}–{d.match_end ?? 0}
            </dd>
          </div>
          <div>
            <dt className="text-xs text-base-content/50">Created</dt>
            <dd className="text-xs">
              {d.created_at ? formatIST(d.created_at) : "—"}
            </dd>
          </div>
          <div>
            <dt className="text-xs text-base-content/50">Document</dt>
            <dd>
              {d.document_id ? (
                <Link
                  to={`/secret-detection/documents/${d.document_id}`}
                  className="link mono text-xs"
                >
                  {shortId(d.document_id)}
                  {doc ? ` · ${doc.source_kind}` : ""}
                </Link>
              ) : (
                "—"
              )}
            </dd>
          </div>
          <div>
            <dt className="text-xs text-base-content/50">Finding</dt>
            <dd>
              {d.finding_id ? (
                <Link to={`/findings/${d.finding_id}`} className="link mono text-xs">
                  {d.finding_id}
                </Link>
              ) : (
                <span className="text-base-content/40">none (intelligence only)</span>
              )}
            </dd>
          </div>
        </dl>
      </Section>

      {(d.context_before || d.context_after) && (
        <Section title="Context">
          <pre className="panel p-3 mono text-xs whitespace-pre-wrap break-all max-h-64 overflow-y-auto">
            <span className="text-base-content/50">{d.context_before || ""}</span>
            <span className="bg-warning/30 text-warning-content px-0.5">
              {d.redacted_value}
            </span>
            <span className="text-base-content/50">{d.context_after || ""}</span>
          </pre>
        </Section>
      )}

      {occ && (
        <Section title="Occurrence">
          <div className="text-sm space-y-1">
            <div>
              <span className="text-xs text-base-content/50">URL </span>
              <span className="mono text-xs break-all">{occ.url || "—"}</span>
            </div>
            <div>
              <span className="text-xs text-base-content/50">Path </span>
              <span className="mono text-xs">{occ.path || "—"}</span>
            </div>
            {occ.flow_id && (
              <div>
                <span className="text-xs text-base-content/50">Flow </span>
                <Link to={`/flows/${occ.flow_id}`} className="link mono text-xs">
                  {occ.flow_id}
                </Link>
              </div>
            )}
          </div>
        </Section>
      )}

      {siblings.length > 0 && (
        <Section title={`Same secret elsewhere (${siblings.length})`}>
          <ul className="space-y-1 text-sm">
            {siblings.map((s) => (
              <li key={s.id}>
                <Link
                  to={`/secret-detection/detections/${s.id}`}
                  className="link mono text-xs"
                >
                  {shortId(s.id)}
                </Link>
                <span className="text-base-content/50 text-xs ml-2">
                  doc {shortId(s.document_id)} · {s.confidence_level}
                </span>
              </li>
            ))}
          </ul>
        </Section>
      )}
    </div>
  );
}
