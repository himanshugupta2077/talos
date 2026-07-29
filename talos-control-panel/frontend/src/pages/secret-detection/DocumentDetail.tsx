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
import StaleVersionBadge from "./components/StaleVersionBadge";
import type { DetectionRow, DocumentRow, OccurrenceRow } from "./shared";
import { formatBytes, SECRETS_BASE, shortId } from "./shared";

interface DetailPayload {
  document: DocumentRow;
  occurrences: OccurrenceRow[];
  detections: DetectionRow[];
  children: DocumentRow[];
  scanner_version: string;
}

export default function DocumentDetail() {
  const { documentId } = useParams();
  const { selected } = useProject();
  const [data, setData] = useState<DetailPayload | null>(null);
  const [error, setError] = useState("");

  const load = () => {
    if (!selected || !documentId) return;
    api
      .get<DetailPayload>(`/api/passive/documents/${documentId}`, {
        project_id: selected.id,
      })
      .then(setData)
      .catch(() => {
        setData(null);
        setError("Document not found");
      });
  };

  useEffect(load, [selected, documentId]);

  const rescan = useAction("Rescan document", () =>
    api.post(
      "/api/passive/rescan",
      { mode: "document", id: data!.document.id, force: true },
      { project_id: selected!.id },
    ),
  );

  if (!selected) return <NoProjectNotice />;
  if (error && !data) {
    return (
      <div>
        <Link to={`${SECRETS_BASE}?tab=documents`} className="link link-sm">
          back to documents
        </Link>
        <p className="mt-4 text-error">{error}</p>
      </div>
    );
  }
  if (!data) return <div className="loading loading-spinner" />;

  const doc = data.document;

  return (
    <div>
      <Link to={`${SECRETS_BASE}?tab=documents`} className="link link-sm mb-4 inline-block">
        back to documents
      </Link>

      <div className="mb-4">
        <h1 className="text-xl font-semibold mb-1 mono text-base">
          {shortId(doc.id, 12)}
        </h1>
        <div className="flex flex-wrap items-center gap-2">
          <span className="badge badge-outline badge-sm">{doc.source_kind}</span>
          <span className="badge badge-ghost badge-sm">{doc.scan_status}</span>
          <StaleVersionBadge
            version={doc.scanner_version}
            current={data.scanner_version}
            stale={doc.stale}
          />
          <span className="text-xs text-base-content/50">
            {formatBytes(doc.body_size)}
          </span>
        </div>
      </div>

      <Section
        title="Actions"
        action={
          <div className="flex gap-2">
            {doc.first_flow_id && (
              <Link to={`/flows/${doc.first_flow_id}`} className="btn btn-xs">
                Open first flow
              </Link>
            )}
            <button
              className="btn btn-xs btn-primary"
              disabled={rescan.running}
              onClick={async () => {
                await rescan.run();
                load();
              }}
            >
              Rescan document
            </button>
          </div>
        }
      >
        <dl className="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-2 text-sm">
          <div>
            <dt className="text-xs text-base-content/50">ID</dt>
            <dd>
              <UuidChip value={doc.id} />
            </dd>
          </div>
          <div>
            <dt className="text-xs text-base-content/50">Body hash</dt>
            <dd className="mono text-xs break-all">{doc.body_hash}</dd>
          </div>
          <div>
            <dt className="text-xs text-base-content/50">Logical name</dt>
            <dd className="text-xs">{doc.logical_source_name || "—"}</dd>
          </div>
          <div>
            <dt className="text-xs text-base-content/50">Parent document</dt>
            <dd>
              {doc.parent_document_id ? (
                <Link
                  to={`${SECRETS_BASE}/documents/${doc.parent_document_id}`}
                  className="link mono text-xs"
                >
                  {shortId(doc.parent_document_id)}
                </Link>
              ) : (
                "—"
              )}
            </dd>
          </div>
          <div>
            <dt className="text-xs text-base-content/50">First seen</dt>
            <dd className="text-xs">
              {doc.first_seen ? formatIST(doc.first_seen) : "—"}
            </dd>
          </div>
          <div>
            <dt className="text-xs text-base-content/50">Last scanned</dt>
            <dd className="text-xs">
              {doc.last_scanned_at ? formatIST(doc.last_scanned_at) : "—"}
            </dd>
          </div>
          {doc.error_message && (
            <div className="sm:col-span-2">
              <dt className="text-xs text-base-content/50">Error</dt>
              <dd className="text-error text-xs">{doc.error_message}</dd>
            </div>
          )}
        </dl>
      </Section>

      <Section title={`Occurrences (${data.occurrences.length})`}>
        {data.occurrences.length === 0 ? (
          <p className="text-sm text-base-content/50">None</p>
        ) : (
          <ul className="space-y-2 text-sm">
            {data.occurrences.map((o) => (
              <li key={o.id} className="panel p-2">
                <div className="mono text-xs break-all">{o.url || o.path || "—"}</div>
                <div className="flex flex-wrap gap-2 mt-1 text-xs text-base-content/60">
                  <span>{o.host}</span>
                  <span>{o.content_type}</span>
                  {o.observed_at && <span>{formatIST(o.observed_at)}</span>}
                  {o.flow_id && (
                    <Link to={`/flows/${o.flow_id}`} className="link">
                      flow {shortId(o.flow_id)}
                    </Link>
                  )}
                </div>
              </li>
            ))}
          </ul>
        )}
      </Section>

      {data.children.length > 0 && (
        <Section title={`Virtual children (${data.children.length})`}>
          <ul className="space-y-1 text-sm">
            {data.children.map((c) => (
              <li key={c.id}>
                <Link
                  to={`${SECRETS_BASE}/documents/${c.id}`}
                  className="link mono text-xs"
                >
                  {shortId(c.id)}
                </Link>
                <span className="text-xs text-base-content/50 ml-2">
                  {c.source_kind}
                  {c.logical_source_name ? ` · ${c.logical_source_name}` : ""}
                </span>
              </li>
            ))}
          </ul>
        </Section>
      )}

      <Section title={`Detections (${data.detections.length})`}>
        {data.detections.length === 0 ? (
          <p className="text-sm text-base-content/50">None on this document</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="table table-xs">
              <thead>
                <tr>
                  <th>Value</th>
                  <th>Detector</th>
                  <th>Cat</th>
                  <th>Confidence</th>
                  <th>Finding</th>
                </tr>
              </thead>
              <tbody>
                {data.detections.map((d) => (
                  <tr key={d.id}>
                    <td>
                      <Link
                        to={`${SECRETS_BASE}/detections/${d.id}`}
                        className="link link-hover"
                      >
                        <RedactedValue value={d.redacted_value} />
                      </Link>
                    </td>
                    <td className="mono text-xs">{d.detector_id}</td>
                    <td>
                      <CategoryBadge category={d.category} />
                    </td>
                    <td>
                      <ConfidenceChip
                        level={d.confidence_level}
                        score={d.confidence_score}
                      />
                    </td>
                    <td>
                      {d.finding_id ? (
                        <Link
                          to={`/findings/${d.finding_id}`}
                          className="link mono text-xs"
                        >
                          {shortId(d.finding_id)}
                        </Link>
                      ) : (
                        "—"
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Section>
    </div>
  );
}
