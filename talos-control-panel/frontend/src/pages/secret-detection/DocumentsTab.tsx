import { useCallback, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../../api/client";
import DataTable, { Column } from "../../components/DataTable";
import { formatIST } from "../../lib/time";
import StaleVersionBadge from "./components/StaleVersionBadge";
import {
  DocumentRow,
  SCAN_STATUSES,
  SOURCE_KINDS,
  formatBytes,
  selectClass,
  shortId,
} from "./shared";

export default function DocumentsTab({ projectId }: { projectId: string }) {
  const navigate = useNavigate();
  const [rows, setRows] = useState<DocumentRow[]>([]);
  const [scannerVersion, setScannerVersion] = useState<string>("");
  const [status, setStatus] = useState("");
  const [kind, setKind] = useState("");
  const [limit, setLimit] = useState(50);
  const [loading, setLoading] = useState(false);

  const load = useCallback(() => {
    setLoading(true);
    const params: Record<string, string | number> = {
      project_id: projectId,
      limit,
    };
    if (status) params.status = status;
    if (kind) params.kind = kind;

    api
      .get<{ documents: DocumentRow[]; scanner_version: string }>(
        "/api/passive/documents",
        params,
      )
      .then((r) => {
        setRows(r.documents || []);
        setScannerVersion(r.scanner_version || "");
      })
      .catch(() => setRows([]))
      .finally(() => setLoading(false));
  }, [projectId, status, kind, limit]);

  useEffect(() => {
    load();
  }, [load]);

  const columns: Column<DocumentRow>[] = [
    {
      key: "id",
      header: "ID",
      render: (d) => <span className="mono text-xs">{shortId(d.id)}</span>,
    },
    {
      key: "source_kind",
      header: "Kind",
      render: (d) => <span className="badge badge-ghost badge-xs">{d.source_kind}</span>,
    },
    {
      key: "scan_status",
      header: "Status",
      render: (d) => (
        <span
          className={`badge badge-xs ${
            d.scan_status === "scanned"
              ? "badge-success badge-outline"
              : d.scan_status === "error"
                ? "badge-error badge-outline"
                : "badge-ghost"
          }`}
        >
          {d.scan_status}
        </span>
      ),
    },
    {
      key: "body_size",
      header: "Size",
      render: (d) => formatBytes(d.body_size),
    },
    {
      key: "scanner_version",
      header: "Scanner",
      render: (d) => (
        <StaleVersionBadge
          version={d.scanner_version}
          current={scannerVersion}
          stale={d.stale}
        />
      ),
    },
    {
      key: "logical_source_name",
      header: "Name",
      render: (d) =>
        d.logical_source_name || d.parent_document_id ? (
          <span className="text-xs truncate max-w-[12rem] inline-block">
            {d.logical_source_name || (
              <span className="text-base-content/40">virtual child</span>
            )}
          </span>
        ) : (
          <span className="text-base-content/30">—</span>
        ),
    },
    {
      key: "last_seen",
      header: "Last seen",
      className: "text-xs",
      sortValue: (d) => d.last_seen || "",
      render: (d) => (d.last_seen ? formatIST(d.last_seen) : "—"),
    },
  ];

  return (
    <div>
      <div className="flex flex-wrap gap-2 mb-4 items-center">
        <select
          className={selectClass}
          value={status}
          onChange={(e) => setStatus(e.target.value)}
        >
          <option value="">status: any</option>
          {SCAN_STATUSES.filter(Boolean).map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
        <select
          className={selectClass}
          value={kind}
          onChange={(e) => setKind(e.target.value)}
        >
          <option value="">kind: any</option>
          {SOURCE_KINDS.filter(Boolean).map((k) => (
            <option key={k} value={k}>
              {k}
            </option>
          ))}
        </select>
        <select
          className={selectClass}
          value={limit}
          onChange={(e) => setLimit(Number(e.target.value))}
        >
          {[25, 50, 100, 200].map((n) => (
            <option key={n} value={n}>
              limit {n}
            </option>
          ))}
        </select>
        <button className="btn btn-xs" onClick={load} disabled={loading}>
          Refresh
        </button>
        <span className="text-xs text-base-content/50">
          {loading ? "Loading…" : `${rows.length} document(s)`}
        </span>
      </div>

      <DataTable
        columns={columns}
        rows={rows}
        rowKey={(d) => d.id}
        onRowClick={(d) => navigate(`/secret-detection/documents/${d.id}`)}
        emptyLabel="No source documents yet. Capture traffic with the proxy."
        storageKey="passive-documents"
      />
    </div>
  );
}
