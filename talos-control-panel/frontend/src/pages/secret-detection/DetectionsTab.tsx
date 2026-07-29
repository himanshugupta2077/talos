import { useCallback, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../../api/client";
import DataTable, { Column } from "../../components/DataTable";
import { formatIST } from "../../lib/time";
import ConfidenceChip from "./components/ConfidenceChip";
import CategoryBadge from "./components/CategoryBadge";
import RedactedValue from "./components/RedactedValue";
import {
  CATEGORIES,
  CONFIDENCE_LEVELS,
  DetectionRow,
  SECRETS_BASE,
  selectClass,
  shortId,
} from "./shared";

export default function DetectionsTab({ projectId }: { projectId: string }) {
  const navigate = useNavigate();
  const [rows, setRows] = useState<DetectionRow[]>([]);
  const [category, setCategory] = useState("");
  const [confidence, setConfidence] = useState("");
  const [secretType, setSecretType] = useState("");
  const [hasFinding, setHasFinding] = useState("");
  const [suppressed, setSuppressed] = useState(false);
  const [limit, setLimit] = useState(50);
  const [loading, setLoading] = useState(false);

  const load = useCallback(() => {
    setLoading(true);
    const params: Record<string, string | number | boolean> = {
      project_id: projectId,
      limit,
    };
    if (category) params.category = category;
    if (confidence) params.confidence = confidence;
    if (secretType) params.type = secretType;
    if (hasFinding === "yes") params.has_finding = true;
    if (hasFinding === "no") params.has_finding = false;
    if (suppressed) params.suppressed = true;

    api
      .get<{ detections: DetectionRow[] }>("/api/passive/detections", params)
      .then((r) => setRows(r.detections || []))
      .catch(() => setRows([]))
      .finally(() => setLoading(false));
  }, [projectId, category, confidence, secretType, hasFinding, suppressed, limit]);

  useEffect(() => {
    load();
  }, [load]);

  const columns: Column<DetectionRow>[] = [
    {
      key: "redacted_value",
      header: "Value",
      render: (d) => <RedactedValue value={d.redacted_value} />,
    },
    {
      key: "detector_id",
      header: "Detector",
      render: (d) => <span className="mono text-xs">{d.detector_id}</span>,
    },
    {
      key: "category",
      header: "Category",
      render: (d) => <CategoryBadge category={d.category} />,
    },
    {
      key: "confidence_level",
      header: "Confidence",
      render: (d) => (
        <ConfidenceChip level={d.confidence_level} score={d.confidence_score} />
      ),
    },
    {
      key: "encoding_chain",
      header: "Encoding",
      render: (d) =>
        d.encoding_chain?.length ? (
          <span className="badge badge-ghost badge-xs mono">
            {d.encoding_chain.join("→")}
          </span>
        ) : (
          <span className="text-base-content/30">—</span>
        ),
    },
    {
      key: "finding_id",
      header: "Finding",
      render: (d) =>
        d.finding_id ? (
          <span className="mono text-xs text-success">{shortId(d.finding_id)}</span>
        ) : (
          <span className="text-base-content/30">—</span>
        ),
    },
    {
      key: "created_at",
      header: "Created",
      className: "text-xs",
      sortValue: (d) => d.created_at || "",
      render: (d) => (d.created_at ? formatIST(d.created_at) : "—"),
    },
  ];

  return (
    <div>
      <div className="flex flex-wrap gap-2 mb-4 items-center">
        <select
          className={selectClass}
          value={category}
          onChange={(e) => setCategory(e.target.value)}
        >
          <option value="">category: any</option>
          {CATEGORIES.filter(Boolean).map((c) => (
            <option key={c} value={c}>
              {c}
            </option>
          ))}
        </select>
        <select
          className={selectClass}
          value={confidence}
          onChange={(e) => setConfidence(e.target.value)}
        >
          <option value="">confidence: any</option>
          {CONFIDENCE_LEVELS.filter(Boolean).map((c) => (
            <option key={c} value={c}>
              {c}
            </option>
          ))}
        </select>
        <input
          className="input input-xs input-bordered w-40"
          placeholder="type / detector"
          value={secretType}
          onChange={(e) => setSecretType(e.target.value)}
        />
        <select
          className={selectClass}
          value={hasFinding}
          onChange={(e) => setHasFinding(e.target.value)}
        >
          <option value="">finding: any</option>
          <option value="yes">has finding</option>
          <option value="no">no finding</option>
        </select>
        <label className="label cursor-pointer gap-1 py-0">
          <input
            type="checkbox"
            className="checkbox checkbox-xs"
            checked={suppressed}
            onChange={(e) => setSuppressed(e.target.checked)}
          />
          <span className="label-text text-xs">suppressed only</span>
        </label>
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
          {loading ? "Loading…" : `${rows.length} row(s)`}
        </span>
      </div>

      <DataTable
        columns={columns}
        rows={rows}
        rowKey={(d) => d.id}
        onRowClick={(d) => navigate(`${SECRETS_BASE}/detections/${d.id}`)}
        emptyLabel="No detections match filters."
        storageKey="passive-detections"
      />
    </div>
  );
}
