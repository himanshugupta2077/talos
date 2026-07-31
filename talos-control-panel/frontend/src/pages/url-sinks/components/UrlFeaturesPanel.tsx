/**
 * Collapsible display of passive url_features for inventory drawer.
 * Uses shared chips from components/url-sink (K15).
 */

import {
  InventoryOnlyBadge,
  NrsBadge,
  SinkCategoryBadge,
  UrlScoreChip,
  isInventoryOnlySurface,
} from "../../../components/url-sink";
import { truncateValue } from "../shared";

export default function UrlFeaturesPanel({
  urlFeatures,
  urlScore,
  nrs,
  nameCategory,
  looksLike,
  location,
  name,
  exampleValues,
  showJson = true,
}: {
  urlFeatures?: Record<string, unknown> | null;
  urlScore?: number | null;
  nrs?: boolean | null;
  nameCategory?: string | null;
  looksLike?: string[];
  location?: string | null;
  name?: string | null;
  exampleValues?: unknown[];
  showJson?: boolean;
}) {
  const uf = urlFeatures && typeof urlFeatures === "object" ? urlFeatures : {};
  const score =
    urlScore != null
      ? urlScore
      : typeof uf.score === "number"
        ? uf.score
        : Number(uf.score) || null;
  const nrsFlag =
    nrs != null
      ? nrs
      : Boolean(uf.possible_network_resource);
  const cat =
    nameCategory ||
    (typeof uf.name_category === "string" ? uf.name_category : null);
  const looks =
    looksLike && looksLike.length
      ? looksLike
      : Array.isArray(uf.looks_like)
        ? (uf.looks_like as string[])
        : [];
  const protocols = Array.isArray(uf.protocols_seen)
    ? (uf.protocols_seen as string[])
    : [];
  const evidence = Array.isArray(uf.evidence)
    ? (uf.evidence as unknown[])
    : [];
  const invOnly = isInventoryOnlySurface(location, name);

  return (
    <div className="space-y-3 text-xs">
      <div className="flex flex-wrap items-center gap-2">
        <UrlScoreChip score={score} />
        <NrsBadge nrs={nrsFlag} />
        <SinkCategoryBadge category={cat} />
        {invOnly && <InventoryOnlyBadge />}
      </div>

      {looks.length > 0 && (
        <div>
          <div className="text-base-content/50 mb-0.5">Looks like</div>
          <div className="flex flex-wrap gap-1">
            {looks.map((l) => (
              <span key={l} className="badge badge-ghost badge-xs mono">
                {l}
              </span>
            ))}
          </div>
        </div>
      )}

      {protocols.length > 0 && (
        <div>
          <div className="text-base-content/50 mb-0.5">Protocols seen</div>
          <div className="flex flex-wrap gap-1">
            {protocols.map((p) => (
              <span key={p} className="badge badge-outline badge-xs mono">
                {p}
              </span>
            ))}
          </div>
        </div>
      )}

      {evidence.length > 0 && (
        <div>
          <div className="text-base-content/50 mb-0.5">Evidence tokens</div>
          <div className="flex flex-wrap gap-1">
            {evidence.slice(0, 12).map((e, i) => (
              <span
                key={`${i}-${String(e)}`}
                className="badge badge-ghost badge-xs mono max-w-full truncate"
                title={String(e)}
              >
                {truncateValue(e, 40)}
              </span>
            ))}
            {evidence.length > 12 && (
              <span className="text-base-content/40">
                +{evidence.length - 12} more
              </span>
            )}
          </div>
        </div>
      )}

      {exampleValues && exampleValues.length > 0 && (
        <div>
          <div className="text-base-content/50 mb-0.5">Sample values</div>
          <ul className="space-y-0.5 mono break-all">
            {exampleValues.slice(0, 6).map((v, i) => (
              <li key={i} title={String(v)}>
                {truncateValue(v, 96)}
              </li>
            ))}
          </ul>
        </div>
      )}

      {showJson && Object.keys(uf).length > 0 && (
        <details className="mt-1">
          <summary className="cursor-pointer text-base-content/60 hover:text-base-content">
            Full url_features JSON
          </summary>
          <pre className="mt-2 p-2 bg-base-200 rounded text-[10px] overflow-x-auto max-h-64">
            {JSON.stringify(uf, null, 2)}
          </pre>
        </details>
      )}

      <p className="text-[10px] text-base-content/45">
        Scores and NRS are prioritization only — not confirmed SSRF or Findings.
      </p>
    </div>
  );
}
