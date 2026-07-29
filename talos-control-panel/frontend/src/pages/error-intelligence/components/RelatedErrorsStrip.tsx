/**
 * Compact related-errors list for Endpoint / IV parameter cross-links (PR5).
 * Fail-soft: parent should pass rows or null after catch.
 */

import { Link } from "react-router-dom";
import SeverityBadge from "./SeverityBadge";
import CategoryBadge from "./CategoryBadge";
import {
  ERRORS_BASE,
  EndpointRollupRow,
  ParameterRollupRow,
  shortId,
} from "../shared";

type Row = ParameterRollupRow | EndpointRollupRow;

export default function RelatedErrorsStrip({
  rows,
  loading,
  title = "Related errors",
  emptyLabel = "No error intelligence linked yet.",
  limit = 8,
}: {
  rows: Row[] | null;
  loading?: boolean;
  title?: string;
  emptyLabel?: string;
  limit?: number;
}) {
  if (loading) {
    return (
      <div className="panel p-3 text-xs text-base-content/50">
        Loading error intelligence…
      </div>
    );
  }

  if (rows === null) {
    return null; // API failed — fail soft, hide strip
  }

  const shown = rows.slice(0, limit);

  return (
    <div className="panel p-3">
      <div className="flex items-center justify-between mb-2">
        <h3 className="font-semibold text-sm">{title}</h3>
        <Link to={ERRORS_BASE} className="link text-xs">
          Error Intelligence
        </Link>
      </div>
      {shown.length === 0 ? (
        <p className="text-xs text-base-content/50">{emptyLabel}</p>
      ) : (
        <ul className="space-y-1.5">
          {shown.map((r, i) => {
            const errorId = r.error_id ? String(r.error_id) : null;
            const titleText =
              (r.exception_type as string) ||
              (errorId ? shortId(errorId) : "cluster");
            return (
              <li
                key={`${errorId}-${i}`}
                className="flex flex-wrap items-center gap-2 text-sm"
              >
                {r.severity != null && (
                  <SeverityBadge severity={String(r.severity)} />
                )}
                {r.category != null && (
                  <CategoryBadge category={String(r.category)} />
                )}
                {errorId ? (
                  <Link to={`${ERRORS_BASE}/${errorId}`} className="link">
                    {titleText}
                  </Link>
                ) : (
                  <span>{titleText}</span>
                )}
                {r.observation_count != null && (
                  <span className="text-xs text-base-content/40 mono">
                    {String(r.observation_count)} obs
                  </span>
                )}
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}
