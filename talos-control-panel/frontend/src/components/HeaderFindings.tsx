import { Link } from "react-router-dom";
import { useStatus } from "../state/StatusContext";

/**
 * Header findings signal — PRIMARY count first, then total (PRIMARY + LINKED).
 * Warning highlight stays on TRIAGING (needs review). Links to Findings.
 */
export default function HeaderFindings() {
  const { findingsPrimary, findingsTotal, findingsTriaging } = useStatus();

  if (findingsPrimary === null || findingsTotal === null) {
    return (
      <span className="btn btn-xs btn-ghost border border-base-300 opacity-60 pointer-events-none">
        Findings: —
      </span>
    );
  }

  const hasOpen = (findingsTriaging ?? 0) > 0;
  const label = `${findingsPrimary} primary, ${findingsTotal} total`;

  return (
    <Link
      to="/findings"
      title={label}
      aria-label={`Findings: ${label}`}
      className={`btn btn-xs gap-1.5 mono ${
        hasOpen ? "btn-warning" : "btn-ghost border border-base-300"
      }`}
    >
      <span
        className={`inline-block w-2 h-2 rounded-full shrink-0 ${
          hasOpen ? "bg-warning-content" : "bg-base-content/30"
        }`}
      />
      Findings: {findingsPrimary} / {findingsTotal}
    </Link>
  );
}
