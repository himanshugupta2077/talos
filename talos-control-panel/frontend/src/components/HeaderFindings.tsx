import { Link } from "react-router-dom";
import { useStatus } from "../state/StatusContext";

/**
 * Header findings signal — clearly defined as TRIAGING count (needs review).
 * Links to Findings.
 */
export default function HeaderFindings() {
  const { findingsTriaging } = useStatus();

  if (findingsTriaging === null) {
    return (
      <span className="btn btn-xs btn-ghost border border-base-300 opacity-60 pointer-events-none">
        Findings: —
      </span>
    );
  }

  const hasOpen = findingsTriaging > 0;

  return (
    <Link
      to="/findings"
      className={`btn btn-xs gap-1.5 mono ${
        hasOpen ? "btn-warning" : "btn-ghost border border-base-300"
      }`}
    >
      <span
        className={`inline-block w-2 h-2 rounded-full shrink-0 ${
          hasOpen ? "bg-warning-content" : "bg-base-content/30"
        }`}
      />
      Findings: {findingsTriaging}
    </Link>
  );
}
