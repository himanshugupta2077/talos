export default function IvDisclaimer({ compact = false }: { compact?: boolean }) {
  if (compact) {
    return (
      <span className="text-xs text-base-content/50">
        Prioritization only — not confirmed vulns. Stored reflection = data-flow evidence.
      </span>
    );
  }
  return (
    <div className="alert alert-info text-xs py-2 mb-3">
      <span>
        Input Validation is a <strong>characterization / intelligence</strong> engine.
        Candidate scores are <strong>prioritization only</strong>, not confirmed vulnerabilities
        and not findings.{" "}
        <strong>Stored / cross-page reflection</strong> is data-flow prioritization
        evidence (source parameter value observed later on another page), not XSS confirmation.
      </span>
    </div>
  );
}
