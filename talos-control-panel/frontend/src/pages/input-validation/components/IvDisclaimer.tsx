export default function IvDisclaimer({ compact = false }: { compact?: boolean }) {
  if (compact) {
    return (
      <span className="text-xs text-base-content/50">
        Prioritization only — not confirmed vulnerabilities.
      </span>
    );
  }
  return (
    <div className="alert alert-info text-xs py-2 mb-3">
      <span>
        Input Validation is a <strong>characterization / intelligence</strong> engine.
        Candidate scores are <strong>prioritization only</strong>, not confirmed vulnerabilities
        and not findings.
      </span>
    </div>
  );
}
