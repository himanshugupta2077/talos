export default function PassiveDisclaimer() {
  return (
    <div className="alert alert-info text-xs py-2 mb-4">
      <span>
        <strong>Passive local analysis</strong> — no outbound secret validation.
        High-confidence secrets become Findings automatically; MEDIUM /
        OBSERVATION_ONLY and infrastructure disclosures stay intelligence-only by
        default.
      </span>
    </div>
  );
}
