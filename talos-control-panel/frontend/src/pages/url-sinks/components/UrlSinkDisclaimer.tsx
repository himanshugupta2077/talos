/**
 * Passive inventory disclaimer for URL Sink Discovery module tabs.
 * Characterization / prioritization only — never confirmed Findings.
 */
export default function UrlSinkDisclaimer() {
  return (
    <div className="alert alert-info text-xs py-2 mb-4">
      <span>
        <strong>Passive local analysis</strong> of captured parameter values and
        names — no extra HTTP. Network-resource scores and categories are{" "}
        <strong>prioritization signals</strong>, not confirmed vulnerabilities
        or Findings.
      </span>
    </div>
  );
}
