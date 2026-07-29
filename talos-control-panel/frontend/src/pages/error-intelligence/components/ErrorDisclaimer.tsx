export default function ErrorDisclaimer() {
  return (
    <div className="alert alert-info text-xs py-2 mb-4">
      <span>
        <strong>Passive local analysis</strong> of stored HTTP responses — no
        extra requests. <strong>Intelligence only in v1</strong> (no auto
        Findings). Treat evidence snippets as confidential.
      </span>
    </div>
  );
}
