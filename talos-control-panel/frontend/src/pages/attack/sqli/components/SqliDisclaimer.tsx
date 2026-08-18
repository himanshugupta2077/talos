export default function SqliDisclaimer() {
  return (
    <div className="alert alert-warning text-xs py-2 mb-4">
      <span>
        SQLi testing sends outbound requests with mutated query, JSON, and form
        values. Each payload stores a unique replay flow. Findings are created
        only when a probe shows a <strong>new</strong> DBMS error versus the
        captured baseline, a UNION column-count leak, or a time delay. A
        pre-existing conversion error on the baseline is not itself a finding.
      </span>
    </div>
  );
}
