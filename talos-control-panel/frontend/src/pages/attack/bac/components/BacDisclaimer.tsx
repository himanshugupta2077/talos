/** High-risk active testing notice for BAC. */
export default function BacDisclaimer() {
  return (
    <div className="alert alert-warning text-xs py-2 mb-4">
      <span>
        <strong>Active · high risk.</strong> BAC enqueues live requests using
        attacker-role credentials against target-role flows (session swap,
        method/url/host fuzz, privilege injection, parser probes). Scope with
        Endpoint Policy and the access matrix before large runs. Monitor the{" "}
        <span className="mono">Scheduler</span> while jobs execute.
      </span>
    </div>
  );
}
