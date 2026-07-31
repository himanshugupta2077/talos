/** Active-attack notice for Auth-Session Testing. */
export default function AuthSessionDisclaimer() {
  return (
    <div className="alert alert-warning text-xs py-2 mb-4">
      <span>
        <strong>Active attack · medium risk.</strong> Auth-Session Testing
        mutates a presented credential (JWT structure, algorithm, signature,
        claims, kid) and replays one HTTP request per approved testcase against
        the live target. Use only on authorized bug bounty / client-approved
        scope. Operator must approve candidates before run — pending tests never
        auto-fire.{" "}
        <span className="text-base-content/70">
          WEAK_VALIDATION is evidence of weak token validation, not a freeform
          exploit.
        </span>
      </span>
    </div>
  );
}
