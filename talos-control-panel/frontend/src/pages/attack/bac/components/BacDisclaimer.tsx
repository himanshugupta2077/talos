/** High-risk active testing notice for BAC. */
export default function BacDisclaimer({
  authMode,
}: {
  authMode?: string;
}) {
  const ntlm = authMode === "platform_ntlm";
  return (
    <div className="alert alert-warning text-xs py-2 mb-4">
      <span>
        <strong>Active · high risk.</strong>{" "}
        {ntlm ? (
          <>
            This is a <strong>Windows / NTLM</strong> project. BAC sends live
            requests as the attacker role’s bound NTLM profile (fresh handshake)
            against target-role URLs. Recipes mutate the HTTP request after
            identity is set — they do not replay captured{" "}
            <span className="mono">Authorization</span> blobs.
          </>
        ) : (
          <>
            BAC enqueues live requests using attacker-role cookies/headers
            against target-role flows (session swap, method/url/host fuzz,
            privilege injection, parser probes).
          </>
        )}{" "}
        Scope with Endpoint Policy, the access matrix, and role privilege
        ranks (0 = highest) before large runs. Privilege-diff candidates
        come from endpoints a higher role mapped and a lower role did not.
        Monitor the <span className="mono">Scheduler</span> while jobs execute.
      </span>
    </div>
  );
}
