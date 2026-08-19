export default function XssDisclaimer() {
  return (
    <div className="alert alert-warning text-xs py-2 mb-4">
      <span>
        XSS / HTML injection testing sends outbound requests with mutated query,
        JSON, form, multipart filename, and path values. Payloads typically{" "}
        <strong>append</strong> to the captured field and store a unique replay
        flow (visible in the Talos Burp extension under XSS). Findings
        are created only when the <strong>TalosXss</strong> canary reflects with an{" "}
        unencoded JS sink (XSS) or unencoded HTML markup (HTMLI). Encoded echo (
        <span className="mono">&amp;lt;</span>, <span className="mono">%3C</span>
        ) is not a finding.
      </span>
    </div>
  );
}
