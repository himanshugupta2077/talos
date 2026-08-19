export default function PathTraversalDisclaimer() {
  return (
    <div className="alert alert-warning text-xs py-2 mb-4">
      <span>
        Path traversal / LFI testing sends outbound requests with mutated query,
        JSON, form, multipart filename, and path values. Each payload{" "}
        <strong>replaces</strong> the captured field and stores a unique replay
        flow (visible in the Talos Burp extension under Path Traversal). Findings
        are created only when a probe leaks a <strong>well-known file</strong>{" "}
        that was not already in the captured baseline (
        <span className="mono">/etc/passwd</span>, <span className="mono">win.ini</span>
        , PHP filter base64 of those files, and similar).
      </span>
    </div>
  );
}
