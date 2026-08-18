export default function SmuggleDisclaimer() {
  return (
    <div className="alert alert-warning text-xs py-2 mb-4">
      <span>
        HTTP request smuggling sends raw{" "}
        <span className="mono">Content-Length</span> /{" "}
        <span className="mono">Transfer-Encoding</span> probes on a keep-alive
        connection (NTLM handshake first when platform auth is configured).
        Each technique stores a unique replay flow and appears in the Talos
        Burp extension. Findings are created only on a confirmed desync — a
        timeout alone is not an issue.
      </span>
    </div>
  );
}
