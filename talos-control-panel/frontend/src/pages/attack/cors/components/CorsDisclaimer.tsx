export default function CorsDisclaimer() {
  return (
    <div className="alert alert-warning text-xs py-2 mb-4">
      <span>
        CORS testing sends outbound requests with mutated{" "}
        <span className="mono">Origin</span> headers. Each technique stores a
        unique replay flow. Findings are created only when an attacker origin
        or subdomain is reflected — <span className="mono">ACAO: *</span> or
        credentials-only responses are not standalone issues.
      </span>
    </div>
  );
}
