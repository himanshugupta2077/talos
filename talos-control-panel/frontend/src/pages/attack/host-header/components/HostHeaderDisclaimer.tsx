export default function HostHeaderDisclaimer() {
  return (
    <div className="alert alert-warning text-xs py-2 mb-4">
      <span>
        Host-header injection sends outbound requests to the{" "}
        <strong>captured origin</strong> with a mutated Host /
        X-Forwarded-Host / Forwarded value (not BAC host-fuzz routing). Each
        payload stores a unique replay flow (visible in the Talos Burp
        extension under Host Header Injection). Findings are created only when
        a probe reflects the canary host{" "}
        <span className="mono">talos-hhi.invalid</span> in a{" "}
        <strong>URL-shaped</strong> response sink (Location, HTML/JSON
        absolute URLs, CORS ACAO, Set-Cookie Domain) that was not already in
        the captured baseline.
      </span>
    </div>
  );
}
