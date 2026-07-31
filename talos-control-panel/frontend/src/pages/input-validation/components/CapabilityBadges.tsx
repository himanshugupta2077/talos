/**
 * Capability chips for IV profiles.
 * Sink-family tooltips use prioritization language only — never "vulnerable".
 */

const SINK_CAPS = new Set([
  "network_resource_sink",
  "redirect_sink",
  "fetch_sink",
  "webhook_sink",
  "protocol_support",
  "url_like_value",
]);

const SINK_TOOLTIPS: Record<string, string> = {
  network_resource_sink:
    "Input may accept URL/host/IP-shaped values — prioritization capability, not confirmed SSRF",
  redirect_sink:
    "Redirect-like behavior or name category — prioritization for open redirect, not confirmation",
  fetch_sink:
    "Server-side fetch-like signals from characterization — prioritization only",
  webhook_sink:
    "Webhook-like name/value signals — prioritization for webhook abuse, not confirmation",
  protocol_support:
    "Non-http(s) or multi-scheme acceptance observed in canaries — characterization only",
  url_like_value:
    "Value looks URL-like (legacy alias) — prioritization signal only",
};

function badgeClass(cap: string): string {
  if (cap === "stored_reflection") {
    return "badge badge-warning badge-outline badge-xs mono";
  }
  if (cap === "reflective_input") {
    return "badge badge-info badge-outline badge-xs mono";
  }
  if (cap === "network_resource_sink") {
    return "badge badge-warning badge-outline badge-xs mono";
  }
  if (cap === "redirect_sink" || cap === "webhook_sink") {
    return "badge badge-info badge-outline badge-xs mono";
  }
  if (cap === "fetch_sink" || cap === "protocol_support" || cap === "url_like_value") {
    return "badge badge-accent badge-outline badge-xs mono";
  }
  if (cap.endsWith("_context")) {
    return "badge badge-accent badge-outline badge-xs mono";
  }
  return "badge badge-ghost badge-xs mono";
}

function titleFor(cap: string): string | undefined {
  if (SINK_TOOLTIPS[cap]) return SINK_TOOLTIPS[cap];
  if (cap === "stored_reflection") {
    return "Value observed on another page/flow (data-flow evidence, not XSS)";
  }
  if (cap === "reflective_input") {
    return "Input reflects in a response (same-request and/or stored)";
  }
  if (SINK_CAPS.has(cap)) {
    return "Prioritization capability — not a confirmed vulnerability";
  }
  return undefined;
}

export default function CapabilityBadges({
  caps,
  limit = 12,
}: {
  caps?: string[] | null;
  limit?: number;
}) {
  const list = caps || [];
  if (!list.length) {
    return <span className="text-base-content/40 text-xs">—</span>;
  }
  const shown = list.slice(0, limit);
  const extra = list.length - shown.length;
  return (
    <span className="inline-flex flex-wrap gap-1">
      {shown.map((c) => (
        <span key={c} className={badgeClass(c)} title={titleFor(c)}>
          {c}
        </span>
      ))}
      {extra > 0 && <span className="badge badge-ghost badge-xs">+{extra}</span>}
    </span>
  );
}
