import { maskSensitiveDisplay } from "../shared";

/**
 * Evidence panel with mandatory sensitivity warning (BUG-12).
 * Optional client-side mask is display-only — not complete redaction.
 */
export default function EvidenceSnippet({
  snippet,
  mask = true,
  maxHeightClass = "max-h-64",
}: {
  snippet: string | null | undefined;
  mask?: boolean;
  maxHeightClass?: string;
}) {
  if (!snippet) {
    return (
      <p className="text-sm text-base-content/40">No evidence snippet stored.</p>
    );
  }

  const display = mask ? maskSensitiveDisplay(snippet) : snippet;

  return (
    <div>
      <div className="alert alert-warning text-xs py-2 mb-2">
        <span>
          Snippet may contain sensitive material from the response; treat as
          confidential. Full body only on the Flow HTTP tab. Client-side masking
          is incomplete — not a security boundary.
        </span>
      </div>
      <pre
        className={`panel p-3 mono text-xs whitespace-pre-wrap break-all overflow-y-auto ${maxHeightClass}`}
      >
        {display}
      </pre>
    </div>
  );
}
