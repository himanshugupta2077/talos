/** Shared labels and helpers for the Repeater workspace. */

export const REPEATER_HELP_TITLE = "How the Repeater works";

export const REPEATER_HELP_BODY = `
Edit a captured (or previously sent) request, then Send to fire a new request
with full lineage. Captures stay immutable — every send inserts a new flow.

• Replay = exact re-execution of the stored request (Mode 1).
• Send = free mutation with parent/root lineage (Mode 2).

Tabs are a project archive (server / talos send tab) — they survive refresh.
Draft request bodies stay local until Send; re-open re-materializes from the
parent flow. Parent does not advance after Send; use Fork on a history row to
continue from that execution.
`.trim();

export function shortUuid(id: string | null | undefined): string {
  if (!id) return "—";
  return id.slice(0, 8);
}

export function isLogoutAnnotated(annotations: string[]): boolean {
  return annotations.some((a) => a.toLowerCase() === "logout");
}

export function isDangerousAnnotated(annotations: string[]): boolean {
  return annotations.some((a) => a.toLowerCase() === "dangerous");
}

export function downloadBase64(filename: string, b64: string): void {
  const bytes = atob(b64);
  const arr = new Uint8Array(bytes.length);
  for (let i = 0; i < bytes.length; i++) arr[i] = bytes.charCodeAt(i);
  const blob = new Blob([arr], { type: "application/octet-stream" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}
