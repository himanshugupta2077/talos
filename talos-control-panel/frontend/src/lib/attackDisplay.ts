/**
 * Operator-facing attack_type labels for Findings list / detail (K18b).
 * Mirrors core ATTACK_DISPLAY for types CP surfaces.
 */
export const ATTACK_DISPLAY: Record<string, string> = {
  passive_secret: "Client-Side Secret Exposure",
  auth_session: "Authentication & Session Testing",
  bac: "Broken Access Control",
  unauth: "Unauthenticated Access",
  auth_test: "Authentication Bypass",
  iv: "Input Validation",
  cors: "CORS Misconfiguration",
  sqli: "SQL Injection",
  path_traversal: "Path Traversal / LFI",
  smuggle: "HTTP Request Smuggling",
  intruder: "Intruder",
  replay: "Replay",
};

/** Compact labels for Flows / Scheduler chips (space-constrained). */
export const ATTACK_MODULE_SHORT: Record<string, string> = {
  iv: "IV",
  bac: "BAC",
  unauth: "Unauth",
  cors: "CORS misconfig",
  sqli: "SQLi",
  path_traversal: "LFI",
  smuggle: "Smuggle",
  auth_session: "Auth-session",
  auth_test: "Auth test",
  intruder: "Intruder",
  replay: "Replay",
};

export function attackModuleShortLabel(
  id: string | null | undefined
): string {
  if (!id) return "—";
  return ATTACK_MODULE_SHORT[id] || ATTACK_DISPLAY[id] || id;
}

export function attackTypeLabel(attackType: string | null | undefined): string {
  if (!attackType) return "—";
  return ATTACK_DISPLAY[attackType] || attackType;
}
