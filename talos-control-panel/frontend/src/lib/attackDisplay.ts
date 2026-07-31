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
};

export function attackTypeLabel(attackType: string | null | undefined): string {
  if (!attackType) return "—";
  return ATTACK_DISPLAY[attackType] || attackType;
}
