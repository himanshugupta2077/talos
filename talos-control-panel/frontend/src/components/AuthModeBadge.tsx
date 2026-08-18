/** Compact badge: cookie/header vs Windows NTLM project. */

export default function AuthModeBadge({
  mode,
  size = "xs",
}: {
  mode?: string | null;
  size?: "xs" | "sm";
}) {
  const ntlm = mode === "platform_ntlm";
  const cls = size === "sm" ? "badge-sm" : "badge-xs";
  if (ntlm) {
    return (
      <span className={`badge badge-warning ${cls} gap-1`} title="Windows / NTLM platform auth">
        NTLM
      </span>
    );
  }
  return (
    <span className={`badge badge-ghost ${cls}`} title="Cookie / header session">
      cookies
    </span>
  );
}
