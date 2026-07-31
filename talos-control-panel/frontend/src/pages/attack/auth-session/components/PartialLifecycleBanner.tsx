/**
 * Progressive-phase banner until full E2E (approve + run) lands in UI.
 * Phase 2: generate OK; approve / run still Phase 3–4.
 */
export default function PartialLifecycleBanner() {
  return (
    <div className="alert text-xs py-2 mb-4 bg-base-200 border border-base-300">
      <span>
        <strong>Partial lifecycle (Phase 2).</strong> You can bind, generate, and
        browse candidates here. Approve / reject bulk actions and the Run tab
        land in later phases — use CLI{" "}
        <span className="mono">talos attack auth-session approve …</span> and{" "}
        <span className="mono">run …</span> until then, or wait for the next
        Control Panel phase.
      </span>
    </div>
  );
}
