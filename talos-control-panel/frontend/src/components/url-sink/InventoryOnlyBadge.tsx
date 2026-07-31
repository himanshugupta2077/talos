/**
 * Marks parameters that are inventory/characterization only (not injectable):
 * location=response or jwt.* virtual claim names.
 */
export default function InventoryOnlyBadge({
  show = true,
  className = "",
}: {
  show?: boolean;
  className?: string;
}) {
  if (!show) return null;
  return (
    <span
      className={`badge badge-ghost badge-xs ${className}`}
      title="Inventory-only surface (response body or jwt.* claim). Not a normal injectable input — IV Run may not apply."
    >
      inv-only
    </span>
  );
}

/** True when location is response or name starts with jwt. (core inventory-only surfaces). */
export function isInventoryOnlySurface(
  location?: string | null,
  name?: string | null,
): boolean {
  if ((location || "") === "response") return true;
  if ((name || "").startsWith("jwt.")) return true;
  return false;
}
