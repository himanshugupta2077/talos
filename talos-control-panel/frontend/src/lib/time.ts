/**
 * Timestamp display helpers.
 *
 * Backend / SQLite store times in UTC (or ISO strings). The control panel
 * renders them in Asia/Kolkata (IST) for consistent operator review.
 */

const IST = "Asia/Kolkata";

function toDate(value: string | Date | null | undefined): Date | null {
  if (value == null || value === "") return null;
  const d = value instanceof Date ? value : new Date(value);
  return Number.isNaN(d.getTime()) ? null : d;
}

/**
 * Full IST timestamp for tables and detail views.
 * Example: "18/07/2026, 14:30:45"
 */
export function formatIST(value: string | Date | null | undefined): string {
  const d = toDate(value);
  if (!d) return "—";
  return new Intl.DateTimeFormat("en-IN", {
    timeZone: IST,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }).format(d);
}

/**
 * Compact IST clock for the global header.
 * Example: "14:30:45"
 */
export function formatISTClock(value: Date | string = new Date()): string {
  const d = toDate(value) ?? new Date();
  return new Intl.DateTimeFormat("en-IN", {
    timeZone: IST,
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }).format(d);
}
