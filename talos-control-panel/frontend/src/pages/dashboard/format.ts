/** Relative age for capture freshness / session TTL. */
export function formatRelativeAge(
  value: string | number | null | undefined
): string {
  if (value == null || value === "") return "—";
  let seconds: number;
  if (typeof value === "number") {
    seconds = value;
  } else {
    const d = new Date(value);
    if (Number.isNaN(d.getTime())) return "—";
    seconds = Math.floor((Date.now() - d.getTime()) / 1000);
  }
  const abs = Math.abs(seconds);
  const future = seconds < 0;
  const unit = (n: number, label: string) =>
    future ? `in ${n}${label}` : `${n}${label} ago`;
  if (abs < 60) return unit(abs, "s");
  if (abs < 3600) return unit(Math.floor(abs / 60), "m");
  if (abs < 86400) return unit(Math.floor(abs / 3600), "h");
  return unit(Math.floor(abs / 86400), "d");
}

export function formatDurationSeconds(
  value: number | null | undefined
): string {
  if (value == null || Number.isNaN(value)) return "—";
  const abs = Math.abs(Math.floor(value));
  const sign = value < 0 ? "-" : "";
  if (abs < 60) return `${sign}${abs}s`;
  if (abs < 3600) return `${sign}${Math.floor(abs / 60)}m`;
  return `${sign}${Math.floor(abs / 3600)}h ${Math.floor((abs % 3600) / 60)}m`;
}

export function formatBytes(n: number | null | undefined): string {
  if (n == null || Number.isNaN(n)) return "—";
  if (n >= 1024 * 1024 && n % (1024 * 1024) === 0) {
    return `${n / (1024 * 1024)} MiB`;
  }
  if (n >= 1024) return `${Math.round(n / 1024)} KiB`;
  return `${n} B`;
}

export function formatUptime(startup: string | null | undefined): string {
  if (!startup) return "—";
  const d = new Date(startup);
  if (Number.isNaN(d.getTime())) return "—";
  const seconds = Math.floor((Date.now() - d.getTime()) / 1000);
  if (seconds < 0) return "—";
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m`;
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  return `${h}h ${m}m`;
}
