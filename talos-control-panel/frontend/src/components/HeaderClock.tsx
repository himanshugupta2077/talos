import { useEffect, useState } from "react";
import { formatISTClock } from "../lib/time";

/**
 * Live IST clock for the global header. Ticks every 15s so minute changes
 * appear promptly without a 1Hz timer.
 */
export default function HeaderClock() {
  const [now, setNow] = useState(() => new Date());

  useEffect(() => {
    const id = setInterval(() => setNow(new Date()), 15_000);
    return () => clearInterval(id);
  }, []);

  return (
    <time
      className="text-xs mono text-base-content/60 tabular-nums whitespace-nowrap px-1"
      dateTime={now.toISOString()}
      aria-label="Current time (Asia/Kolkata)"
    >
      {formatISTClock(now)}
    </time>
  );
}
