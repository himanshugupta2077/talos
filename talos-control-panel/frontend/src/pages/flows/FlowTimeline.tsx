import { Link } from "react-router-dom";
import { formatIST } from "../../lib/time";

export interface TimelineEvent {
  at: string;
  label: string;
  href?: string;
  detail?: string;
}

/**
 * Compose timeline only from real DB-backed events. Never invent steps.
 */
export function buildTimelineEvents(input: {
  capturedAt: string;
  endpointId?: string | null;
  jobs?: { job_id: string; job_type: string; status: string; created_at: string }[];
  children?: { id: string; captured_at: string; replay_reason?: string | null }[];
  diff?: { created_at?: string; verdict?: string } | null;
  bac?: { created_at?: string; verdict?: string } | null;
  unauth?: { created_at?: string; verdict?: string } | null;
  authTest?: { created_at?: string; verdict?: string } | null;
  findings?: {
    finding_id: string;
    title: string;
    created_at: string;
    evidence_type: string;
  }[];
}): TimelineEvent[] {
  const events: TimelineEvent[] = [];
  events.push({ at: input.capturedAt, label: "Captured" });

  if (input.endpointId) {
    events.push({
      at: input.capturedAt,
      label: "Endpoint linked",
      href: `/endpoints/${input.endpointId}`,
      detail: input.endpointId.slice(0, 8),
    });
  }

  for (const j of input.jobs || []) {
    events.push({
      at: j.created_at,
      label: `Scheduler: ${j.job_type}`,
      href: "/scheduler",
      detail: j.status,
    });
  }

  for (const c of input.children || []) {
    events.push({
      at: c.captured_at,
      label: "Replay child",
      href: `/flows/${c.id}`,
      detail: c.replay_reason || c.id.slice(0, 8),
    });
  }

  if (input.diff) {
    events.push({
      at: (input.diff as any).created_at || input.capturedAt,
      label: "Diff result",
      detail: input.diff.verdict,
    });
  }
  if (input.bac) {
    events.push({
      at: (input.bac as any).created_at || input.capturedAt,
      label: "BAC result",
      detail: input.bac.verdict,
    });
  }
  if (input.unauth) {
    events.push({
      at: (input.unauth as any).created_at || input.capturedAt,
      label: "Unauth result",
      detail: input.unauth.verdict,
    });
  }
  if (input.authTest) {
    events.push({
      at: (input.authTest as any).created_at || input.capturedAt,
      label: "Auth-test result",
      detail: input.authTest.verdict,
    });
  }

  for (const f of input.findings || []) {
    events.push({
      at: f.created_at,
      label: "Finding evidence",
      href: `/findings/${f.finding_id}`,
      detail: f.title || f.evidence_type,
    });
  }

  // Sort by time when possible
  return events.sort((a, b) => String(a.at).localeCompare(String(b.at)));
}

export default function FlowTimeline({ events }: { events: TimelineEvent[] }) {
  if (events.length <= 1) {
    return (
      <div className="text-xs text-base-content/50 p-2">
        Only the capture event is known for this flow. Related jobs, replays, and
        findings appear here when Core stores them.
      </div>
    );
  }
  return (
    <ul className="timeline timeline-vertical timeline-compact">
      {events.map((e, i) => (
        <li key={`${e.label}-${e.at}-${i}`}>
          {i > 0 && <hr />}
          <div className="timeline-start text-[10px] text-base-content/40 whitespace-nowrap">
            {formatIST(e.at)}
          </div>
          <div className="timeline-middle">
            <span className="w-2 h-2 rounded-full bg-primary inline-block" />
          </div>
          <div className="timeline-end timeline-box text-xs py-1 px-2">
            {e.href ? (
              <Link to={e.href} className="link">
                {e.label}
              </Link>
            ) : (
              e.label
            )}
            {e.detail && (
              <span className="text-base-content/50 ml-1 mono text-[10px]">{e.detail}</span>
            )}
          </div>
          {i < events.length - 1 && <hr />}
        </li>
      ))}
    </ul>
  );
}
