import type { ReactNode } from "react";
import { Link } from "react-router-dom";
import { UuidChip } from "../../components/Common";
import SideDrawer from "../../components/SideDrawer";
import StatusBadge from "../../components/StatusBadge";
import { formatIST } from "../../lib/time";
import type { SchedulerJob } from "../../types";
import {
  familyBadgeClass,
  isCancellable,
  jobFamily,
  shortJobId,
} from "./shared";

export default function JobDetailDrawer({
  job,
  open,
  onClose,
  onCancel,
  cancelling,
}: {
  job: SchedulerJob | null;
  open: boolean;
  onClose: () => void;
  onCancel: (jobId: string) => void;
  cancelling?: boolean;
}) {
  if (!job) {
    return (
      <SideDrawer open={open} onClose={onClose} title="Job detail" wide>
        <p className="text-sm text-base-content/50">No job selected.</p>
      </SideDrawer>
    );
  }

  const family = jobFamily(job.job_type);
  const canCancel = isCancellable(job.status);
  const meta = job.meta && typeof job.meta === "object" ? job.meta : {};
  const metaPretty =
    Object.keys(meta).length > 0
      ? JSON.stringify(meta, null, 2)
      : null;

  const epId = job.resolved_endpoint_id || job.endpoint_id;

  return (
    <SideDrawer
      open={open}
      onClose={onClose}
      title={`Job ${shortJobId(job.job_id)}`}
      wide
    >
      <div className="space-y-4 text-sm">
        {/* Identity */}
        <section>
          <div className="text-[10px] uppercase text-base-content/50 mb-1.5">
            Identity
          </div>
          <div className="grid grid-cols-2 gap-2">
            <Field label="Job ID">
              <UuidChip value={job.job_id} />
              <span className="text-[10px] text-base-content/40 mono ml-1">
                {job.job_id}
              </span>
            </Field>
            <Field label="Status">
              <StatusBadge value={job.status} />
            </Field>
            <Field label="Type">
              <span
                className={`badge badge-sm ${familyBadgeClass(family)} uppercase`}
              >
                {family}
              </span>
              <span className="mono text-xs ml-1">{job.job_type}</span>
            </Field>
            <Field label="Priority">
              <span className="mono">{job.priority}</span>
            </Field>
          </div>
        </section>

        {/* Targets */}
        <section>
          <div className="text-[10px] uppercase text-base-content/50 mb-1.5">
            Targets
          </div>
          <div className="space-y-1.5">
            <TargetRow label="Endpoint" id={epId} href={epId ? `/endpoints/${epId}` : null} />
            <TargetRow
              label="Flow"
              id={job.flow_id}
              href={job.flow_id ? `/flows/${job.flow_id}` : null}
            />
            <TargetRow
              label="Replayed flow"
              id={job.replayed_flow_id}
              href={
                job.replayed_flow_id ? `/flows/${job.replayed_flow_id}` : null
              }
            />
            {(job.role_name || job.module_name) && (
              <div className="text-xs text-base-content/60">
                {job.role_name && (
                  <span>
                    Role: <span className="font-medium">{job.role_name}</span>
                  </span>
                )}
                {job.role_name && job.module_name && " · "}
                {job.module_name && (
                  <span>
                    Module: <span className="font-medium">{job.module_name}</span>
                  </span>
                )}
              </div>
            )}
          </div>
        </section>

        {/* Timeline */}
        <section>
          <div className="text-[10px] uppercase text-base-content/50 mb-1.5">
            Timeline
          </div>
          <div className="grid grid-cols-2 gap-2 text-xs">
            <Field label="Created">{formatIST(job.created_at)}</Field>
            <Field label="Scheduled">{formatIST(job.scheduled_at)}</Field>
            <Field label="Started">{formatIST(job.started_at)}</Field>
            <Field label="Finished">{formatIST(job.finished_at)}</Field>
          </div>
        </section>

        {/* Outcome */}
        <section>
          <div className="text-[10px] uppercase text-base-content/50 mb-1.5">
            Outcome
          </div>
          <div className="space-y-1.5">
            <div className="flex items-center gap-2">
              <span className="text-base-content/50 text-xs">Verdict</span>
              <StatusBadge value={job.verdict} />
            </div>
            {job.failure_reason && (
              <div className="rounded bg-error/10 border border-error/20 p-2 text-xs whitespace-pre-wrap break-words">
                {job.failure_reason}
              </div>
            )}
          </div>
        </section>

        {/* Meta */}
        {metaPretty && (
          <section>
            <div className="text-[10px] uppercase text-base-content/50 mb-1.5">
              Meta
            </div>
            <pre className="text-[11px] mono bg-base-200/80 rounded p-2 overflow-x-auto max-h-64 whitespace-pre-wrap break-all">
              {metaPretty}
            </pre>
          </section>
        )}

        {/* Actions */}
        <section className="flex flex-wrap gap-2 pt-2 border-t border-base-300">
          {canCancel && (
            <button
              type="button"
              className="btn btn-sm btn-error"
              disabled={cancelling}
              onClick={() => onCancel(job.job_id)}
            >
              {cancelling ? "Cancelling…" : "Cancel job"}
            </button>
          )}
          <button
            type="button"
            className="btn btn-sm btn-ghost"
            onClick={() => navigator.clipboard.writeText(job.job_id)}
          >
            Copy job ID
          </button>
          {job.flow_id && (
            <Link
              className="btn btn-sm btn-ghost"
              to={`/flows/${job.flow_id}`}
              target="_blank"
            >
              Open flow
            </Link>
          )}
          {epId && (
            <Link
              className="btn btn-sm btn-ghost"
              to={`/endpoints/${epId}`}
              target="_blank"
            >
              Open endpoint
            </Link>
          )}
          {job.replayed_flow_id && (
            <Link
              className="btn btn-sm btn-ghost"
              to={`/flows/${job.replayed_flow_id}`}
              target="_blank"
            >
              Open replayed flow
            </Link>
          )}
        </section>
      </div>
    </SideDrawer>
  );
}

function Field({
  label,
  children,
}: {
  label: string;
  children?: ReactNode;
}) {
  return (
    <div>
      <div className="text-[10px] text-base-content/40 uppercase">{label}</div>
      <div className="mt-0.5">{children ?? "—"}</div>
    </div>
  );
}

function TargetRow({
  label,
  id,
  href,
}: {
  label: string;
  id: string | null | undefined;
  href: string | null;
}) {
  return (
    <div className="flex items-center gap-2 text-xs">
      <span className="text-base-content/50 w-24 shrink-0">{label}</span>
      {id ? (
        href ? (
          <Link to={href} className="link link-primary mono" target="_blank">
            {id.slice(0, 8)}…
          </Link>
        ) : (
          <UuidChip value={id} />
        )
      ) : (
        <span className="text-base-content/30">—</span>
      )}
    </div>
  );
}
