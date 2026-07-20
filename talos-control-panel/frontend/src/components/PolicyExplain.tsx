/**
 * Structured view of `talos endpoint policy <id>` — used by Policy tab drawer
 * and Endpoint Detail → Policy. Single implementation for both surfaces.
 */

import { useState } from "react";
import { EndpointPolicyExplanation } from "../types";
import StatusBadge from "./StatusBadge";
import { UuidChip } from "./Common";

export default function PolicyExplain({
  data,
  compact = false,
}: {
  data: EndpointPolicyExplanation | null | undefined;
  compact?: boolean;
}) {
  const [showJson, setShowJson] = useState(false);
  if (!data) {
    return <div className="text-sm text-base-content/50 py-4">No policy explanation available.</div>;
  }

  const pr = data.priority;
  const ex = data.exclusion;
  const qu = data.qualification;
  const sf = data.safety;
  const bl = data.baseline;
  const decision =
    data.decision ||
    (qu?.qualified && !ex?.effective ? "TESTABLE" : "SKIPPED");
  const label =
    data.endpoint?.label ||
    `${data.endpoint?.method || ""} ${data.endpoint?.origin || ""}${data.endpoint?.path || ""}`.trim();

  return (
    <div className="space-y-4 text-sm">
      {label && !compact && (
        <div>
          <div className="font-mono text-base font-semibold break-all">{label}</div>
          {data.endpoint?.id && (
            <div className="mt-1 text-xs text-base-content/50">
              Endpoint ID <UuidChip value={data.endpoint.id} />
            </div>
          )}
        </div>
      )}

      <Block title="FINAL DECISION">
        <StatusBadge value={decision} />
      </Block>

      <Block title="PRIORITY">
        <div className="flex items-center gap-2 mb-2">
          <StatusBadge value={pr?.effective || data.effective_level} />
          <span className="badge badge-ghost badge-sm uppercase">
            {(pr?.source || data.source || "—").replace("path_rule", "rule")}
          </span>
        </div>
        <div className="text-xs text-base-content/60 space-y-1 mono">
          <div>Resolution</div>
          <ol className="list-decimal ml-4 space-y-0.5">
            <li>
              Manual endpoint priority{" "}
              <span className="text-base-content">
                {pr?.manual ? `→ ${pr.manual}` : "not configured"}
              </span>
            </li>
            <li>
              Path rule{" "}
              {pr?.rule?.pattern ? (
                <span className="text-base-content">
                  {pr.rule.pattern} matched → {pr.rule.priority}
                  {pr.rule.id ? ` · ${pr.rule.id.slice(0, 8)}` : ""}
                </span>
              ) : (
                <span>none matched</span>
              )}
            </li>
            <li>
              Auto priority{" "}
              <span className="text-base-content">
                {pr?.auto?.priority || "NORMAL"}
                {pr?.auto?.score != null ? ` (score ${pr.auto.score})` : ""}
              </span>
            </li>
          </ol>
          <div className="pt-1">
            Effective: <strong>{pr?.effective || data.effective_level}</strong>
            {" · "}
            Source:{" "}
            <strong>{(pr?.source || data.source || "—").replace("path_rule", "path rule")}</strong>
          </div>
        </div>
      </Block>

      <Block title="EXCLUSION">
        <div className="text-xs space-y-1">
          <Row label="Endpoint exclusion" value={ex?.source === "endpoint" ? "true" : "false"} />
          <Row
            label="Matching exclusion rule"
            value={ex?.rule_pattern || "none"}
          />
          <div className="pt-1">
            Effective:{" "}
            <strong>{ex?.effective || data.excluded ? "EXCLUDED" : "INCLUDED"}</strong>
          </div>
        </div>
      </Block>

      <Block title="QUALIFICATION">
        <div className="text-xs space-y-1">
          <Row label="Qualified" value={qu?.qualified ?? data.qualified ? "yes" : "no"} />
          <Row label="Reason" value={qu?.reason || data.qualification_reason || "—"} />
        </div>
      </Block>

      <Block title="SAFETY">
        <div className="text-xs space-y-1">
          <Row label="Dangerous" value={sf?.dangerous ?? data.dangerous ? "true" : "false"} />
          <Row label="Logout" value={sf?.logout ?? data.logout ? "true" : "false"} />
        </div>
      </Block>

      <Block title="BASELINE">
        <div className="text-xs space-y-1">
          <div className="flex items-center gap-2">
            <span className="text-base-content/50 w-28">Flow</span>
            <UuidChip value={bl?.flow_id || data.baseline_flow_id} />
          </div>
          <Row
            label="Status"
            value={
              bl?.status != null
                ? String(bl.status)
                : data.baseline_status != null
                  ? String(data.baseline_status)
                  : "—"
            }
          />
        </div>
      </Block>

      <div>
        <button className="btn btn-xs btn-ghost" onClick={() => setShowJson((v) => !v)}>
          {showJson ? "Hide JSON" : "View JSON"}
        </button>
        {showJson && (
          <pre className="mt-2 p-2 panel text-xs mono overflow-x-auto max-h-80 overflow-y-auto">
            {JSON.stringify(data, null, 2)}
          </pre>
        )}
      </div>
    </div>
  );
}

function Block({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="panel p-3">
      <div className="text-[10px] uppercase tracking-wide text-base-content/50 font-semibold mb-2">
        {title}
      </div>
      {children}
    </div>
  );
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex gap-2">
      <span className="text-base-content/50 w-44 shrink-0">{label}</span>
      <span className="mono break-all">{value}</span>
    </div>
  );
}
