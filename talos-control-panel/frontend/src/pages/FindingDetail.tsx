import { useEffect, useMemo, useState } from "react";
import { useNavigate, useParams, useSearchParams, Link } from "react-router-dom";
import { useProject } from "../state/ProjectContext";
import { api } from "../api/client";
import { useAction } from "../hooks/useAction";
import { Section, UuidChip, ConfirmButton } from "../components/Common";
import StatusBadge from "../components/StatusBadge";
import { attackTypeLabel } from "../lib/attackDisplay";
import { formatIST } from "../lib/time";
import { Finding, FindingGroup } from "../types";
import { SECRETS_BASE } from "./attack/registry";
import SecretHighlight from "./secret-detection/components/SecretHighlight";
import ConfidenceChip from "./secret-detection/components/ConfidenceChip";
import RedactedValue from "./secret-detection/components/RedactedValue";
import { findingNavFromSearch, preserveSearch } from "./findings/nav";
import FindingFlowHttp from "./findings/FindingFlowHttp";

interface FlowSummary {
  id: string;
  missing?: boolean;
  method?: string | null;
  url?: string | null;
  path?: string | null;
  status_code?: number | null;
  content_type?: string | null;
  body_len?: number;
  captured_at?: string | null;
  original_flow_id?: string | null;
  replay_reason?: string | null;
}

interface FlowComparison {
  original: FlowSummary | null;
  testcase: FlowSummary | null;
  delta: {
    status_changed: boolean;
    status_from: number | null;
    status_to: number | null;
    body_len_delta: number;
  } | null;
  diff_verdict?: string | null;
  original_evidence_id?: string | null;
  testcase_evidence_id?: string | null;
}

interface SecretHit {
  detection_id?: string | null;
  finding_id?: string | null;
  document_id?: string | null;
  occurrence_id?: string | null;
  flow_id?: string | null;
  url?: string | null;
  path?: string | null;
  host?: string | null;
  detector_id?: string | null;
  detector_family?: string | null;
  secret_type?: string | null;
  matched_key?: string | null;
  redacted_value?: string | null;
  raw_value?: string | null;
  confidence_level?: string | null;
  confidence_score?: number | null;
  match_start?: number;
  match_end?: number;
  context_before?: string | null;
  context_after?: string | null;
  encoding_chain?: string[];
}

interface SecretExposure {
  hits: SecretHit[];
  count: number;
}

interface Bundle {
  finding: Finding;
  evidence: { id: string; evidence_type: string; reference_id: string | null; label: string; data: any; created_at: string }[];
  timeline: { id: string; event: string; actor: string; created_at: string }[];
  duplicates: Finding[];
  parent?: Finding | null;
  linked?: Finding[];
  flow_comparison?: FlowComparison | null;
  secret_exposure?: SecretExposure | null;
}

const EVIDENCE_TYPE_LABELS: Record<string, string> = {
  original_flow: "Original Flow",
  replay_flow: "Attack / Testcase Flow",
  diff: "Replay Diff",
  passive_detection: "Secret Detection",
  source_document: "Source Document",
  source_occurrence: "Source Occurrence",
  auth_test_result: "Auth Test Result",
  unauth_result: "Unauth Result",
  auth_session_result: "Auth-Session Result",
  bac_result: "BAC Result",
  attacker_role: "Attacker Role",
  target_role: "Target Role",
  endpoint: "Endpoint",
  scheduler_job: "Scheduler Job",
  module: "Module",
  role: "Role",
  analyst_note: "Analyst Note",
  decision_filter_result: "Decision Filter",
};

function evidenceTypeLabel(t: string): string {
  return EVIDENCE_TYPE_LABELS[t] || t;
}

function SecretExposureSection({
  exposure,
  findingId,
}: {
  exposure: SecretExposure;
  findingId?: string;
}) {
  const hits = exposure.hits || [];
  return (
    <Section
      title={hits.length > 1 ? `Leaked secret (${hits.length} locations)` : "Leaked secret"}
    >
      <p className="text-xs text-base-content/50 mb-3">
        Highlighted span is the exact match Secret Detection flagged, including
        the secret type (email, token, …) and the unmasked value when it was
        stored on the finding.
      </p>
      <div className="space-y-3">
        {hits.map((hit, i) => {
          const loc = hit.url || hit.path || "unknown path";
          const detId = hit.detection_id;
          const displayed = (hit.raw_value || hit.redacted_value || "").trim();
          return (
            <div key={detId || `${loc}-${i}`} className="panel p-3 border-l-4 border-l-warning/60">
              <div className="flex flex-wrap items-center gap-2 mb-2">
                {hit.secret_type && (
                  <span className="badge badge-outline badge-sm">{hit.secret_type}</span>
                )}
                {displayed ? (
                  <span className="mono text-sm font-semibold break-all">{displayed}</span>
                ) : (
                  <RedactedValue value={hit.redacted_value} className="text-sm font-semibold" />
                )}
                {hit.confidence_level && (
                  <ConfidenceChip
                    level={hit.confidence_level}
                    score={hit.confidence_score}
                  />
                )}
                {hit.detector_id && (
                  <span className="badge badge-ghost badge-sm mono">{hit.detector_id}</span>
                )}
                {hit.matched_key && (
                  <span className="text-xs mono text-base-content/60">
                    key={hit.matched_key}
                  </span>
                )}
              </div>
              <SecretHighlight
                contextBefore={hit.context_before}
                redactedValue={displayed || hit.redacted_value}
                contextAfter={hit.context_after}
              />
              <div className="flex flex-wrap items-center gap-2 mt-2 text-xs text-base-content/60">
                <span className="mono break-all">{loc}</span>
                {(hit.match_start != null || hit.match_end != null) && (
                  <span className="mono">
                    offsets {hit.match_start ?? 0}–{hit.match_end ?? 0}
                  </span>
                )}
                {hit.flow_id && (
                  <Link to={`/flows/${hit.flow_id}`} className="link">
                    Open flow
                  </Link>
                )}
                {hit.finding_id && hit.finding_id !== findingId && (
                  <Link to={`/findings/${hit.finding_id}`} className="link">
                    Linked finding
                  </Link>
                )}
                {detId && (
                  <Link to={`${SECRETS_BASE}/detections/${detId}`} className="link">
                    Open detection
                  </Link>
                )}
                {hit.document_id && (
                  <Link to={`${SECRETS_BASE}/documents/${hit.document_id}`} className="link">
                    Open document
                  </Link>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </Section>
  );
}

function FlowComparisonSection({ comparison }: { comparison: FlowComparison }) {
  const { original, testcase, delta, diff_verdict } = comparison;

  return (
    <div className="space-y-4 mb-6">
      {testcase && (
        <Section
          title="Attack flow"
          action={
            diff_verdict ? <StatusBadge value={String(diff_verdict)} /> : undefined
          }
        >
          <FindingFlowHttp
            title="Attack / testcase"
            badgeClass="badge-warning"
            summary={testcase}
            emptyLabel="No replay_flow (attack/testcase) evidence on this finding."
          />
        </Section>
      )}
      {delta && testcase && original && (
        <div className="panel p-3 text-sm flex flex-wrap gap-4 items-center">
          <span className="text-xs font-medium uppercase tracking-wide text-base-content/50">
            Delta
          </span>
          <span>
            Status:{" "}
            <span className={delta.status_changed ? "text-warning font-medium" : ""}>
              {delta.status_changed ? "changed" : "unchanged"}
            </span>{" "}
            <span className="mono text-base-content/70">
              ({delta.status_from ?? "?"} → {delta.status_to ?? "?"})
            </span>
          </span>
          <span>
            Body length:{" "}
            <span
              className={`mono ${
                delta.body_len_delta !== 0 ? "text-warning font-medium" : ""
              }`}
            >
              {delta.body_len_delta >= 0 ? "+" : ""}
              {delta.body_len_delta} B
            </span>
          </span>
        </div>
      )}
      {original && (
        <Section title="Original flow">
          <FindingFlowHttp
            title="Original"
            badgeClass="badge-info"
            summary={original}
            emptyLabel="No original_flow evidence on this finding."
          />
        </Section>
      )}
    </div>
  );
}

function isTypingTarget(t: EventTarget | null): boolean {
  if (!(t instanceof HTMLElement)) return false;
  return (
    t.tagName === "INPUT" ||
    t.tagName === "TEXTAREA" ||
    t.tagName === "SELECT" ||
    t.isContentEditable
  );
}

export default function FindingDetail() {
  const { findingId } = useParams();
  const { selected } = useProject();
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const [bundle, setBundle] = useState<Bundle | null>(null);
  const [groups, setGroups] = useState<FindingGroup[]>([]);
  const [duplicateOf, setDuplicateOf] = useState("");
  const [reportText, setReportText] = useState("");
  const [notesDraft, setNotesDraft] = useState("");
  const [applyLinked, setApplyLinked] = useState(false);
  const [adjacent, setAdjacent] = useState<{
    prev_id: string | null;
    next_id: string | null;
  }>({ prev_id: null, next_id: null });

  const filterQs = useMemo(
    () => findingNavFromSearch(searchParams),
    [searchParams]
  );
  const listHref = `/findings${preserveSearch(searchParams)}`;
  const findingHref = (id: string) =>
    `/findings/${id}${preserveSearch(searchParams)}`;

  const load = () => {
    if (!selected || !findingId) return;
    api.get<Bundle>(`/api/findings/${findingId}`, { project_id: selected.id }).then((b) => {
      setBundle(b);
      setNotesDraft(b.finding.notes || "");
    });
    api
      .get<{ groups: FindingGroup[] }>("/api/findings/groups/list", {
        project_id: selected.id,
      })
      .then((r) => setGroups(r.groups));
    api
      .get<{ prev_id: string | null; next_id: string | null }>(
        `/api/findings/${findingId}/adjacent`,
        { project_id: selected.id, ...filterQs }
      )
      .then(setAdjacent)
      .catch(() => setAdjacent({ prev_id: null, next_id: null }));
  };
  useEffect(load, [selected, findingId, filterQs]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (isTypingTarget(e.target)) return;
      if (e.altKey || e.ctrlKey || e.metaKey) return;
      if (e.key === "Escape") {
        navigate(listHref);
        return;
      }
      if (e.key === "ArrowLeft" && adjacent.prev_id) {
        e.preventDefault();
        navigate(findingHref(adjacent.prev_id));
      }
      if (e.key === "ArrowRight" && adjacent.next_id) {
        e.preventDefault();
        navigate(findingHref(adjacent.next_id));
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [adjacent, navigate, listHref, searchParams]);

  const lifecycleBody = () => (applyLinked ? { linked: true, force: true } : {});

  const confirm = useAction("Confirm finding", () =>
    api.post(`/api/findings/${findingId}/confirm`, lifecycleBody(), { project_id: selected!.id })
  );
  const reject = useAction("Reject finding", () =>
    api.post(`/api/findings/${findingId}/reject`, lifecycleBody(), { project_id: selected!.id })
  );
  const reopen = useAction("Reopen finding", () =>
    api.post(`/api/findings/${findingId}/reopen`, lifecycleBody(), { project_id: selected!.id })
  );
  const duplicate = useAction("Mark duplicate", () =>
    api.post(`/api/findings/${findingId}/duplicate`, { of: duplicateOf }, { project_id: selected!.id })
  );
  const addToGroup = useAction("Add to group", (group: string) =>
    api.post("/api/findings/groups/add", { group, finding: findingId }, { project_id: selected!.id })
  );
  const saveNotes = useAction("Save finding notes", () =>
    api.post(`/api/findings/${findingId}/notes`, { notes: notesDraft }, { project_id: selected!.id })
  );
  const clearNotes = useAction("Clear finding notes", () =>
    api.del(`/api/findings/${findingId}/notes`, { project_id: selected!.id })
  );
  const genReport = useAction("Generate report", async () => {
    const r = await api.get<{ steps: any[] }>(`/api/findings/${findingId}/report`, { project_id: selected!.id });
    return r;
  });

  if (!bundle) return <div className="loading loading-spinner" />;
  const { finding, evidence, timeline, duplicates } = bundle;
  const parent = bundle.parent ?? null;
  const linked = bundle.linked ?? [];
  const flowComparison = bundle.flow_comparison ?? null;
  const secretExposure = bundle.secret_exposure ?? null;
  const isPrimary = (finding.relation_type || "PRIMARY").toUpperCase() === "PRIMARY";
  const linkedCount = finding.linked_count ?? linked.length;

  return (
    <div>
      <div className="flex items-center justify-between mb-4 flex-wrap gap-2">
        <Link to={listHref} className="link link-sm">
          back to findings
        </Link>
        <div className="flex items-center gap-2">
          <button
            type="button"
            className="btn btn-xs"
            disabled={!adjacent.prev_id}
            onClick={() => adjacent.prev_id && navigate(findingHref(adjacent.prev_id))}
            title="Newer finding (←)"
          >
            ← prev
          </button>
          <button
            type="button"
            className="btn btn-xs"
            disabled={!adjacent.next_id}
            onClick={() => adjacent.next_id && navigate(findingHref(adjacent.next_id))}
            title="Older finding (→)"
          >
            next →
          </button>
          <span className="text-[10px] text-base-content/40 hidden sm:inline">
            ← / → to move · Esc list
          </span>
        </div>
      </div>

      <div className="mb-4">
        <div className="flex items-start justify-between gap-3 mb-1 flex-wrap">
          <h1 className="text-xl font-semibold min-w-0 flex-1">
            {finding.title || "(untitled finding)"}
          </h1>
          <div className="flex flex-wrap items-center justify-end gap-2 shrink-0">
            {finding.status === "TRIAGING" && (
              <>
                <button
                  className="btn btn-xs btn-success"
                  disabled={confirm.running}
                  onClick={async () => { await confirm.run(); load(); }}
                >
                  {confirm.running ? <span className="loading loading-spinner loading-xs" /> : "Confirm"}
                </button>
                <button
                  className="btn btn-xs btn-error"
                  disabled={reject.running}
                  onClick={async () => { await reject.run(); load(); }}
                >
                  {reject.running ? <span className="loading loading-spinner loading-xs" /> : "Reject"}
                </button>
              </>
            )}
            {finding.status !== "TRIAGING" && (
              <button
                className="btn btn-xs"
                disabled={reopen.running}
                onClick={async () => { await reopen.run(); load(); }}
              >
                {reopen.running ? <span className="loading loading-spinner loading-xs" /> : "Reopen"}
              </button>
            )}
            {isPrimary && linkedCount > 0 && (
              <label className="label cursor-pointer gap-2 py-0">
                <input
                  type="checkbox"
                  className="checkbox checkbox-xs"
                  checked={applyLinked}
                  onChange={(e) => setApplyLinked(e.target.checked)}
                />
                <span className="label-text text-xs">Apply to linked ({linkedCount})</span>
              </label>
            )}
          </div>
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          <StatusBadge value={finding.verdict} />
          <StatusBadge value={finding.status} />
          <span className={`badge badge-sm ${isPrimary ? "badge-outline" : "badge-ghost"}`}>
            {(finding.relation_type || "PRIMARY").toUpperCase()}
            {isPrimary && linkedCount > 0 ? ` · ${linkedCount} linked` : ""}
          </span>
          <span
            className="text-xs text-base-content/50"
            title={finding.attack_type || undefined}
          >
            {attackTypeLabel(finding.attack_type)}
          </span>
          {finding.role_name && <span className="badge badge-outline badge-sm">role: {finding.role_name}</span>}
          {finding.module_name && <span className="badge badge-outline badge-sm">module: {finding.module_name}</span>}
          {finding.endpoint_id && <Link to={`/endpoints/${finding.endpoint_id}`} className="link text-xs">endpoint</Link>}
          {finding.cluster_key && (
            <span className="text-xs mono text-base-content/40" title={finding.cluster_key}>
              cluster: {finding.cluster_key.length > 40 ? `${finding.cluster_key.slice(0, 40)}…` : finding.cluster_key}
            </span>
          )}
          <div className="flex gap-1 items-center ml-auto">
            <input
              className="input input-xs input-bordered mono w-40"
              placeholder="duplicate-of uuid"
              value={duplicateOf}
              onChange={(e) => setDuplicateOf(e.target.value)}
            />
            <button
              className="btn btn-xs"
              disabled={!duplicateOf || duplicate.running}
              onClick={async () => { await duplicate.run(); setDuplicateOf(""); load(); }}
            >
              {duplicate.running ? <span className="loading loading-spinner loading-xs" /> : "Mark duplicate"}
            </button>
          </div>
        </div>
        {applyLinked && (
          <p className="text-xs text-base-content/50 mt-2 text-right">
            Passes <span className="mono">--linked --force</span> so PRIMARY + currently LINKED children
            share the same lifecycle status (CLI one-time bulk op).
          </p>
        )}
      </div>

      {/* First-class leaked-secret highlight for Client-Side Secret Exposure */}
      {secretExposure && secretExposure.hits?.length > 0 && (
        <SecretExposureSection exposure={secretExposure} findingId={finding.id} />
      )}

      {/* First-class original vs attack/testcase — not buried in Evidence */}
      {flowComparison && <FlowComparisonSection comparison={flowComparison} />}

      <Section title="Analyst notes">
        <textarea
          className="textarea textarea-bordered textarea-sm w-full mono text-sm min-h-[6rem]"
          value={notesDraft}
          onChange={(e) => setNotesDraft(e.target.value)}
          placeholder="Free-form triage notes (included in report)…"
        />
        <div className="flex gap-2 mt-2">
          <button
            className="btn btn-xs btn-primary"
            disabled={saveNotes.running || !notesDraft.trim()}
            onClick={async () => { await saveNotes.run(); load(); }}
          >
            {saveNotes.running ? <span className="loading loading-spinner loading-xs" /> : "Save notes"}
          </button>
          <ConfirmButton
            className="btn btn-xs btn-ghost"
            confirmText="clear notes?"
            onConfirm={async () => {
              await clearNotes.run();
              setNotesDraft("");
              load();
            }}
          >
            Clear
          </ConfirmButton>
        </div>
      </Section>

      {(parent || linked.length > 0) && (
        <Section title="Cluster">
          {parent && (
            <div className="mb-2 text-sm">
              <span className="text-xs text-base-content/50 mr-2">Primary</span>
              <Link to={findingHref(parent.id)} className="link">
                {parent.title || parent.id}
              </Link>
              <StatusBadge value={parent.status} />
            </div>
          )}
          {linked.length > 0 && (
            <ul className="space-y-1">
              {linked.map((c) => (
                <li key={c.id} className="text-sm flex flex-wrap items-center gap-2">
                  <span className="badge badge-ghost badge-xs">LINKED</span>
                  <Link to={findingHref(c.id)} className="link">
                    {c.title || c.id}
                  </Link>
                  <StatusBadge value={c.status} />
                  {c.verdict && <StatusBadge value={c.verdict} />}
                </li>
              ))}
            </ul>
          )}
        </Section>
      )}

      <Section title="Groups" action={
        <select className="select select-xs select-bordered" value="" onChange={async (e) => { if (e.target.value) { await addToGroup.run(e.target.value); e.target.value = ""; } }}>
          <option value="">Add to group…</option>
          {groups.map((g) => <option key={g.id} value={g.name}>{g.name}</option>)}
        </select>
      }>
        <p className="text-xs text-base-content/50">Manage groups from the Findings list page.</p>
      </Section>

      <Section title="Report" action={
        <button className="btn btn-xs" onClick={async () => {
          const r: any = await genReport.run();
          const step = r?.steps?.[0];
          setReportText(step?.stdout || step?.stderr || "");
        }}>Generate</button>
      }>
        {reportText && <pre className="panel p-3 mono text-xs whitespace-pre-wrap max-h-96 overflow-y-auto">{reportText}</pre>}
      </Section>

      <Section title={`Evidence (${evidence.length})`}>
        <div className="space-y-2">
          {evidence.map((e) => {
            const isFlowRef = ["original_flow", "replay_flow", "diff"].includes(e.evidence_type);
            const passiveLink =
              e.evidence_type === "source_document" && e.reference_id
                ? `${SECRETS_BASE}/documents/${e.reference_id}`
                : e.evidence_type === "passive_detection" && e.reference_id
                  ? `${SECRETS_BASE}/detections/${e.reference_id}`
                  : e.evidence_type === "source_occurrence" && e.reference_id
                    ? // occurrence is not a top-level route; open document from data if present
                      e.data?.document_id
                        ? `${SECRETS_BASE}/documents/${e.data.document_id}`
                        : null
                    : null;
            const hasRawSecret =
              e.evidence_type === "passive_detection" &&
              e.data &&
              typeof e.data.raw_value === "string" &&
              e.data.raw_value.length > 0;
            return (
              <div key={e.id} className="panel p-3">
                <div className="flex items-center gap-2 text-xs mb-1 flex-wrap">
                  <span className="badge badge-outline badge-xs" title={e.evidence_type}>
                    {evidenceTypeLabel(e.evidence_type)}
                  </span>
                  <span className="text-base-content/40 mono text-[10px]">{e.evidence_type}</span>
                  <span className="text-base-content/50">{e.created_at}</span>
                  {e.reference_id && (
                    isFlowRef ? (
                      <Link to={`/flows/${e.reference_id}`} className="link">
                        <UuidChip value={e.reference_id} />
                      </Link>
                    ) : passiveLink ? (
                      <Link to={passiveLink} className="link">
                        <UuidChip value={e.reference_id} />
                      </Link>
                    ) : (
                      <UuidChip value={e.reference_id} />
                    )
                  )}
                  {e.reference_id &&
                    (e.evidence_type === "original_flow" ||
                      e.evidence_type === "replay_flow") && (
                      <Link
                        to={`/repeater?flow=${e.reference_id}`}
                        className="link text-xs"
                      >
                        Send to Repeater
                      </Link>
                    )}
                  {passiveLink && (
                    <Link to={passiveLink} className="link text-xs">
                      open in Secret Detection
                    </Link>
                  )}
                </div>
                <div className="text-sm">{e.label}</div>
                {hasRawSecret ? (
                  <details className="mt-1">
                    <summary className="text-xs text-warning cursor-pointer">
                      Reveal secret in evidence (local only)
                    </summary>
                    <pre className="mono text-xs mt-1 text-base-content/60 whitespace-pre-wrap break-all">
                      {JSON.stringify(e.data, null, 2)}
                    </pre>
                  </details>
                ) : (
                  Object.keys(e.data || {}).length > 0 && (
                    <pre className="mono text-xs mt-1 text-base-content/60">
                      {JSON.stringify(e.data, null, 2)}
                    </pre>
                  )
                )}
              </div>
            );
          })}
          {evidence.length === 0 && <div className="text-sm text-base-content/40">No evidence recorded.</div>}
        </div>
      </Section>

      <Section title="Timeline">
        <ul className="space-y-1">
          {timeline.map((t) => (
            <li key={t.id} className="text-sm flex gap-2">
              <span className="text-base-content/40 text-xs mono w-40 shrink-0">{formatIST(t.created_at)}</span>
              <span className={`badge badge-xs ${t.actor === "system" ? "badge-ghost" : "badge-info"}`}>{t.actor}</span>
              <span>{t.event}</span>
            </li>
          ))}
          {timeline.length === 0 && <div className="text-sm text-base-content/40">No timeline events.</div>}
        </ul>
      </Section>

      {duplicates.length > 0 && (
        <Section title="Duplicates of this finding">
          <ul className="space-y-1">
            {duplicates.map((d) => (
              <li key={d.id}>
                <Link to={findingHref(d.id)} className="link text-sm">{d.title || d.id}</Link>
              </li>
            ))}
          </ul>
        </Section>
      )}
    </div>
  );
}
