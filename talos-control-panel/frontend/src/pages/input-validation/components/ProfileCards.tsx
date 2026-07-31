import CapabilityBadges from "./CapabilityBadges";
import StateChip from "./StateChip";
import TaxonomyChips from "./TaxonomyChips";
import CandidateScore from "./CandidateScore";
import { Link } from "react-router-dom";
import {
  NrsBadge,
  SinkCategoryBadge,
  UrlScoreChip,
} from "../../../components/url-sink";
import { inventoryHref } from "../../url-sinks/shared";

function Card({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="panel p-3 text-xs h-full">
      <div className="font-medium mb-2 text-sm">{title}</div>
      {children}
    </div>
  );
}

function field(label: string, value: React.ReactNode) {
  return (
    <div className="flex gap-2 mb-1">
      <span className="text-base-content/50 w-28 shrink-0">{label}</span>
      <span className="min-w-0 break-words">{value ?? "—"}</span>
    </div>
  );
}

function boolDot(v: boolean | null | undefined, label: string) {
  const on = v === true;
  return (
    <span
      className={`inline-flex items-center gap-1 mr-2 ${on ? "text-base-content" : "text-base-content/35"}`}
      title={label}
    >
      <span className={on ? "text-success" : "text-base-content/25"}>{on ? "●" : "○"}</span>
      {label}
    </span>
  );
}

export default function ProfileCards({ profile }: { profile: any }) {
  if (!profile) {
    return (
      <div className="text-sm text-base-content/50">
        No intelligence profile yet. Run probes, then Synthesize.
      </div>
    );
  }

  const observed = profile.observed || {};
  const reflection = observed.reflection || {};
  const length = observed.length || {};
  const types = observed.types || {};
  const acceptance = observed.acceptance || {};
  const classes = acceptance.classes || {};
  const urlFeatures =
    (observed.url_features && typeof observed.url_features === "object"
      ? observed.url_features
      : null) ||
    (profile.url_features && typeof profile.url_features === "object"
      ? profile.url_features
      : {}) ||
    {};
  const urlSink =
    (observed.url_sink && typeof observed.url_sink === "object"
      ? observed.url_sink
      : {}) || {};
  const parser =
    observed.parser ||
    profile.parser ||
    {};
  const pipeline: any[] =
    profile.normalization_pipeline ||
    observed.normalization_pipeline ||
    [];
  const timing = observed.timing || {};
  const semantic = observed.semantic || profile.inferred?.semantic || {};
  const tested = profile.tested || {};
  const candidates = profile.candidates || [];
  const caps = profile.capabilities || [];

  const primaryType =
    types?._summary?.primary ||
    types?.primary?.state ||
    types?.primary?.outcome ||
    "—";

  const hasUrlFeatures =
    Object.keys(urlFeatures).length > 0 &&
    (Number(urlFeatures.score) > 0 ||
      urlFeatures.possible_network_resource ||
      urlFeatures.name_category ||
      (Array.isArray(urlFeatures.looks_like) && urlFeatures.looks_like.length > 0));
  const hasUrlSink =
    Object.keys(urlSink).length > 0 &&
    (Number(urlSink.confidence) > 0 ||
      urlSink.accepts_url ||
      urlSink.redirect_behavior ||
      urlSink.fetch_behavior ||
      (Array.isArray(urlSink.per_probe) && urlSink.per_probe.length) ||
      (urlSink.per_probe && typeof urlSink.per_probe === "object" && Object.keys(urlSink.per_probe).length > 0));

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap gap-2 items-center">
        <span className="text-xs text-base-content/50">Capabilities</span>
        <CapabilityBadges caps={caps} />
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        <Card title="Passive URL features">
          <p className="text-base-content/50 mb-2">
            From captured values/names — prioritization only, not a Finding.
          </p>
          {hasUrlFeatures ? (
            <>
              {field("Score", <UrlScoreChip score={urlFeatures.score as number} />)}
              {field("NRS", <NrsBadge nrs={!!urlFeatures.possible_network_resource} />)}
              {field(
                "Category",
                <SinkCategoryBadge
                  category={
                    (urlFeatures.name_category as string) ||
                    (Array.isArray(urlFeatures.name_categories)
                      ? (urlFeatures.name_categories[0] as string)
                      : null)
                  }
                />,
              )}
              {field(
                "Looks like",
                Array.isArray(urlFeatures.looks_like) && urlFeatures.looks_like.length
                  ? (urlFeatures.looks_like as string[]).join(", ")
                  : "—",
              )}
              {field(
                "Protocols",
                Array.isArray(urlFeatures.protocols_seen) && urlFeatures.protocols_seen.length
                  ? (urlFeatures.protocols_seen as string[]).join(", ")
                  : "—",
              )}
              {field(
                "Evidence",
                Array.isArray(urlFeatures.evidence) && urlFeatures.evidence.length
                  ? (urlFeatures.evidence as string[]).slice(0, 8).join(", ")
                  : "—",
              )}
              <div className="mt-2">
                <Link
                  to={inventoryHref({
                    search: String(profile.name || profile.parameter_name || ""),
                    host: String(profile.host || ""),
                    nrs_only: false,
                    min_score: 0,
                  })}
                  className="link text-[11px]"
                >
                  Open in URL sink inventory
                </Link>
              </div>
            </>
          ) : (
            <span className="text-base-content/40">
              No passive URL features on this profile yet (older capture or score 0).{" "}
              <Link
                to={inventoryHref({ nrs_only: true })}
                className="link"
              >
                URL Sink inventory
              </Link>
            </span>
          )}
        </Card>

        <Card title="Active URL sink (canaries)">
          <p className="text-base-content/50 mb-2">
            Benign characterization probes (<span className="mono">talos-canary.invalid</span>).
            Accept/redirect/fetch/DNS signals are behavioral evidence for prioritization, not
            confirmed SSRF.
          </p>
          {hasUrlSink ? (
            <>
              {field("Confidence", urlSink.confidence ?? "—")}
              {field(
                "Accepts",
                <span className="flex flex-wrap gap-y-1">
                  {boolDot(urlSink.accepts_url, "url")}
                  {boolDot(urlSink.accepts_hostname, "hostname")}
                  {boolDot(urlSink.accepts_ip, "ip")}
                  {boolDot(urlSink.accepts_path, "path")}
                  {boolDot(urlSink.accepts_unc, "unc")}
                  {boolDot(urlSink.accepts_protocol, "protocol")}
                </span>,
              )}
              {field(
                "Accepted protocols",
                Array.isArray(urlSink.accepted_protocols) && urlSink.accepted_protocols.length
                  ? (urlSink.accepted_protocols as string[]).join(", ")
                  : "—",
              )}
              {field(
                "Redirect",
                urlSink.redirect_behavior === true
                  ? "yes"
                  : urlSink.redirect_behavior === false
                    ? "no"
                    : "—",
              )}
              {field(
                "Fetch",
                urlSink.fetch_behavior === true
                  ? "yes"
                  : urlSink.fetch_behavior === false
                    ? "no"
                    : "—",
              )}
              {field(
                "DNS detected",
                urlSink.dns_resolution_detected === true
                  ? "yes"
                  : urlSink.dns_resolution_detected === false
                    ? "no"
                    : "—",
              )}
              {field("Validation", urlSink.validation_behavior || "—")}
              {field(
                "Error classes",
                Array.isArray(urlSink.error_classes) && urlSink.error_classes.length
                  ? (urlSink.error_classes as string[]).join(", ")
                  : "—",
              )}
            </>
          ) : (
            <span className="text-base-content/40">
              No active URL-sink characterization yet. Run IV (types + url_sink probes) then
              Synthesize.
            </span>
          )}
        </Card>
      </div>

      {candidates.length > 0 && (
        <div className="panel p-3">
          <div className="font-medium mb-2 text-sm">Candidates (prioritization)</div>
          <div className="space-y-2">
            {[...candidates]
              .sort((a: any, b: any) => (b.score || 0) - (a.score || 0))
              .map((c: any, i: number) => (
                <div key={`${c.attack}-${i}`} className="border-b border-base-content/5 pb-2 last:border-0">
                  <div className="flex items-center gap-3 mb-1 flex-wrap">
                    <span className="font-medium mono text-sm">{c.attack}</span>
                    <CandidateScore score={c.score} confidence={c.confidence} />
                    {(c.reflection_modes || []).length > 0 && (
                      <span className="badge badge-ghost badge-xs mono">
                        {(c.reflection_modes as string[]).join("+")}
                      </span>
                    )}
                  </div>
                  <ul className="list-disc list-inside text-xs text-base-content/70">
                    {(c.reasons || []).map((r: string, j: number) => (
                      <li key={j}>{r}</li>
                    ))}
                  </ul>
                  {c.stored_reflection?.sinks?.length > 0 && (
                    <div className="mt-2">
                      <div className="text-base-content/50 mb-1">
                        Stored / cross-page sinks (data-flow evidence)
                      </div>
                      <ul className="list-disc list-inside text-xs">
                        {(c.stored_reflection.sinks as any[]).slice(0, 5).map((s, j) => (
                          <li key={j} className="mono">
                            {s.reason ||
                              `${s.method || ""} ${s.path || ""} (${s.context || "other"}, ${s.encoding || "raw"})`.trim()}
                            {s.flow_id && (
                              <>
                                {" "}
                                <Link className="link" to={`/flows/${s.flow_id}`}>
                                  {String(s.flow_id).slice(0, 8)}
                                </Link>
                              </>
                            )}
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                  {(c.evidence_flow_ids || []).length > 0 && (
                    <div className="mt-1 flex flex-wrap gap-1">
                      {(c.evidence_flow_ids as string[]).slice(0, 6).map((fid) => (
                        <Link key={fid} className="link mono text-xs" to={`/flows/${fid}`}>
                          {fid.slice(0, 8)}
                        </Link>
                      ))}
                    </div>
                  )}
                </div>
              ))}
          </div>
        </div>
      )}

      {reflection.cross_flow &&
        typeof reflection.cross_flow === "object" &&
        Array.isArray((reflection.cross_flow as { sinks?: unknown[] }).sinks) &&
        ((reflection.cross_flow as { sinks: any[] }).sinks || []).length > 0 && (
          <Card title="Stored / cross-page sinks">
            <p className="text-base-content/50 mb-2">
              Data-flow prioritization evidence — not confirmed XSS.
            </p>
            <ul className="list-disc list-inside space-y-1">
              {((reflection.cross_flow as { sinks: any[] }).sinks || [])
                .slice(0, 8)
                .map((s: any, i: number) => (
                  <li key={i} className="mono">
                    {s.reason ||
                      `${s.sink_method || s.method || ""} ${s.sink_path || s.path || ""}`.trim() ||
                      "sink"}
                    {(s.sink_flow_id || s.flow_id) && (
                      <>
                        {" "}
                        <Link
                          className="link"
                          to={`/flows/${s.sink_flow_id || s.flow_id}`}
                        >
                          {String(s.sink_flow_id || s.flow_id).slice(0, 8)}
                        </Link>
                      </>
                    )}
                  </li>
                ))}
            </ul>
          </Card>
        )}

      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-3">
        <Card title="Reflection">
          {field("State", <StateChip state={reflection.state} kind="reflection" />)}
          {field("Confidence", reflection.confidence ?? "—")}
          {field("Uncertainty", reflection.uncertainty ?? "—")}
          {field(
            "Contexts",
            (reflection.contexts || []).length
              ? (reflection.contexts as string[]).join(", ")
              : "—",
          )}
          {field(
            "Modes",
            (reflection.modes || []).length
              ? (reflection.modes as string[]).join(", ")
              : "—",
          )}
          {reflection.same_request && typeof reflection.same_request === "object" && (
            <>
              {field(
                "Same-request",
                <StateChip
                  state={(reflection.same_request as { state?: string }).state}
                  kind="reflection"
                />,
              )}
            </>
          )}
          {reflection.cross_flow && typeof reflection.cross_flow === "object" && (
            <>
              {field(
                "Cross-flow",
                <StateChip
                  state={(reflection.cross_flow as { state?: string }).state}
                  kind="reflection"
                />,
              )}
              {field(
                "Link count",
                (() => {
                  const cf = reflection.cross_flow as {
                    link_count?: number;
                    sinks?: unknown[];
                  };
                  if (cf.link_count != null) return cf.link_count;
                  const n = (cf.sinks || []).length;
                  return n > 0 ? n : "—";
                })(),
              )}
            </>
          )}
        </Card>

        <Card title="Types">
          {field("Primary", <span className="mono">{primaryType}</span>)}
          {field(
            "Labels",
            Object.keys(types)
              .filter((k) => !k.startsWith("_"))
              .slice(0, 8)
              .join(", ") || "—",
          )}
        </Card>

        <Card title="Length">
          {field("State", <StateChip state={length.state} />)}
          {field("Max accepted", length.max_accepted ?? "—")}
          {field("Confidence", length.confidence ?? "—")}
        </Card>

        <Card title="Timing">
          {field(
            "Samples",
            Array.isArray(timing.samples_ms) ? timing.samples_ms.length : "—",
          )}
          {field("Mean ms", timing.mean_ms ?? "—")}
        </Card>
      </div>

      <Card title="Acceptance classes (taxonomy)">
        <TaxonomyChips classes={classes} />
      </Card>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        <Card title="Parser">
          {Object.keys(parser).length === 0 ? (
            <span className="text-base-content/40">No parser fingerprint yet.</span>
          ) : (
            Object.entries(parser)
              .slice(0, 12)
              .map(([k, v]) =>
                field(
                  k,
                  typeof v === "object" ? JSON.stringify(v).slice(0, 80) : String(v),
                ),
              )
          )}
        </Card>

        <Card title="Normalization pipeline">
          {!pipeline.length ? (
            <span className="text-base-content/40">No stages detected.</span>
          ) : (
            <ol className="list-decimal list-inside space-y-1">
              {pipeline.map((stage: any, i: number) => (
                <li key={i}>
                  <span className="mono">
                    {typeof stage === "string" ? stage : stage.stage || stage.name || JSON.stringify(stage)}
                  </span>
                  {typeof stage === "object" && stage.confidence != null && (
                    <span className="text-base-content/50"> conf {stage.confidence}</span>
                  )}
                </li>
              ))}
            </ol>
          )}
          {semantic && Object.keys(semantic).length > 0 && (
            <div className="mt-3 pt-2 border-t border-base-content/10">
              <div className="font-medium mb-1">Semantic</div>
              <pre className="text-[10px] overflow-auto max-h-24">
                {JSON.stringify(semantic, null, 2)}
              </pre>
            </div>
          )}
        </Card>
      </div>

      <Card title="Negative evidence (tested)">
        {Object.keys(tested).length === 0 ? (
          <span className="text-base-content/40">None recorded yet.</span>
        ) : (
          <div className="overflow-x-auto">
            <table className="table table-xs table-tight">
              <thead>
                <tr>
                  <th>Family</th>
                  <th>Outcome</th>
                  <th>Conf</th>
                </tr>
              </thead>
              <tbody>
                {Object.entries(tested).map(([k, v]: [string, any]) => (
                  <tr key={k}>
                    <td className="mono">{k}</td>
                    <td>
                      <StateChip
                        state={typeof v === "object" ? v?.outcome : String(v)}
                        kind="outcome"
                      />
                    </td>
                    <td>{typeof v === "object" ? v?.confidence ?? "—" : "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}
