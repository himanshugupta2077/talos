import CapabilityBadges from "./CapabilityBadges";
import StateChip from "./StateChip";
import TaxonomyChips from "./TaxonomyChips";
import CandidateScore from "./CandidateScore";
import { Link } from "react-router-dom";

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
      <span className="text-base-content/50 w-24 shrink-0">{label}</span>
      <span className="min-w-0 break-words">{value ?? "—"}</span>
    </div>
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

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap gap-2 items-center">
        <span className="text-xs text-base-content/50">Capabilities</span>
        <CapabilityBadges caps={caps} />
      </div>

      {candidates.length > 0 && (
        <div className="panel p-3">
          <div className="font-medium mb-2 text-sm">Candidates (prioritization)</div>
          <div className="space-y-2">
            {[...candidates]
              .sort((a: any, b: any) => (b.score || 0) - (a.score || 0))
              .map((c: any, i: number) => (
                <div key={`${c.attack}-${i}`} className="border-b border-base-content/5 pb-2 last:border-0">
                  <div className="flex items-center gap-3 mb-1">
                    <span className="font-medium mono text-sm">{c.attack}</span>
                    <CandidateScore score={c.score} confidence={c.confidence} />
                  </div>
                  <ul className="list-disc list-inside text-xs text-base-content/70">
                    {(c.reasons || []).map((r: string, j: number) => (
                      <li key={j}>{r}</li>
                    ))}
                  </ul>
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
