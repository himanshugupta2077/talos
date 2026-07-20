import { useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { useProject } from "../../state/ProjectContext";
import { api } from "../../api/client";
import { useAction } from "../../hooks/useAction";
import { NoProjectNotice, Section, UuidChip } from "../../components/Common";
import CapabilityBadges from "./components/CapabilityBadges";
import IvDisclaimer from "./components/IvDisclaimer";
import ProbeEvidenceTable from "./components/ProbeEvidenceTable";
import ProfileCards from "./components/ProfileCards";
import { downloadJson } from "./shared";

export default function ParameterDetail() {
  const { paramUuid = "" } = useParams();
  const { selected } = useProject();
  const navigate = useNavigate();
  const [probes, setProbes] = useState<any[]>([]);
  const [profile, setProfile] = useState<any>(null);
  const [capabilities, setCapabilities] = useState<string[]>([]);
  const [summaryLines, setSummaryLines] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const load = () => {
    if (!selected || !paramUuid) return;
    setLoading(true);
    setError(null);
    api
      .get<{
        probes: any[];
        profile?: any;
        intelligence?: any;
        capabilities?: string[];
        candidates?: any[];
        summary_lines?: string[];
        error?: string;
      }>(`/api/input-validation/show/${paramUuid}`, {
        project_id: selected.id,
      })
      .then((r) => {
        if (r.error) setError(r.error);
        setProbes(r.probes || []);
        const prof =
          r.profile ||
          (r.intelligence && (r.intelligence.profile || r.intelligence)) ||
          null;
        // Merge candidates/capabilities onto profile for cards.
        if (prof) {
          if (r.capabilities?.length) prof.capabilities = r.capabilities;
          if (r.candidates?.length) prof.candidates = r.candidates;
          if (r.intelligence?.capabilities) {
            prof.capabilities = r.intelligence.capabilities;
          }
          if (r.intelligence?.candidates) {
            prof.candidates = r.intelligence.candidates;
          }
        }
        setProfile(prof);
        setCapabilities(
          r.capabilities ||
            r.intelligence?.capabilities ||
            prof?.capabilities ||
            [],
        );
        setSummaryLines(r.summary_lines || []);
      })
      .catch((e) => setError(String(e)))
      .finally(() => setLoading(false));
  };

  useEffect(load, [selected, paramUuid]);

  const synthesize = useAction("Synthesize parameter", () =>
    api.post(
      "/api/input-validation/synthesize",
      { param_uuid: paramUuid },
      { project_id: selected!.id },
    ),
  );
  const runScoped = useAction("Run IV for parameter", () =>
    api.post(
      "/api/input-validation/run",
      { parameter: paramUuid, budget: "standard" },
      { project_id: selected!.id },
    ),
  );
  const exportCli = useAction("Export parameter CLI", () =>
    api.post(
      "/api/input-validation/export/parameter",
      { parameter_uuid: paramUuid, format: "json" },
      { project_id: selected!.id },
    ),
  );

  const download = async () => {
    if (!selected) return;
    const data = await api.get(`/api/input-validation/export/parameter/${paramUuid}/json`, {
      project_id: selected.id,
    });
    downloadJson(`iv-param-${paramUuid.slice(0, 8)}.json`, data);
  };

  if (!selected) return <NoProjectNotice />;

  const name = profile?.name || profile?.param_name || "…";
  const host = profile?.host || "—";
  const location = profile?.location || "—";

  return (
    <div>
      <div className="flex flex-wrap items-start justify-between gap-3 mb-4">
        <div>
          <button className="btn btn-ghost btn-xs mb-1" onClick={() => navigate("/input-validation?tab=parameters")}>
            ← Parameters
          </button>
          <h1 className="text-xl font-semibold mono">
            {name}{" "}
            <span className="text-base-content/50 font-normal text-sm">
              {location} · {host}
            </span>
          </h1>
          <div className="flex flex-wrap items-center gap-2 mt-1 text-xs">
            <span className="text-base-content/50">param_uuid</span>
            <UuidChip value={paramUuid} />
            {profile?.schema_version != null && (
              <span className="badge badge-ghost badge-xs">
                schema {profile.schema_version}
              </span>
            )}
            {profile?.engine_version && (
              <span className="badge badge-ghost badge-xs mono">
                {profile.engine_version}
              </span>
            )}
            {profile?.budget_tier && (
              <span className="badge badge-outline badge-xs">
                {profile.budget_tier}
              </span>
            )}
            {profile?.requests_used != null && (
              <span className="badge badge-ghost badge-xs">
                req {profile.requests_used}
              </span>
            )}
          </div>
          <div className="mt-2">
            <CapabilityBadges caps={capabilities} />
          </div>
        </div>
        <div className="flex flex-wrap gap-2">
          <button
            className="btn btn-xs"
            disabled={runScoped.running}
            onClick={async () => {
              await runScoped.run();
              load();
            }}
          >
            Run scoped
          </button>
          <button
            className="btn btn-xs"
            disabled={synthesize.running}
            onClick={async () => {
              await synthesize.run();
              load();
            }}
          >
            Synthesize
          </button>
          <button className="btn btn-xs btn-primary" onClick={download}>
            Download JSON
          </button>
          <button className="btn btn-xs" onClick={() => exportCli.run()}>
            Export via CLI
          </button>
          <button className="btn btn-xs" onClick={load} disabled={loading}>
            Refresh
          </button>
        </div>
      </div>

      <IvDisclaimer />

      {error && (
        <div className="alert alert-warning text-xs mb-3">
          <span>{error}</span>
        </div>
      )}

      {summaryLines.length > 0 && (
        <Section title="Summary">
          <pre className="text-xs whitespace-pre-wrap font-mono text-base-content/80">
            {summaryLines.join("\n")}
          </pre>
        </Section>
      )}

      <Section title="Intelligence">
        <ProfileCards profile={profile} />
      </Section>

      <Section title="Evidence probes">
        <ProbeEvidenceTable probes={probes} />
      </Section>

      <details className="mt-4">
        <summary className="cursor-pointer text-xs text-base-content/50">
          Raw profile JSON
        </summary>
        <pre className="text-[10px] panel p-3 mt-2 overflow-auto max-h-96">
          {JSON.stringify(profile, null, 2)}
        </pre>
      </details>

      <div className="mt-4 text-xs">
        <Link className="link" to="/input-validation?tab=candidates">
          Back to candidates
        </Link>
      </div>
    </div>
  );
}
