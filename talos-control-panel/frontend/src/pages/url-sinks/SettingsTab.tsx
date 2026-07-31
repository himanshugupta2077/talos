/**
 * URL Sink Discovery — Settings tab (PR5).
 *
 * Effective url_sink.* knobs via configuration API + Talos Config deep-link.
 * Mutations: POST /api/configuration/value only (no /api/url-sink/config).
 */

import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../../api/client";
import { useAction } from "../../hooks/useAction";
import { Section } from "../../components/Common";
import UrlSinkDisclaimer from "./components/UrlSinkDisclaimer";
import type { UrlSinkStatus } from "./shared";
import {
  DEFAULT_MIN_SCORE,
  TALOS_CONFIG_URL_SINK,
  inputClass,
} from "./shared";

const KEYS = {
  passive: "url_sink.passive.enabled",
  htmlJs: "url_sink.html_js.enabled",
  ivProbes: "url_sink.iv_probes.enabled",
  threshold: "url_sink.score_threshold",
} as const;

export default function SettingsTab({
  projectId,
  status,
  onRefresh,
}: {
  projectId: string;
  status: UrlSinkStatus | null;
  onRefresh: () => void;
}) {
  const [thresholdDraft, setThresholdDraft] = useState(
    String(status?.score_threshold ?? DEFAULT_MIN_SCORE),
  );
  const [sources, setSources] = useState<Record<string, string>>({});
  const [effectiveNote, setEffectiveNote] = useState<string | null>(null);

  useEffect(() => {
    if (status?.score_threshold != null) {
      setThresholdDraft(String(status.score_threshold));
    }
  }, [status?.score_threshold]);

  const loadEffective = useCallback(() => {
    api
      .get<{
        values?: Record<string, unknown>;
        sources?: Record<string, string>;
      }>("/api/configuration/effective", {
        project_id: projectId,
        section: "url_sink",
      })
      .then((r) => {
        setSources(r.sources || {});
        setEffectiveNote(null);
        const thr = r.values?.[KEYS.threshold];
        if (thr != null && thr !== "") {
          setThresholdDraft(String(thr));
        }
      })
      .catch(() => {
        setSources({});
        setEffectiveNote(
          "Could not load section=url_sink effective config; showing status strip values.",
        );
      });
  }, [projectId]);

  useEffect(() => {
    loadEffective();
  }, [loadEffective]);

  const setValue = useAction(
    "Set url_sink config",
    (key: string, value: string | boolean | number) =>
      api.post(
        "/api/configuration/value",
        { key, value, scope: "project" },
        { project_id: projectId },
      ),
  );

  const apply = async (key: string, value: string | boolean | number) => {
    await setValue.run(key, value);
    loadEffective();
    onRefresh();
  };

  const passiveOn = status?.enabled_passive !== false;
  const htmlJsOn = status?.enabled_html_js !== false;
  const ivProbesOn = status?.enabled_iv_probes !== false;
  const thr = status?.score_threshold ?? DEFAULT_MIN_SCORE;

  const sourceOf = (key: string) => sources[key] || "—";

  return (
    <div className="space-y-4">
      <UrlSinkDisclaimer />

      <p className="text-xs text-base-content/55 max-w-2xl">
        Project-scoped <span className="mono">url_sink.*</span> knobs. Changes
        use <span className="mono">talos config set</span> via{" "}
        <span className="mono">POST /api/configuration/value</span> — there is
        no separate URL-sink config store. Passive inventory is local analysis of
        already-captured parameters; IV canaries also need the IV engine and
        types analysis enabled.
      </p>

      {effectiveNote && (
        <div className="alert alert-ghost border border-base-300 text-xs py-1.5">
          {effectiveNote}
        </div>
      )}

      <div className="flex flex-wrap gap-2 items-center text-xs">
        <Link to={TALOS_CONFIG_URL_SINK} className="btn btn-xs btn-outline">
          Open Talos Config → url_sink
        </Link>
        <button
          type="button"
          className="btn btn-xs btn-ghost"
          onClick={() => {
            loadEffective();
            onRefresh();
          }}
          disabled={setValue.running}
        >
          Refresh
        </button>
      </div>

      <Section title="Engine kill-switches">
        <div className="flex flex-wrap gap-4 items-end text-sm">
          <ToggleGroup
            label="Passive inventory"
            help="url_sink.passive.enabled — score parameters on capture"
            on={passiveOn}
            source={sourceOf(KEYS.passive)}
            disabled={setValue.running}
            onSet={(v) => apply(KEYS.passive, v)}
          />
          <ToggleGroup
            label="HTML / JS structure"
            help="url_sink.html_js.enabled — extract sinks from HTML/JS bodies"
            on={htmlJsOn}
            source={sourceOf(KEYS.htmlJs)}
            disabled={setValue.running}
            onSet={(v) => apply(KEYS.htmlJs, v)}
          />
          <ToggleGroup
            label="IV URL-sink probes"
            help="url_sink.iv_probes.enabled — benign talos-canary.invalid canaries during IV"
            on={ivProbesOn}
            source={sourceOf(KEYS.ivProbes)}
            disabled={setValue.running}
            onSet={(v) => apply(KEYS.ivProbes, v)}
          />
        </div>
      </Section>

      <Section title="Score threshold">
        <p className="text-xs text-base-content/55 mb-2 max-w-xl">
          Inclusive lower bound used for{" "}
          <span className="mono">possible_network_resource</span> gating and
          default Inventory filters. Current effective:{" "}
          <span className="mono">{thr}</span> (source:{" "}
          <span className="mono">{sourceOf(KEYS.threshold)}</span>).
        </p>
        <div className="flex flex-wrap gap-2 items-end">
          <div>
            <div className="text-xs text-base-content/50 mb-1">
              url_sink.score_threshold (0–100)
            </div>
            <input
              type="number"
              min={0}
              max={100}
              className={`${inputClass} w-24`}
              value={thresholdDraft}
              onChange={(e) => setThresholdDraft(e.target.value)}
              aria-label="URL sink score threshold"
            />
          </div>
          <button
            type="button"
            className="btn btn-xs btn-primary"
            disabled={setValue.running}
            onClick={() => {
              const n = Math.max(
                0,
                Math.min(100, Number(thresholdDraft) || DEFAULT_MIN_SCORE),
              );
              setThresholdDraft(String(n));
              void apply(KEYS.threshold, n);
            }}
          >
            Set threshold
          </button>
        </div>
      </Section>

      <Section title="Operator notes">
        <ul className="text-xs text-base-content/60 list-disc pl-4 space-y-1 max-w-2xl">
          <li>
            Disabling passive stops new scoring on capture; existing{" "}
            <span className="mono">url_features</span> rows remain readable.
          </li>
          <li>
            IV canary probes require Input Validation enabled + types analysis
            and <span className="mono">url_sink.iv_probes.enabled</span>.
          </li>
          <li>
            Scores and NRS are prioritization intelligence only — never
            confirmed SSRF Findings.
          </li>
        </ul>
      </Section>
    </div>
  );
}

function ToggleGroup({
  label,
  help,
  on,
  source,
  disabled,
  onSet,
}: {
  label: string;
  help: string;
  on: boolean;
  source: string;
  disabled: boolean;
  onSet: (v: boolean) => void;
}) {
  return (
    <div className="min-w-[10rem]">
      <div className="text-xs text-base-content/50 mb-1" title={help}>
        {label}
      </div>
      <div className="flex gap-1">
        <button
          type="button"
          className={`btn btn-xs ${on ? "btn-success" : "btn-outline"}`}
          disabled={disabled || on}
          onClick={() => onSet(true)}
        >
          On
        </button>
        <button
          type="button"
          className={`btn btn-xs ${!on ? "btn-warning" : "btn-outline"}`}
          disabled={disabled || !on}
          onClick={() => onSet(false)}
        >
          Off
        </button>
      </div>
      <div className="text-[10px] text-base-content/40 mt-1 mono">
        source: {source}
      </div>
    </div>
  );
}
