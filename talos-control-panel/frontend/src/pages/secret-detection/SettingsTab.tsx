import { useEffect, useState } from "react";
import { useAction } from "../../hooks/useAction";
import { api } from "../../api/client";
import { Section } from "../../components/Common";
import {
  AUTO_FINDING_THRESHOLDS,
  PassiveConfig,
  inputClass,
  selectClass,
} from "./shared";

const SCAN_TOGGLES: { key: keyof PassiveConfig; label: string }[] = [
  { key: "scan_html", label: "HTML" },
  { key: "scan_javascript", label: "JavaScript" },
  { key: "scan_json", label: "JSON" },
  { key: "scan_xml", label: "XML" },
  { key: "scan_text", label: "Text" },
  { key: "scan_css", label: "CSS" },
  { key: "scan_sourcemaps", label: "Source maps" },
  { key: "scan_wasm", label: "WASM" },
];

export default function SettingsTab({
  projectId,
  config,
  scannerVersion,
  onRefresh,
}: {
  projectId: string;
  config: PassiveConfig | null;
  scannerVersion?: string;
  onRefresh: () => void;
}) {
  const [threshold, setThreshold] = useState("HIGH");
  const [maxDoc, setMaxDoc] = useState("2000000");
  const [maxDepth, setMaxDepth] = useState("3");
  const [maxDecodeBytes, setMaxDecodeBytes] = useState("256000");
  const [maxCandidates, setMaxCandidates] = useState("500");
  const [queueMax, setQueueMax] = useState("500");
  const [maxScanMs, setMaxScanMs] = useState("0");

  useEffect(() => {
    if (!config) return;
    setThreshold(config.auto_finding_threshold || "HIGH");
    setMaxDoc(String(config.max_document_size ?? 2000000));
    setMaxDepth(String(config.max_decode_depth ?? 3));
    setMaxDecodeBytes(String(config.max_decode_bytes ?? 256000));
    setMaxCandidates(String(config.max_candidates_per_document ?? 500));
    setQueueMax(String(config.queue_maxsize ?? 500));
    setMaxScanMs(String(config.max_scan_time_ms ?? 0));
  }, [config]);

  const setKey = useAction("Set passive config", (key: string, value: string | boolean | number) =>
    api.post("/api/passive/config", { key, value }, { project_id: projectId }),
  );

  const apply = async (key: string, value: string | boolean | number) => {
    await setKey.run(key, value);
    onRefresh();
  };

  if (!config) {
    return <p className="text-sm text-base-content/50">Loading config…</p>;
  }

  return (
    <div className="space-y-4">
      {scannerVersion && (
        <p className="text-xs text-base-content/50 mono">
          SCANNER_VERSION = {scannerVersion}
        </p>
      )}

      <Section title="Engine">
        <div className="flex flex-wrap gap-3 items-end text-sm">
          <div>
            <div className="text-xs text-base-content/50 mb-1">Enabled</div>
            <div className="flex gap-2">
              <button
                className={`btn btn-xs ${config.enabled ? "btn-success" : "btn-outline"}`}
                disabled={setKey.running || config.enabled}
                onClick={() => apply("enabled", true)}
              >
                On
              </button>
              <button
                className={`btn btn-xs ${!config.enabled ? "btn-warning" : "btn-outline"}`}
                disabled={setKey.running || !config.enabled}
                onClick={() => apply("enabled", false)}
              >
                Off
              </button>
            </div>
          </div>
          <div>
            <div className="text-xs text-base-content/50 mb-1">Auto-finding threshold</div>
            <div className="flex gap-1">
              <select
                className={selectClass}
                value={threshold}
                onChange={(e) => setThreshold(e.target.value)}
              >
                {AUTO_FINDING_THRESHOLDS.map((t) => (
                  <option key={t} value={t}>
                    {t}
                  </option>
                ))}
              </select>
              <button
                className="btn btn-xs"
                disabled={setKey.running}
                onClick={() => apply("auto_finding_threshold", threshold)}
              >
                Apply
              </button>
            </div>
          </div>
        </div>
        <p className="text-xs text-base-content/50 mt-2">
          Default HIGH creates findings for CONFIRMED_PATTERN + HIGH secrets only.
          Infrastructure disclosures never auto-find.
        </p>
      </Section>

      <Section title="Content types">
        <div className="flex flex-wrap gap-2">
          {SCAN_TOGGLES.map(({ key, label }) => {
            const on = Boolean(config[key]);
            return (
              <button
                key={key}
                className={`btn btn-xs ${on ? "btn-primary" : "btn-ghost"}`}
                disabled={setKey.running}
                onClick={() => apply(key, !on)}
              >
                {label}: {on ? "on" : "off"}
              </button>
            );
          })}
        </div>
      </Section>

      <Section title="Limits">
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 text-sm">
          {(
            [
              ["max_document_size", maxDoc, setMaxDoc, "Max document size (bytes)"],
              ["max_decode_depth", maxDepth, setMaxDepth, "Max decode depth"],
              ["max_decode_bytes", maxDecodeBytes, setMaxDecodeBytes, "Max decode bytes"],
              [
                "max_candidates_per_document",
                maxCandidates,
                setMaxCandidates,
                "Max candidates / doc",
              ],
              ["queue_maxsize", queueMax, setQueueMax, "Queue max size"],
              ["max_scan_time_ms", maxScanMs, setMaxScanMs, "Scan time budget (ms, 0=off)"],
            ] as const
          ).map(([key, val, setVal, label]) => (
            <div key={key}>
              <div className="text-xs text-base-content/50 mb-1">{label}</div>
              <div className="flex gap-1">
                <input
                  className={`${inputClass} w-full`}
                  value={val}
                  onChange={(e) => setVal(e.target.value)}
                />
                <button
                  className="btn btn-xs"
                  disabled={setKey.running}
                  onClick={() => apply(key, Number(val) || 0)}
                >
                  Set
                </button>
              </div>
            </div>
          ))}
        </div>
      </Section>

      <Section title="Privacy & storage">
        <div className="flex flex-wrap gap-2">
          <button
            className={`btn btn-xs ${
              config.store_raw_secret_in_evidence ? "btn-warning" : "btn-ghost"
            }`}
            disabled={setKey.running}
            onClick={() =>
              apply("store_raw_secret_in_evidence", !config.store_raw_secret_in_evidence)
            }
          >
            Raw secret in finding evidence:{" "}
            {config.store_raw_secret_in_evidence ? "on" : "off"}
          </button>
          <button
            className={`btn btn-xs ${
              config.store_suppressed_detections ? "btn-outline" : "btn-ghost"
            }`}
            disabled={setKey.running}
            onClick={() =>
              apply("store_suppressed_detections", !config.store_suppressed_detections)
            }
          >
            Store suppressed: {config.store_suppressed_detections ? "on" : "off"}
          </button>
        </div>
        <p className="text-xs text-base-content/50 mt-2">
          Detection list UIs always show redacted values. Raw secrets may appear only in
          finding evidence when enabled (local workstation).
        </p>
      </Section>
    </div>
  );
}
