import { useEffect, useState } from "react";
import { useAction } from "../../hooks/useAction";
import { api } from "../../api/client";
import { ConfirmButton, Section } from "../../components/Common";
import {
  ErrorIntelConfig,
  inputClass,
} from "./shared";

export default function SettingsTab({
  projectId,
  config,
  scannerVersion,
  onRefresh,
}: {
  projectId: string;
  config: ErrorIntelConfig | null;
  scannerVersion?: string;
  onRefresh: () => void;
}) {
  const [maxBody, setMaxBody] = useState("512000");
  const [gateSniff, setGateSniff] = useState("16384");
  const [queueMax, setQueueMax] = useState("500");
  const [evidenceMax, setEvidenceMax] = useState("4096");
  const [headerNames, setHeaderNames] = useState("");
  const [rescanLimit, setRescanLimit] = useState("200");
  const [flowId, setFlowId] = useState("");

  useEffect(() => {
    if (!config) return;
    setMaxBody(String(config.max_body_scan ?? 512000));
    setGateSniff(String(config.gate_sniff_bytes ?? 16384));
    setQueueMax(String(config.queue_maxsize ?? 500));
    setEvidenceMax(String(config.evidence_snippet_max ?? 4096));
    setHeaderNames((config.error_header_names || []).join(", "));
  }, [config]);

  const setKey = useAction(
    "Set error-intel config",
    (key: string, value: string | boolean | number) =>
      api.post(
        "/api/error-intel/config",
        { key, value },
        { project_id: projectId },
      ),
  );

  const rescanOutdated = useAction("Rescan outdated", () =>
    api.post(
      "/api/error-intel/rescan",
      {
        mode: "all",
        outdated: true,
        force: false,
        limit: Number(rescanLimit) || 200,
      },
      { project_id: projectId },
    ),
  );
  const rescanForce = useAction("Force full rescan", () =>
    api.post(
      "/api/error-intel/rescan",
      {
        mode: "all",
        force: true,
        limit: Number(rescanLimit) || 200,
      },
      { project_id: projectId },
    ),
  );
  const rescanFlow = useAction("Rescan flow", () =>
    api.post(
      "/api/error-intel/rescan",
      { mode: "flow", id: flowId.trim(), force: false },
      { project_id: projectId },
    ),
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
          ERROR_INTEL_VERSION = {scannerVersion}
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
            <div className="text-xs text-base-content/50 mb-1">
              Store generic HTTP errors
            </div>
            <button
              className={`btn btn-xs ${
                config.store_generic_http_errors ? "btn-warning" : "btn-ghost"
              }`}
              disabled={setKey.running}
              onClick={() =>
                apply(
                  "store_generic_http_errors",
                  !config.store_generic_http_errors,
                )
              }
            >
              {config.store_generic_http_errors ? "on" : "off"}
            </button>
            <p className="text-xs text-base-content/50 mt-1 max-w-md">
              Stage G generic HTTP only. Default 404 chrome may still store via
              infrastructure/framework detectors (known noise).
            </p>
          </div>
        </div>
      </Section>

      <Section title="Limits">
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 text-sm">
          {(
            [
              ["max_body_scan", maxBody, setMaxBody, "Max body scan (bytes)"],
              ["gate_sniff_bytes", gateSniff, setGateSniff, "Gate sniff bytes"],
              ["queue_maxsize", queueMax, setQueueMax, "Queue max size"],
              [
                "evidence_snippet_max",
                evidenceMax,
                setEvidenceMax,
                "Evidence snippet max",
              ],
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

      <Section title="Advanced">
        <div className="text-xs text-base-content/50 mb-1">
          Error header names (comma-separated)
        </div>
        <div className="flex gap-1 max-w-xl">
          <input
            className={`${inputClass} w-full`}
            value={headerNames}
            onChange={(e) => setHeaderNames(e.target.value)}
            placeholder="X-Exception, X-Error-Message"
          />
          <button
            className="btn btn-xs"
            disabled={setKey.running}
            onClick={() =>
              apply(
                "error_header_names",
                headerNames
                  .split(",")
                  .map((s) => s.trim())
                  .filter(Boolean)
                  .join(","),
              )
            }
          >
            Set
          </button>
        </div>
      </Section>

      <Section title="Rescan">
        <p className="text-xs text-base-content/60 mb-3 max-w-2xl">
          After scanner upgrades, use <strong>Rescan outdated</strong> to
          reprocess older sightings. <strong>Force</strong> rewrites observations
          already at the current scanner version.
        </p>
        <div className="flex flex-wrap gap-2 items-end mb-3">
          <div>
            <div className="text-xs text-base-content/50 mb-1">Limit</div>
            <input
              className={`${inputClass} w-24`}
              value={rescanLimit}
              onChange={(e) => setRescanLimit(e.target.value)}
            />
          </div>
          <button
            className="btn btn-xs btn-outline"
            disabled={rescanOutdated.running}
            onClick={async () => {
              await rescanOutdated.run();
              onRefresh();
            }}
          >
            Rescan outdated
          </button>
          <ConfirmButton
            className="btn btn-xs btn-warning"
            confirmText="Force rescan recent error-like flows?"
            onConfirm={async () => {
              await rescanForce.run();
              onRefresh();
            }}
          >
            Force full rescan
          </ConfirmButton>
        </div>
        <div className="flex flex-wrap gap-2 items-end">
          <div>
            <div className="text-xs text-base-content/50 mb-1">Flow id</div>
            <input
              className={`${inputClass} w-56 mono`}
              value={flowId}
              onChange={(e) => setFlowId(e.target.value)}
              placeholder="flow uuid"
            />
          </div>
          <button
            className="btn btn-xs"
            disabled={rescanFlow.running || !flowId.trim()}
            onClick={async () => {
              await rescanFlow.run();
              onRefresh();
            }}
          >
            Rescan one flow
          </button>
        </div>
      </Section>
    </div>
  );
}
