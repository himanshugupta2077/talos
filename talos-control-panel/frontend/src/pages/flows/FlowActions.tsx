/**
 * Shared flow actions for list ⋮ menu and detail sticky rail.
 * Phase 1: only actions with real CLI/API support.
 */

import { useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { api } from "../../api/client";
import { useAction } from "../../hooks/useAction";
import { Modal } from "../../components/Common";
import { buildCurl, buildRawRequest } from "../../components/http/buildCurl";
import { Role } from "../../types";

export interface FlowActionTarget {
  id: string;
  method: string;
  host: string;
  path: string;
  query?: string;
  url?: string;
  endpoint_id?: string | null;
  request_headers?: Record<string, string>;
  request_cookies?: Record<string, string>;
  request_body?: string | null;
  request_body_encoding?: string;
}

type Variant = "menu" | "panel";

interface Props {
  flow: FlowActionTarget;
  projectId: string;
  roles: Role[];
  variant?: Variant;
  /** Close parent dropdown (list menu). */
  onDone?: () => void;
  className?: string;
}

async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

export default function FlowActions({
  flow,
  projectId,
  roles,
  variant = "panel",
  onDone,
  className = "",
}: Props) {
  const [assignOpen, setAssignOpen] = useState(false);
  const [assignRoleId, setAssignRoleId] = useState(roles[0]?.id || "");
  const [copyMsg, setCopyMsg] = useState<string | null>(null);

  const replayNow = useAction("Replay flow now", () =>
    api.post(`/api/replay/flow/${flow.id}`, { right_now: true }, { project_id: projectId })
  );
  const enqueueReplay = useAction("Enqueue flow replay", () =>
    api.post("/api/scheduler/enqueue/flow", { flow_id: flow.id }, { project_id: projectId })
  );
  const exportFlow = useAction("Export flow", () =>
    api.post(`/api/flows/${flow.id}/export`, {}, { project_id: projectId })
  );
  const setLoginFlow = useAction("Set as login flow", (roleId: string) =>
    api.post(`/api/auth-config/${roleId}/flows/${flow.id}`, {}, { project_id: projectId })
  );
  const setControlFlow = useAction("Set as control/validation flow", (roleId: string) =>
    api.post(
      `/api/auth-config/${roleId}/control-flows/${flow.id}`,
      {},
      { project_id: projectId }
    )
  );

  const flash = (msg: string) => {
    setCopyMsg(msg);
    setTimeout(() => setCopyMsg(null), 1500);
  };

  const finish = () => onDone?.();

  const onCopyUuid = async () => {
    await copyText(flow.id);
    flash("UUID copied");
    finish();
  };

  const onCopyRaw = async () => {
    const raw = buildRawRequest({
      method: flow.method,
      path: flow.path,
      query: flow.query,
      host: flow.host,
      headers: flow.request_headers,
      cookies: flow.request_cookies,
      body: flow.request_body,
    });
    await copyText(raw);
    flash("Request copied");
    finish();
  };

  const onCopyCurl = async () => {
    const url =
      flow.url ||
      `https://${flow.host}${flow.path}${flow.query ? `?${flow.query}` : ""}`;
    const curl = buildCurl({
      method: flow.method,
      url,
      headers: flow.request_headers,
      cookies: flow.request_cookies,
      body: flow.request_body,
      bodyEncoding: flow.request_body_encoding,
    });
    await copyText(curl);
    flash("curl copied");
    finish();
  };

  const itemClass =
    variant === "menu"
      ? ""
      : "btn btn-xs btn-ghost justify-start w-full font-normal";

  const wrapItem = (node: ReactNode, key: string) =>
    variant === "menu" ? <li key={key}>{node}</li> : <div key={key}>{node}</div>;

  const items = (
    <>
      {wrapItem(
        variant === "menu" ? (
          <Link to={`/repeater?flow=${flow.id}`} onClick={finish}>
            Send to Repeater
          </Link>
        ) : (
          <Link
            to={`/repeater?flow=${flow.id}`}
            className={itemClass}
            onClick={finish}
          >
            Send to Repeater
          </Link>
        ),
        "repeater"
      )}
      {wrapItem(
        <button
          type="button"
          className={itemClass}
          onClick={async () => {
            await replayNow.run();
            finish();
          }}
        >
          Replay now
        </button>,
        "replay"
      )}
      {wrapItem(
        <button
          type="button"
          className={itemClass}
          onClick={async () => {
            await enqueueReplay.run();
            finish();
          }}
        >
          Enqueue replay
        </button>,
        "enqueue"
      )}
      {wrapItem(
        <button
          type="button"
          className={itemClass}
          onClick={async () => {
            await exportFlow.run();
            finish();
          }}
        >
          Export Markdown
        </button>,
        "export"
      )}
      {wrapItem(
        <button
          type="button"
          className={itemClass}
          onClick={() => {
            setAssignRoleId(roles[0]?.id || "");
            setAssignOpen(true);
          }}
        >
          Set as login/control flow…
        </button>,
        "assign"
      )}
      {wrapItem(
        <button type="button" className={itemClass} onClick={onCopyRaw}>
          Copy request (raw)
        </button>,
        "copy-raw"
      )}
      {wrapItem(
        <button type="button" className={itemClass} onClick={onCopyCurl}>
          Copy curl
        </button>,
        "copy-curl"
      )}
      {wrapItem(
        <button type="button" className={itemClass} onClick={onCopyUuid}>
          Copy flow UUID
        </button>,
        "copy-uuid"
      )}
      {flow.endpoint_id &&
        wrapItem(
          variant === "menu" ? (
            <Link to={`/endpoints/${flow.endpoint_id}`} onClick={finish}>
              Open endpoint
            </Link>
          ) : (
            <Link
              to={`/endpoints/${flow.endpoint_id}`}
              className={itemClass}
              onClick={finish}
            >
              Open endpoint
            </Link>
          ),
          "endpoint"
        )}
      {wrapItem(
        <button
          type="button"
          className={`${itemClass} opacity-50 cursor-not-allowed`}
          title="Not available in Core yet — use Attack page for BAC/unauth"
          disabled
        >
          Replay modified / different role
        </button>,
        "disabled-mod"
      )}
    </>
  );

  return (
    <>
      {variant === "panel" ? (
        <div className={`flex flex-col gap-0.5 ${className}`}>
          <p className="text-[11px] text-base-content/50 mb-1 px-1 leading-snug">
            <strong>Send to Repeater</strong> opens Mode 2 edit → send with lineage.
            <strong> Replay</strong> re-sends the stored request as-is (Mode 1).
            Export writes Markdown via <span className="mono">talos flow export</span>.
          </p>
          {items}
          {copyMsg && (
            <div className="text-[10px] text-success px-1 mt-1">{copyMsg}</div>
          )}
          <div className="divider my-1" />
          <Link to="/testing" className="btn btn-xs btn-ghost justify-start">
            Open Testing modules (BAC / unauth)
          </Link>
        </div>
      ) : (
        <ul className={className}>{items}</ul>
      )}

      <Modal
        open={assignOpen}
        onClose={() => setAssignOpen(false)}
        title="Assign flow to a role"
      >
        <div className="flex flex-col gap-3">
          <p className="text-xs text-base-content/60">
            Login flows drive AUTO provider credential acquisition. Control flows
            are session-health validation probes — pick the role that should own
            this capture.
          </p>
          <div className="text-xs mono text-base-content/60">
            {flow.method} {flow.host}
            {flow.path}
          </div>
          <label className="form-control">
            <span className="label-text text-xs">Role</span>
            <select
              className="select select-sm select-bordered"
              value={assignRoleId}
              onChange={(e) => setAssignRoleId(e.target.value)}
            >
              {roles.map((r) => (
                <option key={r.id} value={r.id}>
                  {r.name}
                </option>
              ))}
            </select>
          </label>
          <div className="flex gap-2 flex-wrap">
            <button
              className="btn btn-sm btn-primary"
              disabled={!assignRoleId}
              onClick={async () => {
                await setLoginFlow.run(assignRoleId);
                setAssignOpen(false);
                finish();
              }}
            >
              Set as login flow
            </button>
            <button
              className="btn btn-sm"
              disabled={!assignRoleId}
              onClick={async () => {
                await setControlFlow.run(assignRoleId);
                setAssignOpen(false);
                finish();
              }}
            >
              Set as control/validation flow
            </button>
          </div>
        </div>
      </Modal>
    </>
  );
}
