/**
 * Thin helpers to call /api/send mutations with CommandLog-compatible envelopes.
 */

import { api } from "../../api/client";
import type {
  RepeaterTabDto,
  RepeaterTabOpenResponse,
  RepeaterTabsListResponse,
  SendDupResponse,
  SendExportResponse,
  SendMutationResponse,
  StepsResponse,
} from "../../types";
import { bytesToBase64 } from "./serializeDraft";

export async function postSendOnce(
  projectId: string,
  body: {
    parent_flow_id: string;
    rawBytes: Uint8Array;
    session_id?: string | null;
    note?: string | null;
    update_content_length?: boolean;
    profile?:
      | { type: "once" }
      | { type: "repeat"; n: number; delay_ms?: number }
      | { type: "parallel"; n: number };
  }
): Promise<SendMutationResponse & StepsResponse> {
  const res = await api.post<SendMutationResponse>(
    "/api/send/once",
    {
      parent_flow_id: body.parent_flow_id,
      source: "manual_send",
      note: body.note ?? null,
      session_id: body.session_id ?? null,
      update_content_length: body.update_content_length !== false,
      edit: {
        raw_base64: bytesToBase64(body.rawBytes),
        raw: null,
      },
      profile: body.profile || { type: "once" },
    },
    { project_id: projectId }
  );
  return res;
}

export async function postRedo(
  projectId: string,
  flowId: string,
  note?: string
): Promise<SendMutationResponse & StepsResponse> {
  return api.post<SendMutationResponse>(
    `/api/send/redo/${flowId}`,
    { note: note || "" },
    { project_id: projectId }
  );
}

export async function postDup(
  projectId: string,
  flowId: string
): Promise<SendDupResponse & StepsResponse> {
  return api.post<SendDupResponse>(
    `/api/send/dup/${flowId}`,
    {},
    { project_id: projectId }
  );
}

export async function postNote(
  projectId: string,
  flowId: string,
  note: string
): Promise<StepsResponse & { result: { ok: boolean; flow_id: string } }> {
  return api.post(
    `/api/send/note/${flowId}`,
    { note },
    { project_id: projectId }
  );
}

export async function postExport(
  projectId: string,
  flowId: string
): Promise<SendExportResponse & StepsResponse> {
  return api.post<SendExportResponse>(
    `/api/send/export/${flowId}`,
    {},
    { project_id: projectId }
  );
}

// ------------------------------------------------------------------ #
// Tab archive (project DB; sticky Repeater workspaces)                #
// ------------------------------------------------------------------ #

export async function listRepeaterTabs(
  projectId: string
): Promise<RepeaterTabsListResponse> {
  return api.get<RepeaterTabsListResponse>("/api/send/tabs", {
    project_id: projectId,
  });
}

export async function openRepeaterTab(
  projectId: string,
  body: {
    flow_id: string;
    title?: string;
    session_id?: string | null;
    force_new?: boolean;
  }
): Promise<RepeaterTabOpenResponse> {
  return api.post<RepeaterTabOpenResponse>(
    "/api/send/tabs",
    {
      flow_id: body.flow_id,
      title: body.title ?? null,
      session_id: body.session_id ?? null,
      force_new: !!body.force_new,
    },
    { project_id: projectId }
  );
}

export async function closeRepeaterTab(
  projectId: string,
  tabId: string
): Promise<StepsResponse & { result: { id: string; closed: boolean } }> {
  return api.del(`/api/send/tabs/${tabId}`, { project_id: projectId });
}

export async function clearRepeaterTabs(
  projectId: string
): Promise<StepsResponse & { result: { cleared: number } }> {
  return api.del("/api/send/tabs", { project_id: projectId });
}

export async function touchRepeaterTab(
  projectId: string,
  tabId: string,
  body: {
    parent_flow_id?: string | null;
    session_id?: string | null;
    clear_session?: boolean;
    last_execution_id?: string | null;
    clear_last_execution?: boolean;
  }
): Promise<StepsResponse & { result: { tab: RepeaterTabDto } }> {
  return api.post(
    `/api/send/tabs/${tabId}/touch`,
    {
      parent_flow_id: body.parent_flow_id ?? null,
      session_id: body.session_id ?? null,
      clear_session: !!body.clear_session,
      last_execution_id: body.last_execution_id ?? null,
      clear_last_execution: !!body.clear_last_execution,
    },
    { project_id: projectId }
  );
}
