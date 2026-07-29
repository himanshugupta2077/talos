/**
 * Thin helpers to call /api/send mutations with CommandLog-compatible envelopes.
 */

import { api } from "../../api/client";
import type {
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
