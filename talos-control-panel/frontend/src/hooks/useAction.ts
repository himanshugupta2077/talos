/**
 * useAction — run an async Control Panel action and surface result feedback.
 *
 * Purpose:
 *   Standard wrapper for mutations / OS UI actions: loading flag + command
 *   log drawer + toast via CommandLogContext.
 * Input:
 *   label — operator-visible action name
 *   fn — returns StepsResponse ({ steps: CommandResult[] })
 * Output:
 *   { run, running }
 * Side effects:
 *   Logs steps on success; on ApiError/throw logs a failed step so failures
 *   are never silent, then rethrows so callers can skip follow-up work.
 */

import { useCallback, useState } from "react";
import { ApiError } from "../api/client";
import { useCommandLog } from "../state/CommandLogContext";
import { CommandResult, StepsResponse } from "../types";

function formatActionError(err: unknown): string {
  if (err instanceof ApiError) {
    const detail = err.body?.detail;
    if (typeof detail === "string" && detail.trim()) return detail;
    if (Array.isArray(detail)) {
      // FastAPI validation errors
      return detail
        .map((d) => (typeof d?.msg === "string" ? d.msg : JSON.stringify(d)))
        .join("; ");
    }
    if (detail != null) return JSON.stringify(detail);
    return err.message;
  }
  if (err instanceof Error) return err.message;
  return String(err);
}

function failedStep(label: string, stderr: string): CommandResult {
  return {
    cmd: [],
    cmd_str: label,
    stdout: "",
    stderr,
    exit_code: 1,
    duration_ms: 0,
    ok: false,
  };
}

export function useAction<TArgs extends any[]>(
  label: string,
  fn: (...args: TArgs) => Promise<StepsResponse>
) {
  const { log } = useCommandLog();
  const [running, setRunning] = useState(false);

  const run = useCallback(
    async (...args: TArgs) => {
      setRunning(true);
      try {
        const result = await fn(...args);
        log(label, result.steps || []);
        return result;
      } catch (err) {
        log(label, [failedStep(label, formatActionError(err))]);
        throw err;
      } finally {
        setRunning(false);
      }
    },
    [fn, label, log]
  );

  return { run, running };
}

/** Build a synthetic CommandResult for non-CLI feedback (e.g. clipboard). */
export function feedbackStep(
  cmdStr: string,
  ok: boolean,
  detail: string
): CommandResult {
  return {
    cmd: [],
    cmd_str: cmdStr,
    stdout: ok ? detail : "",
    stderr: ok ? "" : detail,
    exit_code: ok ? 0 : 1,
    duration_ms: 0,
    ok,
  };
}
