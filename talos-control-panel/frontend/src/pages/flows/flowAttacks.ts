/**
 * Attacks that can run against operator-selected flows.
 *
 * Adding a new flow-targeted attack:
 *  1. Teach Core CLI `--flow UUID` (repeatable), then the Control Panel run API.
 *  2. Set status to "available" and implement `run` here.
 *  3. The Flows table bar, flow Actions picker, and endpoint multi-select
 *     bar pick it up automatically.
 *
 * Do not mark a module available until `--flow` is real — a project-wide
 * run from the Flows table would hit the wrong surface.
 */

import { api } from "../../api/client";
import type { StepsResponse } from "../../types";
import type { AttackClass, AttackRisk } from "../attack/registry";
import { TESTING_BASE } from "../attack/registry";

export type FlowAttackStatus = "available" | "coming_soon";

export interface FlowAttackDef {
  id: string;
  name: string;
  shortLabel: string;
  description: string;
  class: AttackClass;
  risk: AttackRisk;
  status: FlowAttackStatus;
  workspacePath: string;
  cliHint: string;
  /** Approximate scheduler jobs per selected flow when `run` is wired. */
  jobsPerFlow: number;
  run?: (projectId: string, flowIds: string[]) => Promise<StepsResponse>;
}

export const FLOW_ATTACKS: FlowAttackDef[] = [
  {
    id: "cors",
    name: "CORS Misconfiguration",
    shortLabel: "CORS",
    description: "Mutate Origin on these flows; one unique replay per technique.",
    class: "active",
    risk: "medium",
    status: "available",
    workspacePath: `${TESTING_BASE}/cors`,
    cliHint: "talos attack cors run --flow",
    jobsPerFlow: 20,
    run: (projectId, flowIds) =>
      api.post("/api/attack/cors/run", { flows: flowIds }, { project_id: projectId }),
  },
  {
    id: "sqli",
    name: "SQL Injection",
    shortLabel: "SQLi",
    description:
      "Inject SQL payloads into every query, JSON, and form field on these flows.",
    class: "active",
    risk: "high",
    status: "available",
    workspacePath: `${TESTING_BASE}/sqli`,
    cliHint: "talos attack sqli run --flow --high-priority",
    jobsPerFlow: 50,
    run: (projectId, flowIds) =>
      api.post(
        "/api/attack/sqli/run",
        { flows: flowIds, high_priority: true },
        { project_id: projectId }
      ),
  },
  {
    id: "smuggle",
    name: "HTTP Request Smuggling",
    shortLabel: "Smuggle",
    description:
      "Raw CL/TE desync probes on these flows. NTLM handshake first when platform auth is on.",
    class: "active",
    risk: "high",
    status: "available",
    workspacePath: `${TESTING_BASE}/smuggle`,
    cliHint: "talos attack smuggle run --flow",
    jobsPerFlow: 7,
    run: (projectId, flowIds) =>
      api.post("/api/attack/smuggle/run", { flows: flowIds }, { project_id: projectId }),
  },
  {
    id: "unauth",
    name: "Unauthenticated Execution",
    shortLabel: "Unauth",
    description: "Strip / mutate auth on these flows.",
    class: "active",
    risk: "medium",
    status: "available",
    workspacePath: `${TESTING_BASE}/unauth`,
    cliHint: "talos attack unauth run --flow",
    jobsPerFlow: 17,
    run: (projectId, flowIds) =>
      api.post("/api/attack/unauth/run", { flows: flowIds }, { project_id: projectId }),
  },
  {
    id: "bac",
    name: "BAC",
    shortLabel: "BAC",
    description: "Broken access-control techniques on these flows.",
    class: "active",
    risk: "high",
    status: "available",
    workspacePath: `${TESTING_BASE}/bac`,
    cliHint: "talos attack bac … --flow",
    jobsPerFlow: 32,
    run: (projectId, flowIds) =>
      api.post("/api/attack/bac/run", { flows: flowIds }, { project_id: projectId }),
  },
  {
    id: "auth-session",
    name: "Auth-Session Testing",
    shortLabel: "Auth-session",
    description:
      "Add these flows as JWT test targets. Run from Auth-Session Testing with the latest or a custom JWT.",
    class: "active",
    risk: "medium",
    status: "available",
    workspacePath: `${TESTING_BASE}/auth-session`,
    cliHint: "talos attack auth-session candidates add --flow",
    jobsPerFlow: 0,
    run: (projectId, flowIds) =>
      api.post(
        "/api/attack/auth-session/generate",
        { flows: flowIds, include_unsafe_methods: true },
        { project_id: projectId }
      ),
  },
  {
    id: "iv",
    name: "Input Validation",
    shortLabel: "IV",
    description: "Characterization probes for parameters on these flows' endpoints.",
    class: "active",
    risk: "medium",
    status: "available",
    workspacePath: `${TESTING_BASE}/input-validation`,
    cliHint: "talos input-validation run --flow",
    jobsPerFlow: 9,
    run: (projectId, flowIds) =>
      api.post("/api/input-validation/run", { flows: flowIds }, { project_id: projectId }),
  },
  {
    id: "intruder",
    name: "Intruder",
    shortLabel: "Intruder",
    description: "High-volume mutation — configure a session from a flow first.",
    class: "active",
    risk: "high",
    status: "coming_soon",
    workspacePath: `${TESTING_BASE}/intruder`,
    cliHint: "talos intruder … --flow",
    jobsPerFlow: 0,
  },
];

export function getFlowAttack(id: string): FlowAttackDef | undefined {
  return FLOW_ATTACKS.find((item) => item.id === id);
}

export function availableFlowAttacks(): FlowAttackDef[] {
  return FLOW_ATTACKS.filter((item) => item.status === "available" && item.run);
}

/** Pre-select CORS only — operator opts into the rest. */
export function defaultSelectedAttackIds(): string[] {
  return availableFlowAttacks().some((item) => item.id === "cors") ? ["cors"] : [];
}

export function estimateFlowAttackJobs(
  flowCount: number,
  attackIds: string[]
): number {
  const n = Math.max(0, flowCount);
  return attackIds.reduce((sum, id) => {
    const def = getFlowAttack(id);
    if (!def || def.status !== "available") return sum;
    return sum + n * Math.max(0, def.jobsPerFlow);
  }, 0);
}

export async function runFlowAttacks(
  projectId: string,
  flowIds: string[],
  attackIds: string[]
): Promise<StepsResponse> {
  if (!projectId) {
    throw new Error("No project selected.");
  }
  if (!flowIds.length) {
    throw new Error("Select at least one flow.");
  }
  const runnable = attackIds
    .map((id) => getFlowAttack(id))
    .filter((def): def is FlowAttackDef => Boolean(def?.run && def.status === "available"));
  if (!runnable.length) {
    throw new Error("Pick at least one available attack.");
  }
  const steps: StepsResponse["steps"] = [];
  for (const def of runnable) {
    const res = await def.run!(projectId, flowIds);
    steps.push(...(res.steps || []));
  }
  return { steps };
}
