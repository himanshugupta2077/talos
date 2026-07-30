/**
 * Intruder Testing module — high-volume mutation workbench.
 */

import ModuleShell from "../ModuleShell";
import { getAttackModule } from "../registry";
import IntruderPage from "../../intruder/IntruderPage";

const module = getAttackModule("intruder")!;

const help = (
  <div className="space-y-2">
    <p>
      <strong>What it is.</strong> High-volume mutation of one baseline request
      using named inject variables, payload generators, and strategies
      (single / sniper / pitchfork / cluster bomb). Not Repeater multi-send and
      not Input Validation probes.
    </p>
    <p>
      <strong>Why Talos has it.</strong> Scheduler-backed, resumable,
      metric-friendly campaigns with hard safety caps (default max 10k
      attempts, 2 RPS, concurrency 1).
    </p>
    <p>
      <strong>How to use.</strong> (1) Send a flow from Capture or Repeater →
      (2) Discover or add variables, attach generators, pick strategy → (3){" "}
      <strong>Save</strong> → (4) Validate / Run → triage Results (interesting
      first). Advanced: match/grep, pools, findings, timing modes.
    </p>
    <p>
      <strong>Example.</strong> Capture{" "}
      <code className="mono">GET /api/users/42</code> with path{" "}
      <code className="mono">/users/{"{user_id}"}</code> → add path var{" "}
      <code className="mono">user_id</code> → numbers or wordlist → sniper →
      Save → run at 2 RPS → filter interesting.
    </p>
    <p>
      <strong>Safety.</strong> Auth headers/cookies are mutable by default;
      logout endpoints hard-blocked; global scheduler resume ≠ Intruder
      resume; <code className="mono">all_flows</code> is expensive; wordlists
      live under the project data dir. Cluster bomb products grow fast — check
      the estimate before Run.
    </p>
    <p className="text-base-content/50">
      CLI: <code className="mono">talos intruder session …</code>
    </p>
  </div>
);

export default function IntruderModule() {
  return (
    <ModuleShell
      module={module}
      helpTitle="How Intruder works"
      help={help}
    >
      <IntruderPage />
    </ModuleShell>
  );
}
