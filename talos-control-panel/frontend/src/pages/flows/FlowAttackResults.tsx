import StatusBadge from "../../components/StatusBadge";

interface Results {
  diff?: any;
  bac?: any;
  unauth?: any;
  auth_test?: any;
}

export default function FlowAttackResults({
  results,
  // legacy aliases
  diff,
  bac_result,
  unauth_result,
  auth_test_result,
}: {
  results?: Results | null;
  diff?: any;
  bac_result?: any;
  unauth_result?: any;
  auth_test_result?: any;
}) {
  const d = results?.diff ?? diff;
  const bac = results?.bac ?? bac_result;
  const unauth = results?.unauth ?? unauth_result;
  const authTest = results?.auth_test ?? auth_test_result;

  if (!d && !bac && !unauth && !authTest) {
    return (
      <div className="text-xs text-base-content/50 p-2">
        No attack or replay-diff results for this flow.
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-2 text-sm">
      {d && (
        <div className="panel p-3">
          <div className="text-xs uppercase text-base-content/50 mb-1">
            Diff{d._from_child ? " (child)" : ""}
          </div>
          <StatusBadge value={d.verdict} />
          {d.status_diff && <div className="mono text-xs mt-1">{d.status_diff}</div>}
          {d.length_diff != null && (
            <div className="text-xs mt-1">length Δ {d.length_diff}</div>
          )}
          <p className="text-[10px] text-base-content/40 mt-1">
            Core summary only (status/length/verdict) — not a body-level diff engine.
          </p>
        </div>
      )}
      {bac && (
        <div className="panel p-3">
          <div className="text-xs uppercase text-base-content/50 mb-1">BAC</div>
          <StatusBadge value={bac.verdict} />
          <div className="text-xs mt-1">
            {bac.attack_type} / {bac.variant}
          </div>
        </div>
      )}
      {unauth && (
        <div className="panel p-3">
          <div className="text-xs uppercase text-base-content/50 mb-1">Unauth</div>
          <StatusBadge value={unauth.verdict} />
          <div className="text-xs mt-1">{unauth.auth_mutation}</div>
        </div>
      )}
      {authTest && (
        <div className="panel p-3">
          <div className="text-xs uppercase text-base-content/50 mb-1">Auth-bypass test</div>
          <StatusBadge value={authTest.verdict} />
        </div>
      )}
    </div>
  );
}
