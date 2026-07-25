import { JwtDecodeResult } from "./parseHttp";

interface Props {
  jwt: JwtDecodeResult | null;
}

/** JWT tab — decode once here, not under Headers. */
export default function HttpJwtView({ jwt }: Props) {
  if (!jwt) {
    return <div className="text-xs text-base-content/40 p-2">No JWT found in headers.</div>;
  }
  if (jwt.error) {
    return (
      <div className="text-xs text-error p-2">
        JWT present but decode failed: {jwt.error}
      </div>
    );
  }
  const summary = jwt.claimsSummary || {};
  return (
    <div className="mono text-xs bg-base-300/40 rounded p-3 max-h-[32rem] overflow-y-auto space-y-3">
      {(summary.sub || summary.exp || summary.iss) && (
        <div className="flex flex-wrap gap-2 text-[11px]">
          {summary.sub && (
            <span className="badge badge-ghost badge-sm">sub: {summary.sub}</span>
          )}
          {summary.exp != null && (
            <span className="badge badge-ghost badge-sm">
              exp: {summary.exp}
              {summary.exp > 1e12
                ? ""
                : ` (${new Date(summary.exp * 1000).toISOString()})`}
            </span>
          )}
          {summary.iss && (
            <span className="badge badge-ghost badge-sm">iss: {summary.iss}</span>
          )}
        </div>
      )}
      <div>
        <div className="text-[10px] uppercase text-base-content/50 mb-1">Header</div>
        <pre className="whitespace-pre-wrap break-all text-info">
          {JSON.stringify(jwt.header, null, 2)}
        </pre>
      </div>
      <div>
        <div className="text-[10px] uppercase text-base-content/50 mb-1">Payload</div>
        <pre className="whitespace-pre-wrap break-all text-info">
          {JSON.stringify(jwt.payload, null, 2)}
        </pre>
      </div>
    </div>
  );
}
