import { CookiePair } from "./parseHttp";

interface Props {
  cookies: CookiePair[];
  emptyLabel?: string;
}

/** Cookies tab only — never re-show Cookie header row. */
export default function HttpCookiesView({
  cookies,
  emptyLabel = "No cookies.",
}: Props) {
  if (!cookies.length) {
    return <div className="text-xs text-base-content/40 p-2">{emptyLabel}</div>;
  }
  return (
    <div className="mono text-xs bg-base-300/40 rounded p-3 max-h-[32rem] overflow-y-auto">
      <table className="table table-xs w-full">
        <thead>
          <tr>
            <th className="w-1/3">Name</th>
            <th>Value</th>
            {cookies.some((c) => c.attributes) && <th className="w-1/4">Attrs</th>}
          </tr>
        </thead>
        <tbody>
          {cookies.map((c) => (
            <tr key={`${c.source}-${c.name}`}>
              <td className="text-primary/80 break-all">{c.name}</td>
              <td className="break-all">{c.value || "—"}</td>
              {cookies.some((x) => x.attributes) && (
                <td className="text-base-content/50 text-[10px] break-all">
                  {c.attributes
                    ? Object.entries(c.attributes)
                        .map(([k, v]) => (v === true ? k : `${k}=${v}`))
                        .join("; ")
                    : ""}
                </td>
              )}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
