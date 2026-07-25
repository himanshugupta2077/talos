import { BodyParam } from "./parseHttp";

interface Props {
  query: BodyParam[];
  bodyParams: BodyParam[];
}

export default function HttpParamsView({ query, bodyParams }: Props) {
  if (!query.length && !bodyParams.length) {
    return (
      <div className="text-xs text-base-content/40 p-2">
        No query or form body parameters.
      </div>
    );
  }
  return (
    <div className="mono text-xs space-y-3 max-h-[32rem] overflow-y-auto">
      {query.length > 0 && (
        <ParamTable title="Query" rows={query} />
      )}
      {bodyParams.length > 0 && (
        <ParamTable title="Body" rows={bodyParams} />
      )}
    </div>
  );
}

function ParamTable({ title, rows }: { title: string; rows: BodyParam[] }) {
  return (
    <div className="bg-base-300/40 rounded p-3">
      <div className="text-[10px] uppercase text-base-content/50 mb-2">{title}</div>
      <table className="table table-xs w-full">
        <thead>
          <tr>
            <th className="w-1/3">Name</th>
            <th>Value</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r, i) => (
            <tr key={`${r.name}-${i}`}>
              <td className="text-primary/80 break-all">{r.name}</td>
              <td className="break-all">{r.value || "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
