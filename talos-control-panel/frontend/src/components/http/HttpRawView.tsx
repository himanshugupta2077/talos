import { buildRawMessage } from "./parseHttp";

interface Props {
  startLine: string;
  headers: Record<string, string>;
  cookies?: Record<string, string>;
  body: string | null;
}

/** Canonical raw HTTP — no cookie expand, no JWT decode. Wrap always on. */
export default function HttpRawView({ startLine, headers, cookies, body }: Props) {
  const raw = buildRawMessage({ startLine, headers, cookies, body });
  return (
    <pre className="mono text-xs bg-base-300/40 rounded p-3 max-h-[32rem] overflow-y-auto whitespace-pre-wrap break-all">
      {raw}
    </pre>
  );
}
