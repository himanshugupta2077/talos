import { buildRawMessage } from "./parseHttp";

interface Props {
  startLine: string;
  headers: Record<string, string>;
  cookies?: Record<string, string>;
  body: string | null;
  wrap?: boolean;
}

/** Canonical raw HTTP — no cookie expand, no JWT decode. */
export default function HttpRawView({ startLine, headers, cookies, body, wrap = true }: Props) {
  const raw = buildRawMessage({ startLine, headers, cookies, body });
  return (
    <pre
      className={`mono text-xs bg-base-300/40 rounded p-3 max-h-[32rem] overflow-y-auto ${
        wrap ? "whitespace-pre-wrap break-all" : "whitespace-pre overflow-x-auto"
      }`}
    >
      {raw}
    </pre>
  );
}
