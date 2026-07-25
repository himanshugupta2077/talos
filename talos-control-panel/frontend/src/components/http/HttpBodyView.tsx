import { prettyBody } from "./parseHttp";

interface Props {
  body: string | null;
  bodyEncoding?: string;
  contentType?: string;
  mode?: "raw" | "pretty";
  wrap?: boolean;
}

export default function HttpBodyView({
  body,
  bodyEncoding,
  contentType,
  mode = "pretty",
  wrap = true,
}: Props) {
  if (bodyEncoding === "base64") {
    return (
      <div className="mono text-xs bg-base-300/40 rounded p-3 max-h-[32rem] overflow-y-auto space-y-2">
        <div className="text-base-content/50">
          Binary body stored as base64 ({body?.length || 0} chars).
        </div>
        <pre className={wrap ? "whitespace-pre-wrap break-all" : "whitespace-pre overflow-x-auto"}>
          {(body || "").slice(0, 2000)}
          {(body?.length || 0) > 2000 ? "…" : ""}
        </pre>
      </div>
    );
  }

  if (body == null || body === "") {
    return <div className="text-xs text-base-content/40 p-2">Empty body.</div>;
  }

  const pretty = prettyBody(body, contentType, bodyEncoding);
  const text = mode === "raw" ? body : pretty.text;

  return (
    <pre
      className={`mono text-xs bg-base-300/40 rounded p-3 max-h-[32rem] overflow-y-auto ${
        wrap ? "whitespace-pre-wrap break-all" : "whitespace-pre overflow-x-auto"
      } ${pretty.kind === "json" && mode === "pretty" ? "text-info" : ""}`}
    >
      {text}
    </pre>
  );
}
