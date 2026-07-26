import { useState, type ReactNode } from "react";
import {
  encodedArtifactDecodedText,
  type EncodedArtifact,
} from "./parseHttp";

interface Props {
  artifacts: EncodedArtifact[];
}

/**
 * Encoded/encrypted values from the HTTP message.
 * Each artifact is its own foldable section (e.g. two JWTs → two panels).
 * Row header: fold toggle + location + copy original / copy decoded.
 */
export default function HttpEncodedView({ artifacts }: Props) {
  if (artifacts.length === 0) {
    return (
      <div className="text-xs text-base-content/40 p-2">
        No encoded or encrypted values found in headers, cookies, query, or body.
      </div>
    );
  }

  return (
    <div className="space-y-2 max-h-[36rem] overflow-y-auto">
      <div className="text-[10px] uppercase tracking-wide text-base-content/45 px-1">
        {artifacts.length} encoded item{artifacts.length === 1 ? "" : "s"}
      </div>
      {artifacts.map((a, i) => (
        <ArtifactPanel key={a.id} artifact={a} defaultOpen={i === 0 || artifacts.length <= 3} />
      ))}
    </div>
  );
}

function ArtifactPanel({
  artifact,
  defaultOpen,
}: {
  artifact: EncodedArtifact;
  defaultOpen: boolean;
}) {
  const [open, setOpen] = useState(defaultOpen);
  const kindBadge = kindLabel(artifact.kind);
  const decodedText = encodedArtifactDecodedText(artifact);

  return (
    <div className="rounded border border-base-content/10 bg-base-300/40 overflow-hidden">
      <div className="flex items-center gap-1.5 px-2 py-1.5 min-w-0">
        <button
          type="button"
          className="flex items-center gap-2 text-left hover:bg-base-content/5 rounded px-1 py-0.5 min-w-0 flex-1 transition-colors"
          onClick={() => setOpen((o) => !o)}
          aria-expanded={open}
        >
          <span className="text-base-content/50 mono text-[11px] w-3 shrink-0">
            {open ? "▾" : "▸"}
          </span>
          <span className={`badge badge-sm shrink-0 ${kindBadge.className}`}>
            {kindBadge.text}
          </span>
          <span
            className="mono text-xs text-base-content/70 truncate min-w-0"
            title={artifact.location}
          >
            {artifact.location}
          </span>
          <SummaryChips artifact={artifact} />
        </button>
        <div className="flex items-center gap-0.5 shrink-0">
          <CopyBtn label="orig" title="Copy original" text={artifact.raw} />
          <CopyBtn
            label="dec"
            title="Copy decoded"
            text={decodedText}
            disabled={!decodedText}
          />
        </div>
      </div>
      {open && (
        <div className="px-3 pb-3 pt-1 border-t border-base-content/5 mono text-xs space-y-3">
          <ArtifactBody artifact={artifact} />
        </div>
      )}
    </div>
  );
}

function CopyBtn({
  label,
  title,
  text,
  disabled,
}: {
  label: string;
  title: string;
  text: string | null | undefined;
  disabled?: boolean;
}) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      className="btn btn-ghost btn-xs mono font-normal min-h-0 h-6 px-1.5"
      title={title}
      disabled={disabled || !text}
      onClick={(e) => {
        e.stopPropagation();
        if (!text) return;
        void navigator.clipboard.writeText(text).then(() => {
          setCopied(true);
          setTimeout(() => setCopied(false), 1000);
        });
      }}
    >
      {copied ? "ok" : label}
    </button>
  );
}

function kindLabel(kind: EncodedArtifact["kind"]): { text: string; className: string } {
  switch (kind) {
    case "jwt":
      return { text: "JWT", className: "badge-info" };
    case "jwe":
      return { text: "JWE", className: "badge-warning" };
    case "basic_auth":
      return { text: "Basic", className: "badge-secondary" };
    case "base64":
      return { text: "Base64", className: "badge-ghost" };
    default:
      return { text: kind, className: "badge-ghost" };
  }
}

function SummaryChips({ artifact }: { artifact: EncodedArtifact }) {
  if (artifact.kind === "jwt" && artifact.jwt?.claimsSummary) {
    const s = artifact.jwt.claimsSummary;
    return (
      <span className="flex flex-wrap gap-1 ml-auto shrink min-w-0 justify-end">
        {s.sub && (
          <span className="badge badge-ghost badge-xs truncate max-w-[10rem]">sub:{s.sub}</span>
        )}
        {s.exp != null && (
          <span className="badge badge-ghost badge-xs">exp:{formatExp(s.exp)}</span>
        )}
      </span>
    );
  }
  if (artifact.kind === "basic_auth" && artifact.basicAuth) {
    return (
      <span className="badge badge-ghost badge-xs ml-auto shrink-0">
        {artifact.basicAuth.username}
      </span>
    );
  }
  if (artifact.kind === "jwe" && artifact.jwe?.header) {
    const enc = artifact.jwe.header.enc;
    const alg = artifact.jwe.header.alg;
    return (
      <span className="flex gap-1 ml-auto shrink-0">
        {typeof alg === "string" && (
          <span className="badge badge-ghost badge-xs">{alg}</span>
        )}
        {typeof enc === "string" && (
          <span className="badge badge-ghost badge-xs">{enc}</span>
        )}
      </span>
    );
  }
  return <span className="ml-auto" />;
}

function formatExp(exp: number): string {
  if (exp > 1e12) return String(exp);
  try {
    return new Date(exp * 1000).toISOString();
  } catch {
    return String(exp);
  }
}

function ArtifactBody({ artifact }: { artifact: EncodedArtifact }) {
  if (artifact.kind === "jwt") {
    const jwt = artifact.jwt;
    if (!jwt) {
      return <div className="text-base-content/40">Could not decode JWT.</div>;
    }
    if (jwt.error) {
      return <div className="text-error">Decode failed: {jwt.error}</div>;
    }
    const summary = jwt.claimsSummary || {};
    return (
      <>
        {(summary.sub || summary.exp != null || summary.iss || summary.iat != null) && (
          <div className="flex flex-wrap gap-2 text-[11px] font-sans">
            {summary.sub && (
              <span className="badge badge-ghost badge-sm">sub: {summary.sub}</span>
            )}
            {summary.iss && (
              <span className="badge badge-ghost badge-sm">iss: {summary.iss}</span>
            )}
            {summary.iat != null && (
              <span className="badge badge-ghost badge-sm">
                iat: {formatExp(summary.iat)}
              </span>
            )}
            {summary.exp != null && (
              <span className="badge badge-ghost badge-sm">
                exp: {summary.exp}
                {summary.exp > 1e12 ? "" : ` (${formatExp(summary.exp)})`}
              </span>
            )}
          </div>
        )}
        <Section title="Header">{JSON.stringify(jwt.header, null, 2)}</Section>
        <Section title="Payload">{JSON.stringify(jwt.payload, null, 2)}</Section>
        <Section title="Raw token" muted>
          {jwt.token}
        </Section>
      </>
    );
  }

  if (artifact.kind === "jwe") {
    const jwe = artifact.jwe;
    if (!jwe) {
      return <div className="text-base-content/40">Could not parse JWE.</div>;
    }
    if (jwe.error) {
      return <div className="text-error">Header decode failed: {jwe.error}</div>;
    }
    return (
      <>
        <p className="text-base-content/50 font-sans text-[11px]">
          Payload is encrypted — only the JOSE header is readable without keys.
        </p>
        <Section title="Header">{JSON.stringify(jwe.header, null, 2)}</Section>
        <Section title="Raw token" muted>
          {jwe.token}
        </Section>
      </>
    );
  }

  if (artifact.kind === "basic_auth" && artifact.basicAuth) {
    return (
      <>
        <div className="grid grid-cols-[5rem_1fr] gap-x-2 gap-y-1">
          <span className="text-base-content/50">username</span>
          <span className="text-info break-all">{artifact.basicAuth.username}</span>
          <span className="text-base-content/50">password</span>
          <span className="text-info break-all">{artifact.basicAuth.password}</span>
        </div>
        <Section title="Raw" muted>
          {artifact.raw}
        </Section>
      </>
    );
  }

  if (artifact.kind === "base64") {
    const b64 = artifact.base64;
    if (!b64) {
      return <div className="text-base-content/40">Could not decode base64.</div>;
    }
    if (b64.error) {
      return <div className="text-error">{b64.error}</div>;
    }
    return (
      <>
        <Section title={b64.isJson ? "Decoded (JSON)" : "Decoded"}>{b64.decoded}</Section>
        <Section title="Raw" muted>
          {artifact.raw}
        </Section>
      </>
    );
  }

  return (
    <Section title="Raw" muted>
      {artifact.raw}
    </Section>
  );
}

function Section({
  title,
  children,
  muted,
}: {
  title: string;
  children: ReactNode;
  muted?: boolean;
}) {
  return (
    <div>
      <div className="text-[10px] uppercase text-base-content/50 mb-1 font-sans">{title}</div>
      <pre
        className={`whitespace-pre-wrap break-all ${
          muted ? "text-base-content/50" : "text-info"
        }`}
      >
        {children}
      </pre>
    </div>
  );
}
