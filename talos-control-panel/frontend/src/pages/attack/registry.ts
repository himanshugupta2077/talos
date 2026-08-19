/**
 * Testing module registry — single source of truth for the Testing hub.
 *
 * Adding a new module:
 *  1. Append an entry here
 *  2. Add a route + module page under pages/attack/modules/ (or external workspace)
 *  3. Optionally wire hub KPIs in AttackHub / TestingHub
 *  4. If it should run from selected Flows / Endpoints, add it in
 *     pages/flows/flowAttacks.ts (requires Core CLI --flow first)
 *  5. Available active modules appear under Attack Module in the sidebar automatically
 *
 * Directory stays pages/attack/ for now (rename deferred); user-facing paths
 * use /testing/*.
 */

export type AttackClass = "passive" | "active";
export type ModuleStatus = "available" | "coming_soon";
export type AttackRisk = "none" | "low" | "medium" | "high";

/** Which summary endpoint powers hub KPI chips. */
export type AttackKpiSource =
  | "unauth"
  | "bac"
  | "auth_session"
  | "secrets"
  | "iv"
  | "errors"
  | "intruder"
  | "url_sinks"
  | "cors"
  | "sqli"
  | "path_traversal"
  | "smuggle";

export interface AttackModuleDef {
  id: string;
  class: AttackClass;
  name: string;
  description: string;
  /** Outbound risk to the target (passive = none). */
  risk: AttackRisk;
  status: ModuleStatus;
  /** Absolute app path for this module's workspace. */
  path: string;
  keywords: string[];
  kpi?: AttackKpiSource;
}

/** Canonical base for the Testing modules hub. */
export const TESTING_BASE = "/testing";

/** Base path for the Secret Detection workspace (nested under Testing). */
export const SECRETS_BASE = "/testing/secrets";

/** Base path for the Input Validation workspace (nested under Testing / Active). */
export const IV_BASE = "/testing/input-validation";

/** Base path for Error Intelligence workspace. */
export const ERRORS_BASE = "/testing/errors";

/** Base path for URL Sink Discovery workspace (passive inventory). */
export const URL_SINKS_BASE = "/testing/url-sinks";

/** @deprecated Use TESTING_BASE — kept for transitional imports. */
export const ATTACK_BASE = TESTING_BASE;

export const ATTACK_MODULES: AttackModuleDef[] = [
  {
    id: "secrets",
    class: "passive",
    name: "Secret Detection",
    description:
      "Scan captured client-side bodies for secrets and infrastructure disclosures. Zero outbound validation.",
    risk: "none",
    status: "available",
    path: SECRETS_BASE,
    keywords: [
      "secret",
      "passive",
      "disclosure",
      "api key",
      "token",
      "source",
    ],
    kpi: "secrets",
  },
  {
    id: "errors",
    class: "passive",
    name: "Error Intelligence",
    description:
      "Cluster error-like responses (stacks, SQL, framework pages, disclosures). Zero extra HTTP.",
    risk: "none",
    status: "available",
    path: ERRORS_BASE,
    keywords: [
      "error",
      "stack",
      "sql",
      "exception",
      "disclosure",
      "traceback",
      "passive",
      "500",
      "whitelabel",
    ],
    kpi: "errors",
  },
  {
    id: "url-sinks",
    class: "passive",
    name: "URL Sink Discovery",
    description:
      "Find parameters treated as URLs, hostnames, IPs, or network resources—regardless of name. Prioritization intelligence only.",
    risk: "none",
    status: "available",
    path: URL_SINKS_BASE,
    keywords: [
      "url",
      "ssrf",
      "redirect",
      "webhook",
      "oauth",
      "hostname",
      "sink",
      "network_resource",
      "url_features",
      "passive",
    ],
    kpi: "url_sinks",
  },
  {
    id: "unauth",
    class: "active",
    name: "Unauthenticated Execution",
    description:
      "Strip auth, apply unauth techniques and request mutations, classify SECURE / BYPASS / UNKNOWN.",
    risk: "medium",
    status: "available",
    path: `${TESTING_BASE}/unauth`,
    keywords: [
      "unauth",
      "auth bypass",
      "empty auth",
      "baseline",
      "unauthenticated",
      "malformed auth",
    ],
    kpi: "unauth",
  },
  {
    id: "bac",
    class: "active",
    name: "BAC",
    description:
      "Broken access control from the access matrix — run all technique families by default, or scope by role/module/endpoint.",
    risk: "high",
    status: "available",
    path: `${TESTING_BASE}/bac`,
    keywords: [
      "bac",
      "idor",
      "session-swap",
      "access control",
      "role-inject",
      "method-fuzz",
      "parser-confuse",
    ],
    kpi: "bac",
  },
  {
    id: "auth-session",
    class: "active",
    name: "Auth-Session Testing",
    description:
      "Mutate presented JWTs (alg, signature, claims, structure) to detect weak validation. Bind a field, pick target flows, run with the latest or a custom JWT.",
    risk: "medium",
    status: "available",
    path: `${TESTING_BASE}/auth-session`,
    keywords: [
      "auth-session",
      "jwt",
      "alg none",
      "token validation",
      "signature",
      "claims",
      "kid",
      "WEAK_VALIDATION",
      "jwt mutation",
    ],
    kpi: "auth_session",
  },
  {
    id: "iv",
    class: "active",
    name: "Input Validation",
    description:
      "Characterization intelligence — profiles, candidates, multi-level learning. Not an exploit engine.",
    risk: "medium",
    status: "available",
    path: IV_BASE,
    keywords: [
      "input validation",
      "iv",
      "xss",
      "sqli",
      "reflection",
      "parameter",
      "probe",
      "characterization",
    ],
    kpi: "iv",
  },
  {
    id: "cors",
    class: "active",
    name: "CORS Misconfiguration",
    description:
      "Probe in-scope 200 OK endpoints with mutated Origin headers. One unique replay flow per technique; one PRIMARY finding if an attacker origin is reflected.",
    risk: "medium",
    status: "available",
    path: `${TESTING_BASE}/cors`,
    keywords: [
      "cors",
      "origin",
      "access-control-allow-origin",
      "credentials",
      "misconfiguration",
      "acao",
      "acac",
    ],
    kpi: "cors",
  },
  {
    id: "sqli",
    class: "active",
    name: "SQL Injection",
    description:
      "Scan a captured flow: inject error / UNION / boolean / time payloads into query, JSON, and form fields. Optional Select DB (unknown or Microsoft SQL Server) and optional parameter. One unique replay per probe.",
    risk: "high",
    status: "available",
    path: `${TESTING_BASE}/sqli`,
    keywords: [
      "sqli",
      "sql injection",
      "union",
      "error based",
      "odbc",
      "sql server",
      "mysql",
      "payload",
    ],
    kpi: "sqli",
  },
  {
    id: "path-traversal",
    class: "active",
    name: "Path Traversal",
    description:
      "Scan a captured flow for LFI / path traversal: Unix, Windows, encoded, PHP wrapper, null-byte, and bypass payloads. Optional parameter. One unique replay per probe; shows in the Talos Burp extension.",
    risk: "high",
    status: "available",
    path: `${TESTING_BASE}/path-traversal`,
    keywords: [
      "path traversal",
      "lfi",
      "local file inclusion",
      "directory traversal",
      "/etc/passwd",
      "win.ini",
      "dotdot",
      "php://filter",
    ],
    kpi: "path_traversal",
  },
  {
    id: "smuggle",
    class: "active",
    name: "HTTP Request Smuggling",
    description:
      "Give a captured flow UUID. Raw CL/TE probes on a keep-alive connection (NTLM handshake first when configured). One unique replay per technique; shows in the Talos Burp extension.",
    risk: "high",
    status: "available",
    path: `${TESTING_BASE}/smuggle`,
    keywords: [
      "smuggle",
      "smuggling",
      "desync",
      "content-length",
      "transfer-encoding",
      "cl.te",
      "te.cl",
      "http request smuggling",
      "ntlm",
    ],
    kpi: "smuggle",
  },
  {
    id: "intruder",
    class: "active",
    name: "Intruder",
    description:
      "High-volume mutation attacks: template positions, payload sets, strategies (sniper/pitchfork/cluster bomb), scheduler-backed sessions with pause/resume.",
    risk: "high",
    status: "available",
    path: `${TESTING_BASE}/intruder`,
    keywords: [
      "intruder",
      "fuzz",
      "wordlist",
      "sniper",
      "pitchfork",
      "cluster bomb",
      "payload",
      "bruteforce",
      "mutation",
      "burp",
    ],
    kpi: "intruder",
  },
];

/** Alias during transition — same catalog as ATTACK_MODULES. */
export const TESTING_MODULES = ATTACK_MODULES;

export const ATTACK_CLASSES: {
  id: AttackClass;
  label: string;
  blurb: string;
}[] = [
  {
    id: "passive",
    label: "Passive",
    blurb: "Observe only — scan captured traffic. No outbound probes against the target.",
  },
  {
    id: "active",
    label: "Active",
    blurb: "Sends requests and may mutate auth. Run deliberately; review risk before enqueueing.",
  },
];

export function getAttackModule(id: string): AttackModuleDef | undefined {
  return ATTACK_MODULES.find((m) => m.id === id);
}

export function modulesForClass(cls: AttackClass): AttackModuleDef[] {
  return ATTACK_MODULES.filter((m) => m.class === cls);
}

/** Available workspaces of a class — used by the Attack Module sidebar subtree. */
export function availableModulesForClass(cls: AttackClass): AttackModuleDef[] {
  return ATTACK_MODULES.filter((m) => m.class === cls && m.status === "available");
}

export function filterModules(query: string): AttackModuleDef[] {
  const q = query.trim().toLowerCase();
  if (!q) return ATTACK_MODULES;
  return ATTACK_MODULES.filter((m) => {
    const hay = [
      m.id,
      m.name,
      m.description,
      m.class,
      m.risk,
      ...m.keywords,
    ]
      .join(" ")
      .toLowerCase();
    return hay.includes(q);
  });
}

export function riskBadgeClass(risk: AttackRisk): string {
  switch (risk) {
    case "none":
      return "badge-ghost";
    case "low":
      return "badge-info";
    case "medium":
      return "badge-warning";
    case "high":
      return "badge-error";
    default:
      return "badge-ghost";
  }
}

export function classBadgeClass(cls: AttackClass): string {
  return cls === "passive" ? "badge-success" : "badge-secondary";
}
