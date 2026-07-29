"""
Module: talos.projects.db

Purpose:
    Initialize and manage the per-project SQLite database.
    Each project gets exactly one database at <data_dir>/talos.db.
    This module owns schema creation — no other module may ALTER TABLE directly.

Dependencies: sqlite3, pathlib, uuid
Data flow:
    ProjectManager calls init_project_db() after creating a project directory.
    All other subsystems (flows, sessions, endpoints) receive the db_path and
    open their own connections — this module does NOT hold a persistent connection.
Side effects:
    - Creates the SQLite file on disk.
    - Enables WAL mode for concurrent read access.
"""

import sqlite3
import uuid
from pathlib import Path


SCHEMA_VERSION = 51

_DDL = """
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_version (
    version     INTEGER NOT NULL
);

-- ------------------------------------------------------------------ --
-- flows: raw captured HTTP exchanges                                  --
-- ------------------------------------------------------------------ --
CREATE TABLE IF NOT EXISTS flows (
    id                       TEXT    PRIMARY KEY,  -- UUID
    project_id               TEXT    NOT NULL,
    captured_at              TEXT    NOT NULL,     -- UTC ISO-8601 (request_start)
    response_end             TEXT,                 -- UTC ISO-8601 (nullable if response absent)
    method                   TEXT    NOT NULL,
    url                      TEXT    NOT NULL,
    host                     TEXT    NOT NULL,
    path                     TEXT    NOT NULL,
    query                    TEXT    NOT NULL DEFAULT '',
    request_headers          TEXT    NOT NULL DEFAULT '{}',   -- JSON
    request_cookies          TEXT    NOT NULL DEFAULT '{}',   -- JSON
    request_body             BLOB,
    request_body_truncated   INTEGER NOT NULL DEFAULT 0,      -- boolean
    status_code              INTEGER,
    response_headers         TEXT    NOT NULL DEFAULT '{}',   -- JSON
    response_body            BLOB,
    response_body_truncated  INTEGER NOT NULL DEFAULT 0,      -- boolean
    content_type             TEXT    NOT NULL DEFAULT '',
    session_id               TEXT,                            -- FK to sessions.id (nullable until resolved)
    endpoint_id              TEXT,                            -- FK to endpoints.id (nullable until normalized)
    role_id                  TEXT    NOT NULL REFERENCES roles(id),   -- resolved at capture-time
    module_id                TEXT    NOT NULL REFERENCES modules(id), -- resolved at capture-time
    tags                     TEXT    NOT NULL DEFAULT '[]',   -- JSON array
    source                   TEXT    NOT NULL DEFAULT 'proxy_capture', -- proxy_capture | manual_replay | auto_replay | iv_scan | manual_send | ai_send
    original_flow_id         TEXT,                                      -- FK to flows.id; NULL for proxy_capture flows
    replay_error             TEXT,                                      -- NULL on success; error label on network/HTTP failure
    replay_reason            TEXT,                                      -- NULL for proxy_capture; e.g. testing | bac_test | input_validation | manual_probe
    flow_meta                TEXT    NOT NULL DEFAULT '{}'               -- JSON: structured metadata describing why this flow was generated
);

-- ------------------------------------------------------------------ --
-- endpoints: normalized, deduplicated request shapes                  --
-- host stores canonical origin (scheme://authority) so non-default    --
-- ports and schemes remain distinct application identities:           --
--   http://test.com:8000/api  ≠  http://test.com:9000/api             --
-- Identity: method + host(canonical origin) + normalized_path         --
-- ------------------------------------------------------------------ --
CREATE TABLE IF NOT EXISTS endpoints (
    id              TEXT    PRIMARY KEY,     -- UUID
    project_id      TEXT    NOT NULL,
    method          TEXT    NOT NULL,
    host            TEXT    NOT NULL,        -- canonical origin, e.g. http://example.com:8000
    path            TEXT    NOT NULL,
    normalized_path TEXT    NOT NULL,
    content_type    TEXT    NOT NULL DEFAULT '',
    auth_required   INTEGER NOT NULL DEFAULT 0,  -- boolean
    roles_seen      TEXT    NOT NULL DEFAULT '[]',  -- JSON array
    first_seen      TEXT    NOT NULL,
    last_seen       TEXT    NOT NULL,
    UNIQUE (project_id, method, host, normalized_path)
);

-- ------------------------------------------------------------------ --
-- parameters: per-endpoint parameter intelligence                     --
-- Expanded in v25: semantic_type, seen_count, role/module tracking,   --
-- and passive reflection intelligence (is_reflected, reflection_count, --
-- reflection_locations, reflection_encoding).                          --
-- ------------------------------------------------------------------ --
CREATE TABLE IF NOT EXISTS parameters (
    id                   TEXT    PRIMARY KEY,     -- UUID
    endpoint_id          TEXT    NOT NULL REFERENCES endpoints(id),
    name                 TEXT    NOT NULL,
    location             TEXT    NOT NULL,        -- path | query | body | header | cookie
    param_type           TEXT    NOT NULL DEFAULT 'unknown',  -- int|float|bool|string|unknown
    semantic_type        TEXT    NOT NULL DEFAULT 'unknown',  -- uuid|jwt|email|objectid|url|ip|hash|timestamp|filename|boolean|integer|float|array|string|unknown
    source               TEXT    NOT NULL DEFAULT 'unknown',  -- user-controlled | server-generated
    volatility           TEXT    NOT NULL DEFAULT 'unknown',  -- static | dynamic
    sensitivity          TEXT    NOT NULL DEFAULT 'unknown',  -- identifier | control | data
    example_values       TEXT    NOT NULL DEFAULT '[]',       -- JSON array (sampled)
    seen_count           INTEGER NOT NULL DEFAULT 1,          -- number of flows where observed
    appears_in_roles     TEXT    NOT NULL DEFAULT '[]',       -- JSON array of role UUIDs
    appears_in_modules   TEXT    NOT NULL DEFAULT '[]',       -- JSON array of module UUIDs
    is_reflected         INTEGER NOT NULL DEFAULT 0,          -- boolean: value seen in response (same-flow only)
    reflection_count     INTEGER NOT NULL DEFAULT 0,          -- how many times reflected (same-flow)
    reflection_locations TEXT    NOT NULL DEFAULT '[]',       -- JSON array: html|json|xml|javascript|other
    reflection_encoding  TEXT    NOT NULL DEFAULT '[]',       -- JSON array: raw|html_encoded|url_encoded|other
    cross_flow_reflected       INTEGER NOT NULL DEFAULT 0,    -- boolean: value seen in another flow's response
    cross_flow_reflection_count INTEGER NOT NULL DEFAULT 0,   -- count of cross-flow reflection observations
    cross_flow_sink_endpoints  TEXT    NOT NULL DEFAULT '[]', -- JSON array of sink endpoint ids
    UNIQUE (endpoint_id, name, location)
);

-- ------------------------------------------------------------------ --
-- input_validation_config: per-project IV engine configuration        --
-- enabled: 0=disabled (default), 1=enabled                           --
-- workers: number of concurrent analysis workers                      --
-- analyses_*: per-phase toggles (1=enabled, 0=disabled)              --
-- excluded_hosts: JSON list of host strings                           --
-- excluded_endpoints: JSON list of endpoint UUIDs                    --
-- ------------------------------------------------------------------ --
CREATE TABLE IF NOT EXISTS input_validation_config (
    id                         TEXT    PRIMARY KEY DEFAULT 'default',
    enabled                    INTEGER NOT NULL DEFAULT 0,
    workers                    INTEGER NOT NULL DEFAULT 2,
    analyses_baseline          INTEGER NOT NULL DEFAULT 1,
    analyses_multiprobe        INTEGER NOT NULL DEFAULT 1,
    analyses_identifier        INTEGER NOT NULL DEFAULT 1,
    analyses_characters        INTEGER NOT NULL DEFAULT 1,
    analyses_length            INTEGER NOT NULL DEFAULT 1,
    analyses_types             INTEGER NOT NULL DEFAULT 1,
    analyses_transformations   INTEGER NOT NULL DEFAULT 1,
    analyses_reflection        INTEGER NOT NULL DEFAULT 1,
    analyses_validation        INTEGER NOT NULL DEFAULT 1,
    probe_strategy             TEXT    NOT NULL DEFAULT 'standard',
    max_requests_per_param     INTEGER NOT NULL DEFAULT 0,
    include_auth_artifacts     INTEGER NOT NULL DEFAULT 0,
    excluded_hosts             TEXT    NOT NULL DEFAULT '[]',
    excluded_endpoints         TEXT    NOT NULL DEFAULT '[]'
);

-- ------------------------------------------------------------------ --
-- iv_param_cache: per-parameter analysis results                       --
-- Cache key: host + location + param_name                             --
-- Analysis phases are stored individually so partial runs are         --
-- resumable without re-running completed phases.                       --
-- ------------------------------------------------------------------ --
CREATE TABLE IF NOT EXISTS iv_param_cache (
    id                TEXT PRIMARY KEY,   -- UUID
    host              TEXT NOT NULL,
    location          TEXT NOT NULL,      -- path|query|body|header|cookie
    param_name        TEXT NOT NULL,
    phase             TEXT NOT NULL,      -- baseline|identifier|characters|length|types|transformations|validation
    status            TEXT NOT NULL DEFAULT 'not_started',  -- not_started|running|completed|failed|skipped|partial
    result            TEXT NOT NULL DEFAULT '{}',            -- JSON blob of phase findings
    flow_id           TEXT,                                  -- UUID of the base flow used for this analysis
    started_at        TEXT,
    completed_at      TEXT,
    UNIQUE (host, location, param_name, phase)
);

CREATE INDEX IF NOT EXISTS idx_iv_param_cache_host
    ON iv_param_cache (host);

-- ------------------------------------------------------------------ --
-- iv_reflection_cache: per-endpoint reflection results                 --
-- Reflection cannot be shared across endpoints — must be per-endpoint. --
-- ------------------------------------------------------------------ --
CREATE TABLE IF NOT EXISTS iv_reflection_cache (
    id           TEXT PRIMARY KEY,  -- UUID
    endpoint_id  TEXT NOT NULL REFERENCES endpoints(id),
    param_name   TEXT NOT NULL,
    location     TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'not_started',
    result       TEXT NOT NULL DEFAULT '{}',
    flow_id      TEXT,               -- UUID of the base flow used for this analysis
    started_at   TEXT,
    completed_at TEXT,
    UNIQUE (endpoint_id, param_name, location)
);

CREATE INDEX IF NOT EXISTS idx_iv_reflection_endpoint
    ON iv_reflection_cache (endpoint_id);

-- ------------------------------------------------------------------ --
-- iv_probe_results: per-HTTP-request IV evidence                       --
-- Each probe sent during input validation produces one row here and   --
-- one replay flow in the flows table.  HTTP response data (status,     --
-- body, content-type) is stored only in the flows table; this table   --
-- holds only the analysis-level identity fields.                       --
-- param_uuid   : sha256(host|location|param_name)[:32] — shared key  --
-- analysis     : baseline|identifier|characters|length|types|validation
-- payload      : exact string value injected into the parameter.      --
-- payload_type : baseline|identifier|character|length|type|validation --
-- flow_id      : FK to flows.id — the replay flow created.           --
-- ------------------------------------------------------------------ --
CREATE TABLE IF NOT EXISTS iv_probe_results (
    id           TEXT    PRIMARY KEY,    -- UUID
    param_uuid   TEXT    NOT NULL,       -- sha256-derived UUID for the parameter
    endpoint_id  TEXT,                   -- FK to endpoints.id (NULL for host-level)
    host         TEXT    NOT NULL,
    location     TEXT    NOT NULL,       -- path|query|body|header|cookie
    param_name   TEXT    NOT NULL,
    analysis     TEXT    NOT NULL,       -- baseline|identifier|characters|length|types|validation
    payload      TEXT,                   -- exact payload string (NULL only for baseline)
    payload_type TEXT    NOT NULL DEFAULT 'unknown',
    payload_index INTEGER NOT NULL DEFAULT 0,
    flow_id      TEXT,                   -- UUID of the replay flow generated
    status       TEXT    NOT NULL DEFAULT 'pending',  -- pending|completed|failed|skipped
    created_at   TEXT    NOT NULL,
    completed_at TEXT,
    UNIQUE (param_uuid, analysis, payload_type, payload_index)
);

CREATE INDEX IF NOT EXISTS idx_iv_probe_results_param
    ON iv_probe_results (param_uuid, analysis);

CREATE INDEX IF NOT EXISTS idx_iv_probe_results_flow
    ON iv_probe_results (flow_id);

-- ------------------------------------------------------------------ --
-- iv_param_profiles: versioned parameter-level intelligence (Module 2)--
-- Separate from iv_param_cache (phase resume) so multi-level profiles --
-- are first-class documents with observed/inferred + capabilities.    --
-- Key: param_uuid = sha256(host|location|name)[:32]                   --
-- profile JSON: schema_version, observed, inferred, tested, attempts, --
--               capabilities, candidates, parser, normalization_*, …  --
-- ------------------------------------------------------------------ --
CREATE TABLE IF NOT EXISTS iv_param_profiles (
    id              TEXT    PRIMARY KEY,   -- UUID
    param_uuid      TEXT    NOT NULL,      -- deterministic parameter key
    host            TEXT    NOT NULL,
    location        TEXT    NOT NULL,      -- path|query|body|header|cookie
    param_name      TEXT    NOT NULL,
    schema_version  INTEGER NOT NULL DEFAULT 1,
    profile_version INTEGER NOT NULL DEFAULT 1,
    profile         TEXT    NOT NULL DEFAULT '{}',  -- full JSON document
    created_at      TEXT    NOT NULL,
    updated_at      TEXT    NOT NULL,
    UNIQUE (param_uuid)
);

CREATE INDEX IF NOT EXISTS idx_iv_param_profiles_host
    ON iv_param_profiles (host, location, param_name);

-- ------------------------------------------------------------------ --
-- iv_endpoint_profiles: endpoint-level intelligence stubs (Module 2)  --
-- Shared middleware/validation defaults; Module 10 fills inheritance. --
-- ------------------------------------------------------------------ --
CREATE TABLE IF NOT EXISTS iv_endpoint_profiles (
    id              TEXT    PRIMARY KEY,   -- UUID
    endpoint_id     TEXT    NOT NULL,      -- FK-like to endpoints.id
    host            TEXT    NOT NULL DEFAULT '',
    schema_version  INTEGER NOT NULL DEFAULT 1,
    profile_version INTEGER NOT NULL DEFAULT 1,
    profile         TEXT    NOT NULL DEFAULT '{}',
    created_at      TEXT    NOT NULL,
    updated_at      TEXT    NOT NULL,
    UNIQUE (endpoint_id)
);

CREATE INDEX IF NOT EXISTS idx_iv_endpoint_profiles_host
    ON iv_endpoint_profiles (host);

-- ------------------------------------------------------------------ --
-- iv_app_profiles: application/host-level intelligence stubs (Module 2)--
-- Inherit defaults for new parameters on the same host.               --
-- ------------------------------------------------------------------ --
CREATE TABLE IF NOT EXISTS iv_app_profiles (
    id              TEXT    PRIMARY KEY,   -- UUID
    host            TEXT    NOT NULL,      -- canonical origin / host key
    schema_version  INTEGER NOT NULL DEFAULT 1,
    profile_version INTEGER NOT NULL DEFAULT 1,
    profile         TEXT    NOT NULL DEFAULT '{}',
    created_at      TEXT    NOT NULL,
    updated_at      TEXT    NOT NULL,
    UNIQUE (host)
);

-- ------------------------------------------------------------------ --
-- sessions: detected identities                                       --
-- ------------------------------------------------------------------ --
CREATE TABLE IF NOT EXISTS sessions (
    id              TEXT    PRIMARY KEY,     -- UUID
    project_id      TEXT    NOT NULL,
    auth_type       TEXT    NOT NULL DEFAULT 'unknown',  -- cookie | bearer | basic | none
    token_signature TEXT    NOT NULL DEFAULT '',         -- partial/hash for dedup
    role            TEXT    NOT NULL DEFAULT '',         -- user-defined label
    first_seen      TEXT    NOT NULL,
    last_seen       TEXT    NOT NULL,
    active          INTEGER NOT NULL DEFAULT 1           -- boolean
);

-- ------------------------------------------------------------------ --
-- roles: identity types for access-control modeling                  --
-- is_active: boolean; at most one row should be 1 at a time.        --
-- The "global" role is the default — always present.                --
-- ------------------------------------------------------------------ --
CREATE TABLE IF NOT EXISTS roles (
    id        TEXT    PRIMARY KEY,   -- UUID
    name      TEXT    NOT NULL UNIQUE,
    is_active INTEGER NOT NULL DEFAULT 0
);

-- ------------------------------------------------------------------ --
-- modules: logical application feature areas                         --
-- is_active: boolean; at most one row should be 1 at a time.        --
-- The "global" module is the default — always present.              --
-- ------------------------------------------------------------------ --
CREATE TABLE IF NOT EXISTS modules (
    id          TEXT    PRIMARY KEY,   -- UUID
    name        TEXT    NOT NULL UNIQUE,
    description TEXT    NOT NULL DEFAULT '',
    is_active   INTEGER NOT NULL DEFAULT 0
);

-- ------------------------------------------------------------------ --
-- access_map: two-layer access model for BAC detection              --
-- client_allowed : what the client exposes for this role/module.    --
-- server_expected: what the backend SHOULD enforce (your assertion).--
-- Values: 'ALLOW' | 'DENY' | 'UNKNOWN' | NULL (not yet set).       --
-- ------------------------------------------------------------------ --
CREATE TABLE IF NOT EXISTS access_map (
    role_id          TEXT NOT NULL REFERENCES roles(id),
    module_id        TEXT NOT NULL REFERENCES modules(id),
    client_allowed   TEXT,
    server_expected  TEXT,
    PRIMARY KEY (role_id, module_id)
);

-- ------------------------------------------------------------------ --
-- endpoint_roles: observed role → endpoint access pairs              --
-- Derived from flows once endpoint_id is resolved on a flow.        --
-- first_seen / last_seen track the time window of observed access.  --
-- ------------------------------------------------------------------ --
CREATE TABLE IF NOT EXISTS endpoint_roles (
    endpoint_id TEXT NOT NULL REFERENCES endpoints(id),
    role_id     TEXT NOT NULL REFERENCES roles(id),
    first_seen  TEXT NOT NULL,   -- UTC ISO-8601
    last_seen   TEXT NOT NULL,   -- UTC ISO-8601
    PRIMARY KEY (endpoint_id, role_id)
);

-- ------------------------------------------------------------------ --
-- indexes: fast query paths for role/module scoped analysis          --
-- Without these, every BAC query does a full flows scan.            --
-- ------------------------------------------------------------------ --
CREATE INDEX IF NOT EXISTS idx_flows_role_id        ON flows (role_id);
CREATE INDEX IF NOT EXISTS idx_flows_module_id      ON flows (module_id);
CREATE INDEX IF NOT EXISTS idx_flows_endpoint_id    ON flows (endpoint_id);
CREATE INDEX IF NOT EXISTS idx_flows_role_module    ON flows (role_id, module_id);
CREATE INDEX IF NOT EXISTS idx_endpoint_roles_role  ON endpoint_roles (role_id);

-- ------------------------------------------------------------------ --
-- replay_diffs: diff result for each replay flow                      --
-- Populated immediately after a replay is stored.                    --
-- verdict: SAME | DIFFERENT | ERROR                                   --
-- status_diff: NULL when unchanged; text like "200→403" when changed. --
-- length_diff: replay_body_length - original_body_length (bytes).    --
-- ------------------------------------------------------------------ --
CREATE TABLE IF NOT EXISTS replay_diffs (
    replay_flow_id   TEXT     PRIMARY KEY REFERENCES flows(id),
    original_flow_id TEXT     NOT NULL,
    verdict          TEXT     NOT NULL,
    status_changed   INTEGER  NOT NULL DEFAULT 0,  -- boolean
    status_diff      TEXT,                          -- NULL when unchanged
    length_diff      INTEGER  NOT NULL DEFAULT 0
);

-- ------------------------------------------------------------------ --
-- auth_config: per-project auth field names (cookie/header)          --
-- Populated manually via 'talos auth set'.                           --
-- type: 'cookie' | 'header'                                          --
-- name: e.g. 'sessionid', 'Authorization'                           --
-- ------------------------------------------------------------------ --
CREATE TABLE IF NOT EXISTS auth_config (
    type   TEXT NOT NULL,
    name   TEXT NOT NULL,
    PRIMARY KEY (type, name)
);

-- ------------------------------------------------------------------ --
-- auth_test_results: verdict for each auth-bypass test replay        --
-- verdict: SECURE | BYPASS | UNKNOWN                                 --
-- ------------------------------------------------------------------ --
CREATE TABLE IF NOT EXISTS auth_test_results (
    replay_flow_id   TEXT PRIMARY KEY REFERENCES flows(id),
    original_flow_id TEXT NOT NULL,
    verdict          TEXT NOT NULL
);

-- ------------------------------------------------------------------ --
-- endpoint_annotations: safety tags applied manually by the user     --
-- Prevents unsafe replay of destructive or session-breaking endpoints --
-- tag: 'logout' (never replay) | 'dangerous' (skip in auto modes)   --
-- ------------------------------------------------------------------ --
CREATE TABLE IF NOT EXISTS endpoint_annotations (
    endpoint_id TEXT NOT NULL REFERENCES endpoints(id),
    tag         TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    PRIMARY KEY (endpoint_id, tag)
);
-- ------------------------------------------------------------------ --
-- scheduler_jobs: persistent replay job queue                         --
-- Owned by the ReplayScheduler layer.  One row per scheduled job.    --
-- job_type : replay_flow | replay_endpoint | auth_test | bac_* |     --
--            unauth_attack | iv_*                                    --
-- status   : pending | running | paused | done | failed | skipped |  --
--            cancelled                                               --
-- priority : higher value = executed first (manual=100, auto=10)     --
-- ------------------------------------------------------------------ --
CREATE TABLE IF NOT EXISTS scheduler_jobs (
    job_id             TEXT    PRIMARY KEY,
    endpoint_id        TEXT,
    flow_id            TEXT,
    job_type           TEXT    NOT NULL,
    priority           INTEGER NOT NULL DEFAULT 10,
    status             TEXT    NOT NULL DEFAULT 'pending',
    created_at         TEXT    NOT NULL,
    scheduled_at       TEXT,
    started_at         TEXT,
    finished_at        TEXT,
    failure_reason     TEXT,
    replayed_flow_id   TEXT,
    verdict            TEXT,
    meta               TEXT                            -- JSON; attack-type metadata
);

CREATE INDEX IF NOT EXISTS idx_scheduler_jobs_status_priority
    ON scheduler_jobs (status, priority DESC, created_at ASC);
-- ------------------------------------------------------------------ --
-- scheduler_config: per-project scheduler rate-limit settings         --
-- Single-row table — deleted and re-inserted on update.              --
-- ------------------------------------------------------------------ --
CREATE TABLE IF NOT EXISTS scheduler_config (
    min_delay      REAL    NOT NULL DEFAULT 2.0,
    max_delay      REAL    NOT NULL DEFAULT 6.0,
    max_queue_size INTEGER NOT NULL DEFAULT 200
);

-- ------------------------------------------------------------------ --
-- out_of_scope_domains: Basic Scope URL prefixes never captured       --
-- Column name remains `domain` (beta; no migration). Stored values    --
-- are full Basic Scope prefixes (host, host:port, scheme://…, path).  --
-- Matching uses talos.proxy.scope (same as in-scope); out-of-scope    --
-- overrides in-scope. Subdomains are NOT implied.                     --
-- ------------------------------------------------------------------ --
CREATE TABLE IF NOT EXISTS out_of_scope_domains (
    id         TEXT    PRIMARY KEY,   -- UUID
    project_id TEXT    NOT NULL,
    domain     TEXT    NOT NULL,      -- Basic Scope prefix string
    created_at TEXT    NOT NULL,      -- UTC ISO-8601
    UNIQUE (project_id, domain)
);

CREATE INDEX IF NOT EXISTS idx_out_of_scope_project
    ON out_of_scope_domains (project_id);

-- ------------------------------------------------------------------ --
-- attack_config: per-project attack module settings                   --
-- key: config key (e.g. 'unauth_auto_run')                           --
-- value: string value (e.g. '0' or '1')                              --
-- ------------------------------------------------------------------ --
CREATE TABLE IF NOT EXISTS attack_config (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL DEFAULT ''
);

-- ------------------------------------------------------------------ --
-- attack_host_exclusions: per-attack hosts/paths excluded from testing --
-- attack: attack module name (e.g. 'unauth')                          --
-- host:   hostname string (e.g. 'api.internal.example.com')           --
-- path:   path prefix to exclude, or '' for host-level exclusion      --
--         (e.g. '/api/v1' excludes all paths under /api/v1)           --
-- -------------------------------------------------------------------- --
CREATE TABLE IF NOT EXISTS attack_host_exclusions (
    attack     TEXT NOT NULL,
    host       TEXT NOT NULL,
    path       TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    PRIMARY KEY (attack, host, path)
);

-- ------------------------------------------------------------------ --
-- role_auth: per-role login and checkpoint flow assignments           --
-- login_flow_id      : flow to replay to obtain a new session token  --
-- checkpoint_flow_id : flow to replay to validate an existing token  --
-- ------------------------------------------------------------------ --
CREATE TABLE IF NOT EXISTS role_auth (
    role_id            TEXT PRIMARY KEY REFERENCES roles(id),
    login_flow_id      TEXT,   -- FK to flows.id (nullable until assigned)
    checkpoint_flow_id TEXT    -- FK to flows.id (nullable until assigned)
);

-- ------------------------------------------------------------------ --
-- role_session_tokens: generated session tokens per role             --
-- token  : the raw extracted JWT or session string                   --
-- active : boolean; at most one row per role should be 1 at a time  --
-- ------------------------------------------------------------------ --
CREATE TABLE IF NOT EXISTS role_session_tokens (
    id         TEXT    PRIMARY KEY,   -- UUID
    role_id    TEXT    NOT NULL REFERENCES roles(id),
    token      TEXT    NOT NULL,
    created_at TEXT    NOT NULL,      -- UTC ISO-8601
    active     INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_role_session_tokens_role
    ON role_session_tokens (role_id);

-- ------------------------------------------------------------------ --
-- bac_results: verdict for each BAC attack replay                     --
-- attack_type: bac_session_swap | bac_method_fuzz | etc.              --
-- variant    : specific mutation applied (e.g. 'GET_to_POST')        --
-- mutation_family: high-level family (e.g. 'method-fuzz')            --
-- mutation       : specific mutation label (e.g. 'GET→POST')         --
-- verdict    : POSSIBLE_BAC | SECURE | UNKNOWN                        --
-- matched_section: 'passed_detection' | 'failed_detection' | NULL    --
-- matched_group  : group_id or auto-label that matched; NULL if none  --
-- matched_rules  : JSON array of matched rule descriptions; NULL if   --
--                  no filter was used (heuristic path)                --
-- ------------------------------------------------------------------ --
CREATE TABLE IF NOT EXISTS bac_results (
    replay_flow_id   TEXT PRIMARY KEY REFERENCES flows(id),
    original_flow_id TEXT NOT NULL,
    attack_type      TEXT NOT NULL,
    variant          TEXT NOT NULL,
    mutation_family  TEXT,
    mutation         TEXT,
    attacker_role_id TEXT NOT NULL,
    target_role_id   TEXT NOT NULL,
    module_id        TEXT NOT NULL,
    verdict          TEXT NOT NULL,
    matched_section  TEXT,
    matched_group    TEXT,
    matched_rules    TEXT
);

CREATE INDEX IF NOT EXISTS idx_bac_results_verdict
    ON bac_results (verdict, attack_type);

-- ------------------------------------------------------------------ --
-- unauth_results: verdict for each unauth attack replay               --
-- auth_mutation_family : high-level auth mutation family              --
-- auth_mutation        : specific auth mutation (e.g. 'remove_authorization_header')
-- request_mutation_family : request mutation family; NULL for baseline --
-- request_mutation        : specific request mutation; NULL for baseline
-- verdict    : BYPASS | SECURE | UNKNOWN                              --
-- matched_section, matched_group, matched_rules: decision filter evidence
-- ------------------------------------------------------------------ --
CREATE TABLE IF NOT EXISTS unauth_results (
    replay_flow_id          TEXT PRIMARY KEY REFERENCES flows(id),
    original_flow_id        TEXT NOT NULL,
    endpoint_id             TEXT,
    auth_mutation_family    TEXT NOT NULL,
    auth_mutation           TEXT NOT NULL,
    request_mutation_family TEXT,
    request_mutation        TEXT,
    verdict                 TEXT NOT NULL,
    matched_section         TEXT,
    matched_group           TEXT,
    matched_rules           TEXT
);

CREATE INDEX IF NOT EXISTS idx_unauth_results_verdict
    ON unauth_results (verdict, auth_mutation_family);

-- ------------------------------------------------------------------ --
-- proxy_config: proxy startup mode (direct vs upstream-proxy)         --
-- Single-row table — id is always 'default'.                         --
-- upstream_url : e.g. 'http://127.0.0.1:8081' (Burp/ZAP/corp proxy);  --
--                NULL/empty means direct mode (connect straight to    --
--                the target server — mitmdump's default behaviour).  --
-- ------------------------------------------------------------------ --
CREATE TABLE IF NOT EXISTS proxy_config (
    id           TEXT PRIMARY KEY DEFAULT 'default',
    upstream_url TEXT
);

-- ------------------------------------------------------------------ --
-- auth_flow_config: per-role ordered list of auth flows with extractors
-- Replaces the single login_flow_id in role_auth; supports multiple flows
-- and per-flow Python extractors that return key-value auth artifacts.
-- extractor_code: Python source of extract(response) function; NULL means
--                 no extractor set (refresh blocked until assigned).
-- sort_order: execution order within the role (lower = runs first).
-- ------------------------------------------------------------------ --
CREATE TABLE IF NOT EXISTS auth_flow_config (
    id             TEXT    PRIMARY KEY,   -- UUID
    role_id        TEXT    NOT NULL REFERENCES roles(id),
    flow_id        TEXT    NOT NULL,      -- FK to flows.id
    extractor_code TEXT,                  -- nullable Python source
    sort_order     INTEGER NOT NULL DEFAULT 0,
    created_at     TEXT    NOT NULL,
    UNIQUE (role_id, flow_id)
);

CREATE INDEX IF NOT EXISTS idx_auth_flow_config_role
    ON auth_flow_config (role_id, sort_order);

-- ------------------------------------------------------------------ --
-- role_auth_state: current auth key-value pairs per role              --
-- Populated by auth-config refresh; consumed by the BAC engine.       --
-- key: artifact name (e.g. "sessionid", "Authorization")             --
-- value: artifact value (e.g. "abc123", "Bearer eyJ...")             --
-- collected_at: UTC ISO-8601 timestamp of last successful refresh.   --
-- ------------------------------------------------------------------ --
CREATE TABLE IF NOT EXISTS role_auth_state (
    role_id      TEXT NOT NULL REFERENCES roles(id),
    key          TEXT NOT NULL,
    value        TEXT NOT NULL,
    collected_at TEXT NOT NULL,
    PRIMARY KEY (role_id, key)
);

-- ------------------------------------------------------------------ --
-- session_health_config: per-role TTL and expiry signal configuration --
-- ttl_seconds: expected token lifetime (default 1200 = 20 min).      --
-- refresh_before_seconds: pre-refresh window in seconds (default 120).--
-- expiry_body_signals: JSON list of body substrings that signal expiry.
-- expiry_header_signals: JSON dict {header: [values]} for header signals.
-- expiry_status_codes: JSON list of ints; these statuses = suspicious.--
-- validation_endpoint_url: optional Layer 3 validation URL.          --
-- validation_expected_status: expected HTTP status from that URL.    --
-- validation_body_contains: JSON list; all must appear in response.  --
-- validation_body_not_contains: JSON list; none may appear in response.
-- ------------------------------------------------------------------ --
CREATE TABLE IF NOT EXISTS session_health_config (
    role_id                      TEXT PRIMARY KEY REFERENCES roles(id),
    ttl_seconds                  INTEGER NOT NULL DEFAULT 1200,
    refresh_before_seconds       INTEGER NOT NULL DEFAULT 120,
    expiry_body_signals          TEXT    NOT NULL DEFAULT '[]',
    expiry_header_signals        TEXT    NOT NULL DEFAULT '{}',
    expiry_status_codes          TEXT    NOT NULL DEFAULT '[]',
    validation_endpoint_url      TEXT,
    validation_expected_status   INTEGER NOT NULL DEFAULT 200,
    validation_body_contains     TEXT    NOT NULL DEFAULT '[]',
    validation_body_not_contains TEXT    NOT NULL DEFAULT '[]'
);

-- ------------------------------------------------------------------ --
-- session_health_control_flows: Layer 4 control flows per role        --
-- Replayed in groups to judge session liveness when suspicion exists. --
-- Pass threshold: at least one control flow returns expected status.  --
-- ------------------------------------------------------------------ --
CREATE TABLE IF NOT EXISTS session_health_control_flows (
    role_id  TEXT NOT NULL REFERENCES roles(id),
    flow_id  TEXT NOT NULL,
    PRIMARY KEY (role_id, flow_id)
);

-- ------------------------------------------------------------------ --
-- session_suspicion_state: per-role runtime suspicion counter         --
-- suspicion_count: incremented on each observed expiry signal.        --
-- last_checked_at: UTC ISO-8601 timestamp of last validation run.    --
-- ------------------------------------------------------------------ --
CREATE TABLE IF NOT EXISTS session_suspicion_state (
    role_id           TEXT PRIMARY KEY REFERENCES roles(id),
    suspicion_count   INTEGER NOT NULL DEFAULT 0,
    last_checked_at   TEXT
);

-- ------------------------------------------------------------------ --
-- endpoint_policy: per-endpoint policy record                          --
-- auto_priority        : computed by policy_score heuristics           --
-- auto_score           : raw integer score from scoring engine         --
-- auto_breakdown       : JSON dict {contributor_label: delta}          --
-- manual_priority      : tester override; NULL means auto is used      --
-- excluded             : 1 = skip in all attack modules                --
-- qualified            : 1 = endpoint has a 2xx proxy_capture flow     --
--                        and is eligible for automated testing          --
-- qualification_reason : why the endpoint is qualified/unqualified     --
--   values: no_flows | no_2xx_response | only_redirects |              --
--           is_logout | is_dangerous | flow_2xx                        --
-- baseline_flow_id     : FK to flows.id; the pre-computed best 2xx     --
--                        proxy_capture flow for this endpoint           --
-- baseline_status      : HTTP status of the baseline flow              --
-- notes                : free-form tester notes for reports            --
-- tags                 : JSON array of arbitrary string labels         --
-- ------------------------------------------------------------------ --
CREATE TABLE IF NOT EXISTS endpoint_policy (
    endpoint_id          TEXT PRIMARY KEY REFERENCES endpoints(id),
    auto_priority        TEXT    NOT NULL DEFAULT 'NORMAL',
    auto_score           INTEGER NOT NULL DEFAULT 0,
    auto_breakdown       TEXT    NOT NULL DEFAULT '{}',
    manual_priority      TEXT,
    excluded             INTEGER NOT NULL DEFAULT 0,
    dangerous            INTEGER NOT NULL DEFAULT 0,
    logout               INTEGER NOT NULL DEFAULT 0,
    qualified            INTEGER NOT NULL DEFAULT 0,
    qualification_reason TEXT    NOT NULL DEFAULT 'no_flows',
    baseline_flow_id     TEXT,
    baseline_status      INTEGER,
    notes                TEXT    NOT NULL DEFAULT '',
    tags                 TEXT    NOT NULL DEFAULT '[]',
    updated_at           TEXT    NOT NULL
);

-- ------------------------------------------------------------------ --
-- policy_rules: project-scoped path-pattern policy rules              --
-- pattern  : path glob (e.g. /static/* or /api/admin/*)              --
-- priority : NULL | CRITICAL | HIGH | NORMAL | LOW                   --
-- excluded : 1 = all matching endpoints excluded from candidate gen  --
-- A NULL priority means the rule only controls exclusion.             --
-- ------------------------------------------------------------------ --
CREATE TABLE IF NOT EXISTS policy_rules (
    id          TEXT    PRIMARY KEY,
    project_id  TEXT    NOT NULL,
    pattern     TEXT    NOT NULL,
    priority    TEXT,
    excluded    INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT    NOT NULL,
    UNIQUE (project_id, pattern)
);

CREATE INDEX IF NOT EXISTS idx_policy_rules_project
    ON policy_rules (project_id);

-- ------------------------------------------------------------------ --
-- role_auth_provider: per-role authentication provider selection      --
-- provider: 'auto' (replay login flows) | 'manual' (tester provides) --
-- ------------------------------------------------------------------ --
CREATE TABLE IF NOT EXISTS role_auth_provider (
    role_id    TEXT PRIMARY KEY REFERENCES roles(id),
    provider   TEXT NOT NULL DEFAULT 'auto',  -- 'auto' | 'manual'
    updated_at TEXT NOT NULL
);

-- ------------------------------------------------------------------ --
-- manual_session_config: per-role manually-supplied auth artifacts    --
-- headers_json: JSON dict { header_name: value }                      --
-- cookies_json: JSON dict { cookie_name: value }                      --
-- expires_at:   explicit UTC ISO-8601 expiry (nullable)               --
-- ttl_seconds:  token lifetime; computed from created_at (nullable)   --
-- At least one of expires_at / ttl_seconds must be set before the     --
-- session can be used.                                                 --
-- ------------------------------------------------------------------ --
CREATE TABLE IF NOT EXISTS manual_session_config (
    role_id      TEXT PRIMARY KEY REFERENCES roles(id),
    headers_json TEXT NOT NULL DEFAULT '{}',
    cookies_json TEXT NOT NULL DEFAULT '{}',
    expires_at   TEXT,
    ttl_seconds  INTEGER,
    created_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL
);

-- ------------------------------------------------------------------ --
-- scheduler_state: global scheduler execution state                   --
-- state: 'running' | 'paused' | 'waiting_for_session'                --
-- reason: optional human-readable explanation                         --
-- ------------------------------------------------------------------ --
CREATE TABLE IF NOT EXISTS scheduler_state (
    id         TEXT PRIMARY KEY DEFAULT 'default',
    state      TEXT NOT NULL DEFAULT 'running',
    reason     TEXT,
    updated_at TEXT NOT NULL
);

-- ================================================================== --
-- Findings subsystem (v31)                                            --
-- ================================================================== --

-- ------------------------------------------------------------------ --
-- findings: one row per discovered vulnerability instance             --
-- attack_type   : 'bac' | 'auth_test' | 'unauth' (VERDICT_TRIGGERS)  --
-- verdict       : the verdict string that triggered creation           --
-- status        : TRIAGING | CONFIRMED | REJECTED | DUPLICATE         --
-- duplicate_of  : FK to findings.id when status = DUPLICATE          --
-- relation_type : PRIMARY | LINKED (finding relationship, not status)--
-- parent_finding_id : FK to PRIMARY finding when relation_type=LINKED --
-- cluster_key   : deterministic cluster identity (e.g. UNAUTH:<ep>)   --
-- title         : short human-readable summary generated at creation --
-- notes         : free-form analyst notes                             --
-- ------------------------------------------------------------------ --
CREATE TABLE IF NOT EXISTS findings (
    id                 TEXT    PRIMARY KEY,   -- UUID
    project_id         TEXT    NOT NULL,
    attack_type        TEXT    NOT NULL,
    verdict            TEXT    NOT NULL,
    endpoint_id        TEXT,                  -- FK to endpoints.id (nullable)
    status             TEXT    NOT NULL DEFAULT 'TRIAGING',
    duplicate_of       TEXT,                  -- FK to findings.id (nullable)
    relation_type      TEXT    NOT NULL DEFAULT 'PRIMARY',
    parent_finding_id  TEXT,                  -- FK to findings.id (PRIMARY only)
    cluster_key        TEXT,                  -- internal grouping identity
    created_at         TEXT    NOT NULL,      -- UTC ISO-8601
    updated_at         TEXT    NOT NULL,      -- UTC ISO-8601
    title              TEXT    NOT NULL DEFAULT '',
    notes              TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_findings_project
    ON findings (project_id, status, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_findings_parent
    ON findings (parent_finding_id);

CREATE INDEX IF NOT EXISTS idx_findings_relation
    ON findings (project_id, relation_type);

-- At most one PRIMARY finding per cluster_key (NULLs are unrestricted).
CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_primary_cluster
    ON findings (cluster_key)
    WHERE relation_type = 'PRIMARY' AND cluster_key IS NOT NULL;

-- ------------------------------------------------------------------ --
-- finding_evidence: evidence items attached to a finding              --
-- evidence_type : canonical label (EVIDENCE_TYPE_* constants)         --
-- reference_id  : UUID of the referenced DB object (nullable)         --
-- label         : short human-readable description                    --
-- data          : JSON blob for structured metadata                   --
-- ------------------------------------------------------------------ --
CREATE TABLE IF NOT EXISTS finding_evidence (
    id            TEXT    PRIMARY KEY,   -- UUID
    finding_id    TEXT    NOT NULL REFERENCES findings(id),
    evidence_type TEXT    NOT NULL,
    reference_id  TEXT,
    label         TEXT    NOT NULL DEFAULT '',
    data          TEXT    NOT NULL DEFAULT '{}',  -- JSON
    created_at    TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_finding_evidence_finding
    ON finding_evidence (finding_id, created_at ASC);

-- ------------------------------------------------------------------ --
-- finding_timeline: immutable event log per finding                   --
-- actor  : 'system' | 'analyst'                                       --
-- event  : human-readable description of what happened                --
-- ------------------------------------------------------------------ --
CREATE TABLE IF NOT EXISTS finding_timeline (
    id         TEXT    PRIMARY KEY,   -- UUID
    finding_id TEXT    NOT NULL REFERENCES findings(id),
    event      TEXT    NOT NULL,
    actor      TEXT    NOT NULL DEFAULT 'system',
    created_at TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_finding_timeline_finding
    ON finding_timeline (finding_id, created_at ASC);

-- ------------------------------------------------------------------ --
-- finding_groups: user-created named collections of findings          --
-- name is unique within a project                                     --
-- ------------------------------------------------------------------ --
CREATE TABLE IF NOT EXISTS finding_groups (
    id         TEXT    PRIMARY KEY,   -- UUID
    project_id TEXT    NOT NULL,
    name       TEXT    NOT NULL,
    created_at TEXT    NOT NULL,
    UNIQUE (project_id, name)
);

CREATE INDEX IF NOT EXISTS idx_finding_groups_project
    ON finding_groups (project_id);

-- ------------------------------------------------------------------ --
-- finding_group_members: many-to-many findings ↔ groups              --
-- ------------------------------------------------------------------ --
CREATE TABLE IF NOT EXISTS finding_group_members (
    group_id   TEXT    NOT NULL REFERENCES finding_groups(id) ON DELETE CASCADE,
    finding_id TEXT    NOT NULL REFERENCES findings(id),
    added_at   TEXT    NOT NULL,
    PRIMARY KEY (group_id, finding_id)
);

CREATE INDEX IF NOT EXISTS idx_finding_group_members_finding
    ON finding_group_members (finding_id);

-- ------------------------------------------------------------------ --
-- Passive Source Intelligence (schema v39)                            --
-- source_documents: unique body identity (project_id + body_hash)     --
-- source_occurrences: each flow/URL sighting of a document            --
-- passive_detections: scored observations (not findings lifecycle)    --
-- passive_scan_config: single-row defaults (id='default')             --
-- Bodies stay on flows; these tables hold hashes + intelligence only. --
-- ------------------------------------------------------------------ --
CREATE TABLE IF NOT EXISTS source_documents (
    id                   TEXT    PRIMARY KEY,   -- UUID
    project_id           TEXT    NOT NULL,
    body_hash            TEXT    NOT NULL,     -- SHA-256 hex of raw body bytes
    source_kind          TEXT    NOT NULL,     -- html|javascript|json|…
    body_size            INTEGER NOT NULL,     -- raw byte length
    truncated            INTEGER NOT NULL DEFAULT 0,
    scanner_version      TEXT,                  -- last successful SCANNER_VERSION
    scan_status          TEXT    NOT NULL DEFAULT 'pending',
    first_flow_id        TEXT,
    first_seen           TEXT,                  -- UTC ISO-8601
    last_seen            TEXT,
    last_scanned_at      TEXT,
    error_message        TEXT,
    parent_document_id   TEXT,                  -- virtual docs (e.g. sourcesContent)
    logical_source_name  TEXT,                  -- build-hash normalized path (UI)
    UNIQUE (project_id, body_hash)
);

CREATE INDEX IF NOT EXISTS idx_source_documents_project
    ON source_documents (project_id, last_seen DESC);

CREATE INDEX IF NOT EXISTS idx_source_documents_status
    ON source_documents (project_id, scan_status);

CREATE INDEX IF NOT EXISTS idx_source_documents_parent
    ON source_documents (parent_document_id);

CREATE TABLE IF NOT EXISTS source_occurrences (
    id                   TEXT    PRIMARY KEY,   -- UUID
    document_id          TEXT    NOT NULL REFERENCES source_documents(id),
    flow_id              TEXT,
    endpoint_id          TEXT,
    url                  TEXT    NOT NULL DEFAULT '',
    host                 TEXT    NOT NULL DEFAULT '',
    path                 TEXT    NOT NULL DEFAULT '',
    logical_source_name  TEXT,
    content_type         TEXT    NOT NULL DEFAULT '',
    observed_at          TEXT    NOT NULL,
    role_id              TEXT    NOT NULL DEFAULT '',
    module_id            TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_source_occurrences_document
    ON source_occurrences (document_id, observed_at DESC);

CREATE INDEX IF NOT EXISTS idx_source_occurrences_flow
    ON source_occurrences (flow_id);

CREATE TABLE IF NOT EXISTS passive_detections (
    id                   TEXT    PRIMARY KEY,   -- UUID
    document_id          TEXT    NOT NULL REFERENCES source_documents(id),
    occurrence_id        TEXT,
    detector_id          TEXT    NOT NULL,
    detector_family      TEXT    NOT NULL,
    category             TEXT    NOT NULL,
    secret_type          TEXT    NOT NULL DEFAULT '',
    matched_key          TEXT,
    redacted_value       TEXT    NOT NULL DEFAULT '',
    value_fingerprint    TEXT    NOT NULL,     -- SHA-256(family + NUL + canonical)
    confidence_score     INTEGER NOT NULL DEFAULT 0,
    confidence_level     TEXT    NOT NULL,
    entropy              REAL,
    encoding_chain       TEXT    NOT NULL DEFAULT '[]',  -- JSON array
    decode_depth         INTEGER NOT NULL DEFAULT 0,
    match_start          INTEGER NOT NULL DEFAULT 0,
    match_end            INTEGER NOT NULL DEFAULT 0,
    context_before       TEXT    NOT NULL DEFAULT '',
    context_after        TEXT    NOT NULL DEFAULT '',
    suppressed           INTEGER NOT NULL DEFAULT 0,
    suppression_reason   TEXT,
    finding_id           TEXT,                  -- set by finding bridge (Phase 8)
    raw_value_stored     INTEGER NOT NULL DEFAULT 0,
    created_at           TEXT    NOT NULL
);

-- Avoid re-insert of the same match on rescan
CREATE UNIQUE INDEX IF NOT EXISTS idx_passive_detections_dedup
    ON passive_detections (document_id, detector_id, value_fingerprint, match_start);

CREATE INDEX IF NOT EXISTS idx_passive_detections_document
    ON passive_detections (document_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_passive_detections_fingerprint
    ON passive_detections (value_fingerprint);

CREATE INDEX IF NOT EXISTS idx_passive_detections_finding
    ON passive_detections (finding_id);

CREATE TABLE IF NOT EXISTS passive_scan_config (
    id                           TEXT    PRIMARY KEY DEFAULT 'default',
    enabled                      INTEGER NOT NULL DEFAULT 1,
    auto_finding_threshold       TEXT    NOT NULL DEFAULT 'HIGH',
    max_document_size            INTEGER NOT NULL DEFAULT 2000000,
    max_decode_depth             INTEGER NOT NULL DEFAULT 3,
    max_decode_bytes             INTEGER NOT NULL DEFAULT 256000,
    max_candidates_per_document  INTEGER NOT NULL DEFAULT 500,
    scan_html                    INTEGER NOT NULL DEFAULT 1,
    scan_javascript              INTEGER NOT NULL DEFAULT 1,
    scan_json                    INTEGER NOT NULL DEFAULT 1,
    scan_xml                     INTEGER NOT NULL DEFAULT 1,
    scan_text                    INTEGER NOT NULL DEFAULT 1,
    scan_css                     INTEGER NOT NULL DEFAULT 1,
    scan_sourcemaps              INTEGER NOT NULL DEFAULT 1,
    scan_wasm                    INTEGER NOT NULL DEFAULT 0,
    store_raw_secret_in_evidence INTEGER NOT NULL DEFAULT 1,
    store_suppressed_detections  INTEGER NOT NULL DEFAULT 0,
    queue_maxsize                INTEGER NOT NULL DEFAULT 500,
    max_scan_time_ms             INTEGER NOT NULL DEFAULT 0
);

-- ------------------------------------------------------------------ --
-- value_index: distinctive request values for cross-flow reflection   --
-- (schema v42). One row per (host, value_hash, source_param_uuid).    --
-- ------------------------------------------------------------------ --
CREATE TABLE IF NOT EXISTS value_index (
    id                   TEXT    PRIMARY KEY,
    project_id           TEXT    NOT NULL,
    host                 TEXT    NOT NULL,              -- endpoints.host canonical origin
    value_hash           TEXT    NOT NULL,              -- sha256(value_norm)[:32]
    value_match          TEXT    NOT NULL,              -- FULL value for matching (len <= 256)
    value_len            INTEGER NOT NULL,
    source_flow_id       TEXT    NOT NULL,              -- most recent observing flow
    first_source_flow_id TEXT    NOT NULL,              -- first flow that introduced this triple
    source_endpoint_id   TEXT,
    source_param_id      TEXT,
    source_param_uuid    TEXT    NOT NULL,
    source_param_name    TEXT    NOT NULL,
    source_location      TEXT    NOT NULL,
    source_method        TEXT    NOT NULL DEFAULT '',
    source_path          TEXT    NOT NULL DEFAULT '',   -- normalized_path
    source_role_id       TEXT,
    first_seen_at        TEXT    NOT NULL,
    last_seen_at         TEXT    NOT NULL,
    hit_count            INTEGER NOT NULL DEFAULT 1,
    is_canary            INTEGER NOT NULL DEFAULT 0,
    expires_at           TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_value_index_host_hash_param
    ON value_index (host, value_hash, source_param_uuid);

CREATE INDEX IF NOT EXISTS idx_value_index_host_hash
    ON value_index (host, value_hash);

CREATE INDEX IF NOT EXISTS idx_value_index_param
    ON value_index (source_param_uuid);

CREATE INDEX IF NOT EXISTS idx_value_index_expires
    ON value_index (expires_at);

CREATE INDEX IF NOT EXISTS idx_value_index_host_canary_seen
    ON value_index (host, is_canary DESC, last_seen_at DESC);

-- ------------------------------------------------------------------ --
-- cross_flow_reflections: source→sink value reflection links (v42)  --
-- Does not store full secret values — only hash + length.             --
-- ------------------------------------------------------------------ --
CREATE TABLE IF NOT EXISTS cross_flow_reflections (
    id                   TEXT    PRIMARY KEY,
    project_id           TEXT    NOT NULL,
    host                 TEXT    NOT NULL,

    source_flow_id       TEXT    NOT NULL,
    first_source_flow_id TEXT    NOT NULL,
    source_endpoint_id   TEXT,
    source_param_id      TEXT,
    source_param_uuid    TEXT    NOT NULL,
    source_param_name    TEXT    NOT NULL,
    source_location      TEXT    NOT NULL,
    source_method        TEXT    NOT NULL DEFAULT '',
    source_path          TEXT    NOT NULL DEFAULT '',
    source_role_id       TEXT,

    sink_flow_id         TEXT    NOT NULL,
    sink_endpoint_id     TEXT,
    sink_method          TEXT    NOT NULL DEFAULT '',
    sink_path            TEXT    NOT NULL DEFAULT '',
    sink_content_type    TEXT    NOT NULL DEFAULT '',
    sink_context         TEXT    NOT NULL DEFAULT 'other',
    sink_role_id         TEXT,
    encoding             TEXT    NOT NULL DEFAULT 'raw',
    transforms           TEXT    NOT NULL DEFAULT '[]',

    value_hash           TEXT    NOT NULL,
    value_len            INTEGER NOT NULL DEFAULT 0,
    match_kind           TEXT    NOT NULL DEFAULT 'exact',
    confidence           INTEGER NOT NULL DEFAULT 70,
    detection_mode       TEXT    NOT NULL DEFAULT 'passive',
    first_seen_at        TEXT    NOT NULL,
    last_seen_at         TEXT    NOT NULL,
    observation_count    INTEGER NOT NULL DEFAULT 1,

    UNIQUE (source_param_uuid, sink_flow_id, value_hash, encoding)
);

CREATE INDEX IF NOT EXISTS idx_cross_flow_reflections_param
    ON cross_flow_reflections (source_param_uuid);

CREATE INDEX IF NOT EXISTS idx_cross_flow_reflections_host_seen
    ON cross_flow_reflections (host, last_seen_at DESC);

CREATE INDEX IF NOT EXISTS idx_cross_flow_reflections_sink_ep
    ON cross_flow_reflections (sink_endpoint_id);

CREATE INDEX IF NOT EXISTS idx_cross_flow_reflections_source_ep
    ON cross_flow_reflections (source_endpoint_id);

-- ------------------------------------------------------------------ --
-- Error Intelligence (schema v43)                                     --
-- error_clusters: unique fingerprint per project                      --
-- error_observations: each flow / attack sighting                     --
-- error_intel_config: single-row defaults (id='default')              --
-- Intelligence only — no finding_id / auto Findings in v1.             --
-- ------------------------------------------------------------------ --
CREATE TABLE IF NOT EXISTS error_clusters (
    id                   TEXT    PRIMARY KEY,   -- UUID
    project_id           TEXT    NOT NULL,
    fingerprint          TEXT    NOT NULL,     -- SHA-256 of identity tuple
    category             TEXT    NOT NULL,     -- stack_trace|database|…
    severity             TEXT    NOT NULL,     -- low|medium|high|critical
    language             TEXT    NOT NULL DEFAULT 'unknown',
    framework            TEXT,
    database             TEXT,
    server               TEXT,
    exception_type       TEXT,
    message_norm         TEXT,
    technologies_json    TEXT    NOT NULL DEFAULT '[]',
    has_stack_trace      INTEGER NOT NULL DEFAULT 0,
    has_path_leak        INTEGER NOT NULL DEFAULT 0,
    has_internal_host    INTEGER NOT NULL DEFAULT 0,
    has_version_leak     INTEGER NOT NULL DEFAULT 0,
    confidence           INTEGER NOT NULL DEFAULT 0,
    evidence_snippet     TEXT,
    first_seen           TEXT,
    last_seen            TEXT,
    observation_count    INTEGER NOT NULL DEFAULT 0,
    scanner_version      TEXT,
    UNIQUE (project_id, fingerprint)
);

CREATE INDEX IF NOT EXISTS idx_error_clusters_project_seen
    ON error_clusters (project_id, last_seen DESC);

CREATE INDEX IF NOT EXISTS idx_error_clusters_category_sev
    ON error_clusters (project_id, category, severity);

CREATE INDEX IF NOT EXISTS idx_error_clusters_exception
    ON error_clusters (project_id, exception_type);

CREATE TABLE IF NOT EXISTS error_observations (
    id                   TEXT    PRIMARY KEY,   -- UUID
    error_id             TEXT    NOT NULL REFERENCES error_clusters(id),
    flow_id              TEXT,
    endpoint_id          TEXT,
    parameter_uuid       TEXT,
    parameter_name       TEXT,
    attack_type          TEXT    NOT NULL DEFAULT 'unknown',
    payload_redacted     TEXT,
    response_status      INTEGER,
    response_length      INTEGER,
    duration_ms          REAL,
    response_hash        TEXT,
    artifacts_json       TEXT    NOT NULL DEFAULT '[]',
    detectors_json       TEXT    NOT NULL DEFAULT '[]',
    observed_at          TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_error_observations_error
    ON error_observations (error_id, observed_at DESC);

CREATE INDEX IF NOT EXISTS idx_error_observations_flow
    ON error_observations (flow_id);

CREATE INDEX IF NOT EXISTS idx_error_observations_endpoint
    ON error_observations (endpoint_id);

CREATE INDEX IF NOT EXISTS idx_error_observations_param
    ON error_observations (parameter_uuid);

CREATE INDEX IF NOT EXISTS idx_error_observations_attack
    ON error_observations (attack_type);

-- One observation per flow when flow_id is set (NULL/empty allowed multi).
CREATE UNIQUE INDEX IF NOT EXISTS idx_error_observations_flow_unique
    ON error_observations (flow_id)
    WHERE flow_id IS NOT NULL AND flow_id != '';

CREATE TABLE IF NOT EXISTS error_intel_config (
    id                           TEXT    PRIMARY KEY DEFAULT 'default',
    enabled                      INTEGER NOT NULL DEFAULT 1,
    store_generic_http_errors    INTEGER NOT NULL DEFAULT 0,
    max_body_scan                INTEGER NOT NULL DEFAULT 512000,
    gate_sniff_bytes             INTEGER NOT NULL DEFAULT 16384,
    queue_maxsize                INTEGER NOT NULL DEFAULT 500,
    evidence_snippet_max         INTEGER NOT NULL DEFAULT 4096,
    error_header_names_json      TEXT    NOT NULL DEFAULT '[]'
);

-- ------------------------------------------------------------------ --
-- repeater_tabs: persistent Repeater workspace archive (Mode 2)       --
-- Metadata only — draft request bodies stay client/CLI-local until    --
-- Send. Re-open re-materializes from parent_flow_id.                  --
-- ------------------------------------------------------------------ --
CREATE TABLE IF NOT EXISTS repeater_tabs (
    id                  TEXT    PRIMARY KEY,              -- UUID
    project_id          TEXT    NOT NULL,
    title               TEXT    NOT NULL DEFAULT '',
    parent_flow_id      TEXT    NOT NULL,                 -- materialize / once parent
    original_flow_id    TEXT    NOT NULL,                 -- lineage root
    session_id          TEXT,                             -- optional branch marker
    last_execution_id   TEXT,                             -- last send from this tab
    sort_order          INTEGER NOT NULL DEFAULT 0,
    created_at          TEXT    NOT NULL,                 -- UTC ISO-8601
    updated_at          TEXT    NOT NULL                  -- UTC ISO-8601
);
CREATE INDEX IF NOT EXISTS idx_repeater_tabs_project_sort
    ON repeater_tabs (project_id, sort_order ASC, updated_at DESC);

-- ------------------------------------------------------------------ --
-- Intruder (Phase 1): high-volume mutation attack engine sessions     --
-- ------------------------------------------------------------------ --
CREATE TABLE IF NOT EXISTS intruder_sessions (
    id               TEXT    PRIMARY KEY,              -- UUID
    project_id       TEXT    NOT NULL,
    name             TEXT    NOT NULL DEFAULT '',
    status           TEXT    NOT NULL DEFAULT 'draft', -- draft|configured|queued|running|paused|completed|failed|cancelled
    base_flow_id     TEXT,                             -- baseline capture/send flow
    endpoint_id      TEXT,
    config_json      TEXT    NOT NULL DEFAULT '{}',    -- full session config document
    checkpoint_json  TEXT    NOT NULL DEFAULT '{}',    -- strategy/generator cursors + attempt_index
    progress_json    TEXT    NOT NULL DEFAULT '{}',    -- sent, matched, active_duration_s, ...
    job_id           TEXT,                             -- current segment scheduler job
    control_flag     TEXT,                             -- null | pause | cancel
    created_at       TEXT    NOT NULL,
    updated_at       TEXT    NOT NULL,
    started_at       TEXT,
    finished_at      TEXT,
    failure_reason   TEXT,
    schema_version   INTEGER NOT NULL DEFAULT 1        -- config schema version
);
CREATE INDEX IF NOT EXISTS idx_intruder_sessions_project
    ON intruder_sessions (project_id, status, updated_at DESC);

CREATE TABLE IF NOT EXISTS intruder_results (
    id               TEXT    PRIMARY KEY,              -- UUID
    session_id       TEXT    NOT NULL REFERENCES intruder_sessions(id) ON DELETE CASCADE,
    attempt_index    INTEGER NOT NULL,
    variables_json   TEXT    NOT NULL DEFAULT '{}',
    status_code      INTEGER,
    success          INTEGER NOT NULL DEFAULT 0,
    failure_reason   TEXT,
    duration_ms      REAL,
    body_length      INTEGER,
    word_count       INTEGER,
    line_count       INTEGER,
    body_hash        TEXT,
    fingerprint_json TEXT    NOT NULL DEFAULT '{}',
    metrics_json     TEXT    NOT NULL DEFAULT '{}',
    interesting      INTEGER NOT NULL DEFAULT 0,
    match_tags_json  TEXT    NOT NULL DEFAULT '[]',
    grepped_json     TEXT    NOT NULL DEFAULT '{}',
    flow_id          TEXT,
    finding_id       TEXT,                             -- Phase 5 optional findings promote
    created_at       TEXT    NOT NULL,
    UNIQUE (session_id, attempt_index)
);
CREATE INDEX IF NOT EXISTS idx_intruder_results_session
    ON intruder_results (session_id, attempt_index);
CREATE INDEX IF NOT EXISTS idx_intruder_results_interesting
    ON intruder_results (session_id, interesting) WHERE interesting = 1;
CREATE INDEX IF NOT EXISTS idx_intruder_results_finding
    ON intruder_results (finding_id) WHERE finding_id IS NOT NULL;

-- ------------------------------------------------------------------ --
-- Intruder (Phase 3): extracted value pools for chaining              --
-- ------------------------------------------------------------------ --
CREATE TABLE IF NOT EXISTS intruder_pools (
    id               TEXT    PRIMARY KEY,              -- UUID
    project_id       TEXT    NOT NULL,
    name             TEXT    NOT NULL,                 -- pool name (often matches grep rule)
    session_id       TEXT,                             -- last contributing session
    values_json      TEXT    NOT NULL DEFAULT '[]',    -- unique string values
    source_rule      TEXT,                             -- originating grep rule name
    created_at       TEXT    NOT NULL,
    updated_at       TEXT    NOT NULL,
    UNIQUE (project_id, name)
);
CREATE INDEX IF NOT EXISTS idx_intruder_pools_project
    ON intruder_pools (project_id, updated_at DESC);

-- ------------------------------------------------------------------ --
-- AI Layer (v49): sessions, audit, project prefs (Phase A foundation) --
-- ------------------------------------------------------------------ --
CREATE TABLE IF NOT EXISTS ai_sessions (
    id                  TEXT PRIMARY KEY,
    project_id          TEXT NOT NULL,
    goal                TEXT NOT NULL,
    mode                TEXT NOT NULL,
    status              TEXT NOT NULL,  -- active|stopped|halted_budget|completed
    pinned_project_id   TEXT NOT NULL,
    data_dir            TEXT NOT NULL,
    scope_snapshot_json TEXT,           -- audit only; live scope still checked per HTTP tool
    budgets_json        TEXT NOT NULL,
    usage_json          TEXT NOT NULL,
    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ai_sessions_project_status
    ON ai_sessions (project_id, status, updated_at DESC);

CREATE TABLE IF NOT EXISTS ai_project_prefs (
    project_id              TEXT PRIMARY KEY,
    auto_aggressive_ack_at  TEXT,
    auto_aggressive_ack_by  TEXT,
    updated_at              TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ai_audit_events (
    id           TEXT PRIMARY KEY,
    session_id   TEXT,                 -- nullable for project-level events
    project_id   TEXT NOT NULL,
    event_type   TEXT NOT NULL,
    payload_json TEXT NOT NULL,        -- pre-redacted for sensitive fields
    created_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ai_audit_project_created
    ON ai_audit_events (project_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ai_audit_session_created
    ON ai_audit_events (session_id, created_at DESC);

-- ------------------------------------------------------------------ --
-- AI Layer (v50): structured app notes + revision history (Phase B)  --
-- ------------------------------------------------------------------ --
CREATE TABLE IF NOT EXISTS ai_app_notes (
    project_id     TEXT PRIMARY KEY,
    revision       INTEGER NOT NULL DEFAULT 1,
    doc_json       TEXT    NOT NULL,
    updated_at     TEXT    NOT NULL,
    updated_by     TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS ai_app_note_revisions (
    id             TEXT PRIMARY KEY,
    project_id     TEXT NOT NULL,
    revision       INTEGER NOT NULL,
    doc_json       TEXT NOT NULL,
    updated_at     TEXT NOT NULL,
    updated_by     TEXT NOT NULL,
    UNIQUE(project_id, revision)
);
CREATE INDEX IF NOT EXISTS idx_ai_app_note_revisions_project
    ON ai_app_note_revisions (project_id, revision DESC);

-- ------------------------------------------------------------------ --
-- AI Layer (v51): immutable suggestions, plans, observations, PTT     --
-- ------------------------------------------------------------------ --
CREATE TABLE IF NOT EXISTS ai_suggestions (
    id               TEXT PRIMARY KEY,
    session_id       TEXT NOT NULL,
    tool_name        TEXT NOT NULL,
    arguments_json   TEXT NOT NULL,
    rationale        TEXT,
    cli_preview      TEXT,
    display_risk     TEXT,
    created_at       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ai_suggestions_session
    ON ai_suggestions (session_id, created_at DESC);

CREATE TABLE IF NOT EXISTS ai_execution_plans (
    id                    TEXT PRIMARY KEY,
    suggestion_id         TEXT NOT NULL,
    session_id            TEXT NOT NULL,
    tool_name             TEXT NOT NULL,
    arguments_json        TEXT NOT NULL,
    capabilities_json     TEXT NOT NULL,
    status                TEXT NOT NULL,
    policy_meta_json      TEXT NOT NULL DEFAULT '{}',
    capability_token_hash TEXT,
    failure_reason        TEXT,
    created_at            TEXT NOT NULL,
    decided_at            TEXT,
    FOREIGN KEY (suggestion_id) REFERENCES ai_suggestions(id)
);
CREATE INDEX IF NOT EXISTS idx_ai_execution_plans_session
    ON ai_execution_plans (session_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ai_execution_plans_suggestion
    ON ai_execution_plans (suggestion_id, created_at DESC);

CREATE TABLE IF NOT EXISTS ai_observations (
    id              TEXT PRIMARY KEY,
    session_id      TEXT NOT NULL,
    suggestion_id   TEXT NOT NULL,
    plan_id         TEXT NOT NULL,
    tool_name       TEXT NOT NULL,
    result_summary  TEXT NOT NULL,
    citations_json  TEXT NOT NULL,
    raw_ref         TEXT,
    untrusted       INTEGER NOT NULL DEFAULT 1,
    created_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ai_observations_session
    ON ai_observations (session_id, created_at DESC);

CREATE TABLE IF NOT EXISTS ai_task_nodes (
    node_id              TEXT PRIMARY KEY,
    session_id           TEXT NOT NULL,
    project_id           TEXT NOT NULL,
    parent_id            TEXT,
    title                TEXT NOT NULL,
    status               TEXT NOT NULL,
    hypothesis           TEXT,
    evidence_refs_json   TEXT NOT NULL DEFAULT '{}',
    suggested_tools_json TEXT NOT NULL DEFAULT '[]',
    priority             INTEGER NOT NULL DEFAULT 0,
    created_at           TEXT NOT NULL,
    updated_at           TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ai_task_nodes_session
    ON ai_task_nodes (session_id, priority DESC, updated_at DESC);
"""

# Shared CREATE statements for AI Layer tables (schema v49).
# Used by _migrate_schema and migrate_project_db so upgrade paths stay in sync.
_AI_SCHEMA_V49_DDL = """
CREATE TABLE IF NOT EXISTS ai_sessions (
    id                  TEXT PRIMARY KEY,
    project_id          TEXT NOT NULL,
    goal                TEXT NOT NULL,
    mode                TEXT NOT NULL,
    status              TEXT NOT NULL,
    pinned_project_id   TEXT NOT NULL,
    data_dir            TEXT NOT NULL,
    scope_snapshot_json TEXT,
    budgets_json        TEXT NOT NULL,
    usage_json          TEXT NOT NULL,
    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ai_sessions_project_status
    ON ai_sessions (project_id, status, updated_at DESC);

CREATE TABLE IF NOT EXISTS ai_project_prefs (
    project_id              TEXT PRIMARY KEY,
    auto_aggressive_ack_at  TEXT,
    auto_aggressive_ack_by  TEXT,
    updated_at              TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ai_audit_events (
    id           TEXT PRIMARY KEY,
    session_id   TEXT,
    project_id   TEXT NOT NULL,
    event_type   TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    created_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ai_audit_project_created
    ON ai_audit_events (project_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ai_audit_session_created
    ON ai_audit_events (session_id, created_at DESC);
"""

# Shared CREATE statements for AI app notes (schema v50).
_AI_SCHEMA_V50_DDL = """
CREATE TABLE IF NOT EXISTS ai_app_notes (
    project_id     TEXT PRIMARY KEY,
    revision       INTEGER NOT NULL DEFAULT 1,
    doc_json       TEXT    NOT NULL,
    updated_at     TEXT    NOT NULL,
    updated_by     TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS ai_app_note_revisions (
    id             TEXT PRIMARY KEY,
    project_id     TEXT NOT NULL,
    revision       INTEGER NOT NULL,
    doc_json       TEXT NOT NULL,
    updated_at     TEXT NOT NULL,
    updated_by     TEXT NOT NULL,
    UNIQUE(project_id, revision)
);
CREATE INDEX IF NOT EXISTS idx_ai_app_note_revisions_project
    ON ai_app_note_revisions (project_id, revision DESC);
"""

# Shared CREATE statements for AI suggest/approve loop tables (schema v51).
_AI_SCHEMA_V51_DDL = """
CREATE TABLE IF NOT EXISTS ai_suggestions (
    id               TEXT PRIMARY KEY,
    session_id       TEXT NOT NULL,
    tool_name        TEXT NOT NULL,
    arguments_json   TEXT NOT NULL,
    rationale        TEXT,
    cli_preview      TEXT,
    display_risk     TEXT,
    created_at       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ai_suggestions_session
    ON ai_suggestions (session_id, created_at DESC);

CREATE TABLE IF NOT EXISTS ai_execution_plans (
    id                    TEXT PRIMARY KEY,
    suggestion_id         TEXT NOT NULL,
    session_id            TEXT NOT NULL,
    tool_name             TEXT NOT NULL,
    arguments_json        TEXT NOT NULL,
    capabilities_json     TEXT NOT NULL,
    status                TEXT NOT NULL,
    policy_meta_json      TEXT NOT NULL DEFAULT '{}',
    capability_token_hash TEXT,
    failure_reason        TEXT,
    created_at            TEXT NOT NULL,
    decided_at            TEXT,
    FOREIGN KEY (suggestion_id) REFERENCES ai_suggestions(id)
);
CREATE INDEX IF NOT EXISTS idx_ai_execution_plans_session
    ON ai_execution_plans (session_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ai_execution_plans_suggestion
    ON ai_execution_plans (suggestion_id, created_at DESC);

CREATE TABLE IF NOT EXISTS ai_observations (
    id              TEXT PRIMARY KEY,
    session_id      TEXT NOT NULL,
    suggestion_id   TEXT NOT NULL,
    plan_id         TEXT NOT NULL,
    tool_name       TEXT NOT NULL,
    result_summary  TEXT NOT NULL,
    citations_json  TEXT NOT NULL,
    raw_ref         TEXT,
    untrusted       INTEGER NOT NULL DEFAULT 1,
    created_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ai_observations_session
    ON ai_observations (session_id, created_at DESC);

CREATE TABLE IF NOT EXISTS ai_task_nodes (
    node_id              TEXT PRIMARY KEY,
    session_id           TEXT NOT NULL,
    project_id           TEXT NOT NULL,
    parent_id            TEXT,
    title                TEXT NOT NULL,
    status               TEXT NOT NULL,
    hypothesis           TEXT,
    evidence_refs_json   TEXT NOT NULL DEFAULT '{}',
    suggested_tools_json TEXT NOT NULL DEFAULT '[]',
    priority             INTEGER NOT NULL DEFAULT 0,
    created_at           TEXT NOT NULL,
    updated_at           TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ai_task_nodes_session
    ON ai_task_nodes (session_id, priority DESC, updated_at DESC);
"""

# Shared CREATE statements for cross-flow reflection tables (schema v42).
# Used by _migrate_schema and migrate_project_db so upgrade paths stay in sync
# with the CREATE TABLE blocks embedded in _DDL above.
_CROSS_FLOW_SCHEMA_V42_DDL = """
CREATE TABLE IF NOT EXISTS value_index (
    id                   TEXT    PRIMARY KEY,
    project_id           TEXT    NOT NULL,
    host                 TEXT    NOT NULL,
    value_hash           TEXT    NOT NULL,
    value_match          TEXT    NOT NULL,
    value_len            INTEGER NOT NULL,
    source_flow_id       TEXT    NOT NULL,
    first_source_flow_id TEXT    NOT NULL,
    source_endpoint_id   TEXT,
    source_param_id      TEXT,
    source_param_uuid    TEXT    NOT NULL,
    source_param_name    TEXT    NOT NULL,
    source_location      TEXT    NOT NULL,
    source_method        TEXT    NOT NULL DEFAULT '',
    source_path          TEXT    NOT NULL DEFAULT '',
    source_role_id       TEXT,
    first_seen_at        TEXT    NOT NULL,
    last_seen_at         TEXT    NOT NULL,
    hit_count            INTEGER NOT NULL DEFAULT 1,
    is_canary            INTEGER NOT NULL DEFAULT 0,
    expires_at           TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_value_index_host_hash_param
    ON value_index (host, value_hash, source_param_uuid);

CREATE INDEX IF NOT EXISTS idx_value_index_host_hash
    ON value_index (host, value_hash);

CREATE INDEX IF NOT EXISTS idx_value_index_param
    ON value_index (source_param_uuid);

CREATE INDEX IF NOT EXISTS idx_value_index_expires
    ON value_index (expires_at);

CREATE INDEX IF NOT EXISTS idx_value_index_host_canary_seen
    ON value_index (host, is_canary DESC, last_seen_at DESC);

CREATE TABLE IF NOT EXISTS cross_flow_reflections (
    id                   TEXT    PRIMARY KEY,
    project_id           TEXT    NOT NULL,
    host                 TEXT    NOT NULL,

    source_flow_id       TEXT    NOT NULL,
    first_source_flow_id TEXT    NOT NULL,
    source_endpoint_id   TEXT,
    source_param_id      TEXT,
    source_param_uuid    TEXT    NOT NULL,
    source_param_name    TEXT    NOT NULL,
    source_location      TEXT    NOT NULL,
    source_method        TEXT    NOT NULL DEFAULT '',
    source_path          TEXT    NOT NULL DEFAULT '',
    source_role_id       TEXT,

    sink_flow_id         TEXT    NOT NULL,
    sink_endpoint_id     TEXT,
    sink_method          TEXT    NOT NULL DEFAULT '',
    sink_path            TEXT    NOT NULL DEFAULT '',
    sink_content_type    TEXT    NOT NULL DEFAULT '',
    sink_context         TEXT    NOT NULL DEFAULT 'other',
    sink_role_id         TEXT,
    encoding             TEXT    NOT NULL DEFAULT 'raw',
    transforms           TEXT    NOT NULL DEFAULT '[]',

    value_hash           TEXT    NOT NULL,
    value_len            INTEGER NOT NULL DEFAULT 0,
    match_kind           TEXT    NOT NULL DEFAULT 'exact',
    confidence           INTEGER NOT NULL DEFAULT 70,
    detection_mode       TEXT    NOT NULL DEFAULT 'passive',
    first_seen_at        TEXT    NOT NULL,
    last_seen_at         TEXT    NOT NULL,
    observation_count    INTEGER NOT NULL DEFAULT 1,

    UNIQUE (source_param_uuid, sink_flow_id, value_hash, encoding)
);

CREATE INDEX IF NOT EXISTS idx_cross_flow_reflections_param
    ON cross_flow_reflections (source_param_uuid);

CREATE INDEX IF NOT EXISTS idx_cross_flow_reflections_host_seen
    ON cross_flow_reflections (host, last_seen_at DESC);

CREATE INDEX IF NOT EXISTS idx_cross_flow_reflections_sink_ep
    ON cross_flow_reflections (sink_endpoint_id);

CREATE INDEX IF NOT EXISTS idx_cross_flow_reflections_source_ep
    ON cross_flow_reflections (source_endpoint_id);
"""

# Shared CREATE statements for Error Intelligence (schema v43).
# Used by _migrate_schema and migrate_project_db so upgrade paths stay in sync
# with the CREATE TABLE blocks embedded in _DDL above.
_ERROR_INTEL_SCHEMA_V43_DDL = """
CREATE TABLE IF NOT EXISTS error_clusters (
    id                   TEXT    PRIMARY KEY,
    project_id           TEXT    NOT NULL,
    fingerprint          TEXT    NOT NULL,
    category             TEXT    NOT NULL,
    severity             TEXT    NOT NULL,
    language             TEXT    NOT NULL DEFAULT 'unknown',
    framework            TEXT,
    database             TEXT,
    server               TEXT,
    exception_type       TEXT,
    message_norm         TEXT,
    technologies_json    TEXT    NOT NULL DEFAULT '[]',
    has_stack_trace      INTEGER NOT NULL DEFAULT 0,
    has_path_leak        INTEGER NOT NULL DEFAULT 0,
    has_internal_host    INTEGER NOT NULL DEFAULT 0,
    has_version_leak     INTEGER NOT NULL DEFAULT 0,
    confidence           INTEGER NOT NULL DEFAULT 0,
    evidence_snippet     TEXT,
    first_seen           TEXT,
    last_seen            TEXT,
    observation_count    INTEGER NOT NULL DEFAULT 0,
    scanner_version      TEXT,
    UNIQUE (project_id, fingerprint)
);
CREATE INDEX IF NOT EXISTS idx_error_clusters_project_seen
    ON error_clusters (project_id, last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_error_clusters_category_sev
    ON error_clusters (project_id, category, severity);
CREATE INDEX IF NOT EXISTS idx_error_clusters_exception
    ON error_clusters (project_id, exception_type);

CREATE TABLE IF NOT EXISTS error_observations (
    id                   TEXT    PRIMARY KEY,
    error_id             TEXT    NOT NULL REFERENCES error_clusters(id),
    flow_id              TEXT,
    endpoint_id          TEXT,
    parameter_uuid       TEXT,
    parameter_name       TEXT,
    attack_type          TEXT    NOT NULL DEFAULT 'unknown',
    payload_redacted     TEXT,
    response_status      INTEGER,
    response_length      INTEGER,
    duration_ms          REAL,
    response_hash        TEXT,
    artifacts_json       TEXT    NOT NULL DEFAULT '[]',
    detectors_json       TEXT    NOT NULL DEFAULT '[]',
    observed_at          TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_error_observations_error
    ON error_observations (error_id, observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_error_observations_flow
    ON error_observations (flow_id);
CREATE INDEX IF NOT EXISTS idx_error_observations_endpoint
    ON error_observations (endpoint_id);
CREATE INDEX IF NOT EXISTS idx_error_observations_param
    ON error_observations (parameter_uuid);
CREATE INDEX IF NOT EXISTS idx_error_observations_attack
    ON error_observations (attack_type);

CREATE UNIQUE INDEX IF NOT EXISTS idx_error_observations_flow_unique
    ON error_observations (flow_id)
    WHERE flow_id IS NOT NULL AND flow_id != '';

CREATE TABLE IF NOT EXISTS error_intel_config (
    id                           TEXT    PRIMARY KEY DEFAULT 'default',
    enabled                      INTEGER NOT NULL DEFAULT 1,
    store_generic_http_errors    INTEGER NOT NULL DEFAULT 0,
    max_body_scan                INTEGER NOT NULL DEFAULT 512000,
    gate_sniff_bytes             INTEGER NOT NULL DEFAULT 16384,
    queue_maxsize                INTEGER NOT NULL DEFAULT 500,
    evidence_snippet_max         INTEGER NOT NULL DEFAULT 4096,
    error_header_names_json      TEXT    NOT NULL DEFAULT '[]'
);
"""

# Shared CREATE statements for Passive Source Intelligence (schema v39).
# Used by _migrate_schema and migrate_project_db so upgrade paths stay in sync
# with the CREATE TABLE blocks embedded in _DDL above.
_PASSIVE_SCHEMA_V39_DDL = """
CREATE TABLE IF NOT EXISTS source_documents (
    id                   TEXT    PRIMARY KEY,
    project_id           TEXT    NOT NULL,
    body_hash            TEXT    NOT NULL,
    source_kind          TEXT    NOT NULL,
    body_size            INTEGER NOT NULL,
    truncated            INTEGER NOT NULL DEFAULT 0,
    scanner_version      TEXT,
    scan_status          TEXT    NOT NULL DEFAULT 'pending',
    first_flow_id        TEXT,
    first_seen           TEXT,
    last_seen            TEXT,
    last_scanned_at      TEXT,
    error_message        TEXT,
    parent_document_id   TEXT,
    logical_source_name  TEXT,
    UNIQUE (project_id, body_hash)
);
CREATE INDEX IF NOT EXISTS idx_source_documents_project
    ON source_documents (project_id, last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_source_documents_status
    ON source_documents (project_id, scan_status);
CREATE INDEX IF NOT EXISTS idx_source_documents_parent
    ON source_documents (parent_document_id);

CREATE TABLE IF NOT EXISTS source_occurrences (
    id                   TEXT    PRIMARY KEY,
    document_id          TEXT    NOT NULL REFERENCES source_documents(id),
    flow_id              TEXT,
    endpoint_id          TEXT,
    url                  TEXT    NOT NULL DEFAULT '',
    host                 TEXT    NOT NULL DEFAULT '',
    path                 TEXT    NOT NULL DEFAULT '',
    logical_source_name  TEXT,
    content_type         TEXT    NOT NULL DEFAULT '',
    observed_at          TEXT    NOT NULL,
    role_id              TEXT    NOT NULL DEFAULT '',
    module_id            TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_source_occurrences_document
    ON source_occurrences (document_id, observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_source_occurrences_flow
    ON source_occurrences (flow_id);

CREATE TABLE IF NOT EXISTS passive_detections (
    id                   TEXT    PRIMARY KEY,
    document_id          TEXT    NOT NULL REFERENCES source_documents(id),
    occurrence_id        TEXT,
    detector_id          TEXT    NOT NULL,
    detector_family      TEXT    NOT NULL,
    category             TEXT    NOT NULL,
    secret_type          TEXT    NOT NULL DEFAULT '',
    matched_key          TEXT,
    redacted_value       TEXT    NOT NULL DEFAULT '',
    value_fingerprint    TEXT    NOT NULL,
    confidence_score     INTEGER NOT NULL DEFAULT 0,
    confidence_level     TEXT    NOT NULL,
    entropy              REAL,
    encoding_chain       TEXT    NOT NULL DEFAULT '[]',
    decode_depth         INTEGER NOT NULL DEFAULT 0,
    match_start          INTEGER NOT NULL DEFAULT 0,
    match_end            INTEGER NOT NULL DEFAULT 0,
    context_before       TEXT    NOT NULL DEFAULT '',
    context_after        TEXT    NOT NULL DEFAULT '',
    suppressed           INTEGER NOT NULL DEFAULT 0,
    suppression_reason   TEXT,
    finding_id           TEXT,
    raw_value_stored     INTEGER NOT NULL DEFAULT 0,
    created_at           TEXT    NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_passive_detections_dedup
    ON passive_detections (document_id, detector_id, value_fingerprint, match_start);
CREATE INDEX IF NOT EXISTS idx_passive_detections_document
    ON passive_detections (document_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_passive_detections_fingerprint
    ON passive_detections (value_fingerprint);
CREATE INDEX IF NOT EXISTS idx_passive_detections_finding
    ON passive_detections (finding_id);

CREATE TABLE IF NOT EXISTS passive_scan_config (
    id                           TEXT    PRIMARY KEY DEFAULT 'default',
    enabled                      INTEGER NOT NULL DEFAULT 1,
    auto_finding_threshold       TEXT    NOT NULL DEFAULT 'HIGH',
    max_document_size            INTEGER NOT NULL DEFAULT 2000000,
    max_decode_depth             INTEGER NOT NULL DEFAULT 3,
    max_decode_bytes             INTEGER NOT NULL DEFAULT 256000,
    max_candidates_per_document  INTEGER NOT NULL DEFAULT 500,
    scan_html                    INTEGER NOT NULL DEFAULT 1,
    scan_javascript              INTEGER NOT NULL DEFAULT 1,
    scan_json                    INTEGER NOT NULL DEFAULT 1,
    scan_xml                     INTEGER NOT NULL DEFAULT 1,
    scan_text                    INTEGER NOT NULL DEFAULT 1,
    scan_css                     INTEGER NOT NULL DEFAULT 1,
    scan_sourcemaps              INTEGER NOT NULL DEFAULT 1,
    scan_wasm                    INTEGER NOT NULL DEFAULT 0,
    store_raw_secret_in_evidence INTEGER NOT NULL DEFAULT 1,
    store_suppressed_detections  INTEGER NOT NULL DEFAULT 0,
    queue_maxsize                INTEGER NOT NULL DEFAULT 500,
    max_scan_time_ms             INTEGER NOT NULL DEFAULT 0
);
"""


def init_project_db(db_path: Path) -> None:
    """
    Purpose:
        Create the project SQLite database and apply the full schema.
        Idempotent — safe to call on an existing database (uses IF NOT EXISTS).
    Input:
        db_path — absolute Path to the .db file to create/open.
    Output:
        None
    Side effects:
        - Creates file at db_path if it does not exist.
        - Runs DDL statements against the database.
        - Inserts schema_version row if not present.
        - Seeds the "global" role and module as default context entries.
    """
    db_path.parent.mkdir(parents=True, exist_ok=True)

    with sqlite3.connect(str(db_path)) as conn:
        conn.executescript(_DDL)

        row = conn.execute("SELECT version FROM schema_version").fetchone()
        if row is None:
            conn.execute(
                "INSERT INTO schema_version (version) VALUES (?)",
                (SCHEMA_VERSION,),
            )
            conn.commit()
        elif row[0] < SCHEMA_VERSION:
            _migrate_schema(conn, row[0])
            conn.execute("UPDATE schema_version SET version = ?", (SCHEMA_VERSION,))
            conn.commit()

        # Seed passive scan defaults (single-row config). Safe on every init.
        conn.execute(
            "INSERT OR IGNORE INTO passive_scan_config (id) VALUES ('default')"
        )
        # Seed Error Intelligence defaults (schema v43). Safe on every init.
        conn.execute(
            "INSERT OR IGNORE INTO error_intel_config (id) VALUES ('default')"
        )
        conn.commit()

    # Seed default context after schema is guaranteed current.
    # Uses INSERT OR IGNORE so repeated calls are safe.
    _seed_default_context(db_path)


def seed_default_context(db_path: Path) -> None:
    """
    Purpose:
        Public entry point for ensuring the "global" role and module exist and
        one of each is marked active.  Called by the FlowWorker at proxy start
        so that every proxy session has a valid capture context, including
        databases created before v2 that may not have been re-initialised.
    Input:
        db_path — absolute Path to an already-initialised project DB.
    Side effects:
        Same as _seed_default_context; delegates directly.
    """
    _seed_default_context(db_path)


def _migrate_schema(conn: sqlite3.Connection, from_version: int) -> None:
    """
    Purpose:
        Apply incremental schema migrations for databases created at an earlier
        version.  Each migration block is guarded so it is safe to run on a DB
        that already has the column/table (e.g. if migration was partially applied).
    Input:
        conn         — Open SQLite connection with an active transaction.
        from_version — The version stored in schema_version before migration.
    Side effects:
        - Issues ALTER TABLE / CREATE TABLE statements.
        - Does not COMMIT — caller commits after updating schema_version.
    """
    if from_version < 25:
        # Add new columns to parameters table introduced in v25.
        new_cols = [
            ("semantic_type",        "TEXT NOT NULL DEFAULT 'unknown'"),
            ("seen_count",           "INTEGER NOT NULL DEFAULT 1"),
            ("appears_in_roles",     "TEXT NOT NULL DEFAULT '[]'"),
            ("appears_in_modules",   "TEXT NOT NULL DEFAULT '[]'"),
            ("is_reflected",         "INTEGER NOT NULL DEFAULT 0"),
            ("reflection_count",     "INTEGER NOT NULL DEFAULT 0"),
            ("reflection_locations", "TEXT NOT NULL DEFAULT '[]'"),
            ("reflection_encoding",  "TEXT NOT NULL DEFAULT '[]'"),
        ]
        existing = {
            row[1]
            for row in conn.execute("PRAGMA table_info(parameters)").fetchall()
        }
        for col_name, col_def in new_cols:
            if col_name not in existing:
                conn.execute(
                    f"ALTER TABLE parameters ADD COLUMN {col_name} {col_def}"
                )

    if from_version < 26:
        # Add flow_id column to iv_param_cache and iv_reflection_cache so each
        # IV analysis can be traced back to the base flow that was used.
        existing_ipc = {
            row[1]
            for row in conn.execute("PRAGMA table_info(iv_param_cache)").fetchall()
        }
        if "flow_id" not in existing_ipc:
            conn.execute("ALTER TABLE iv_param_cache ADD COLUMN flow_id TEXT")

        existing_irc = {
            row[1]
            for row in conn.execute(
                "PRAGMA table_info(iv_reflection_cache)"
            ).fetchall()
        }
        if "flow_id" not in existing_irc:
            conn.execute("ALTER TABLE iv_reflection_cache ADD COLUMN flow_id TEXT")

    if from_version < 31:
        # Create Findings subsystem tables introduced in v31.
        # Each CREATE TABLE uses IF NOT EXISTS so partial runs are safe.
        # Columns relation_type/parent_finding_id/cluster_key are added by v34
        # when upgrading older DBs; fresh installs get them from SCHEMA_VERSION DDL.
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS findings (
                id           TEXT    PRIMARY KEY,
                project_id   TEXT    NOT NULL,
                attack_type  TEXT    NOT NULL,
                verdict      TEXT    NOT NULL,
                endpoint_id  TEXT,
                status       TEXT    NOT NULL DEFAULT 'TRIAGING',
                duplicate_of TEXT,
                created_at   TEXT    NOT NULL,
                updated_at   TEXT    NOT NULL,
                title        TEXT    NOT NULL DEFAULT '',
                notes        TEXT    NOT NULL DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS idx_findings_project
                ON findings (project_id, status, created_at DESC);

            CREATE TABLE IF NOT EXISTS finding_evidence (
                id            TEXT    PRIMARY KEY,
                finding_id    TEXT    NOT NULL REFERENCES findings(id),
                evidence_type TEXT    NOT NULL,
                reference_id  TEXT,
                label         TEXT    NOT NULL DEFAULT '',
                data          TEXT    NOT NULL DEFAULT '{}',
                created_at    TEXT    NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_finding_evidence_finding
                ON finding_evidence (finding_id, created_at ASC);

            CREATE TABLE IF NOT EXISTS finding_timeline (
                id         TEXT    PRIMARY KEY,
                finding_id TEXT    NOT NULL REFERENCES findings(id),
                event      TEXT    NOT NULL,
                actor      TEXT    NOT NULL DEFAULT 'system',
                created_at TEXT    NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_finding_timeline_finding
                ON finding_timeline (finding_id, created_at ASC);

            CREATE TABLE IF NOT EXISTS finding_groups (
                id         TEXT    PRIMARY KEY,
                project_id TEXT    NOT NULL,
                name       TEXT    NOT NULL,
                created_at TEXT    NOT NULL,
                UNIQUE (project_id, name)
            );
            CREATE INDEX IF NOT EXISTS idx_finding_groups_project
                ON finding_groups (project_id);

            CREATE TABLE IF NOT EXISTS finding_group_members (
                group_id   TEXT    NOT NULL REFERENCES finding_groups(id) ON DELETE CASCADE,
                finding_id TEXT    NOT NULL REFERENCES findings(id),
                added_at   TEXT    NOT NULL,
                PRIMARY KEY (group_id, finding_id)
            );
            CREATE INDEX IF NOT EXISTS idx_finding_group_members_finding
                ON finding_group_members (finding_id);
        """)

    if from_version < 34:
        # Finding relationships (PRIMARY / LINKED) + cluster_key uniqueness.
        existing_findings = {
            row[1]
            for row in conn.execute("PRAGMA table_info(findings)").fetchall()
        }
        if existing_findings:
            if "relation_type" not in existing_findings:
                conn.execute(
                    "ALTER TABLE findings ADD COLUMN relation_type "
                    "TEXT NOT NULL DEFAULT 'PRIMARY'"
                )
            if "parent_finding_id" not in existing_findings:
                conn.execute(
                    "ALTER TABLE findings ADD COLUMN parent_finding_id TEXT"
                )
            if "cluster_key" not in existing_findings:
                conn.execute(
                    "ALTER TABLE findings ADD COLUMN cluster_key TEXT"
                )
            # Backfill is best-effort here; migrate_project_db performs the
            # full PRIMARY/LINKED consolidation when used as the upgrade path.
            rows = conn.execute(
                """
                SELECT id, attack_type, endpoint_id, created_at
                FROM findings
                WHERE cluster_key IS NULL
                ORDER BY created_at ASC, id ASC
                """
            ).fetchall()
            primary_by_cluster: dict = {}
            for fid, attack_type, endpoint_id, _created in rows:
                if not endpoint_id:
                    continue
                at = (attack_type or "").lower()
                if at == "unauth":
                    ck = f"UNAUTH:{endpoint_id}"
                elif at == "auth_test":
                    ck = f"AUTH_TEST:{endpoint_id}"
                elif at == "bac":
                    ck = f"BAC:{endpoint_id}:{fid}"
                else:
                    ck = f"{(attack_type or 'UNKNOWN').upper()}:{endpoint_id}"
                if ck not in primary_by_cluster:
                    primary_by_cluster[ck] = fid
                    conn.execute(
                        """
                        UPDATE findings
                        SET relation_type = 'PRIMARY',
                            parent_finding_id = NULL,
                            cluster_key = ?
                        WHERE id = ?
                        """,
                        (ck, fid),
                    )
                else:
                    conn.execute(
                        """
                        UPDATE findings
                        SET relation_type = 'LINKED',
                            parent_finding_id = ?,
                            cluster_key = ?
                        WHERE id = ?
                        """,
                        (primary_by_cluster[ck], ck, fid),
                    )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_findings_parent "
            "ON findings (parent_finding_id)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_findings_relation "
            "ON findings (project_id, relation_type)"
        )
        conn.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_primary_cluster
                ON findings (cluster_key)
                WHERE relation_type = 'PRIMARY' AND cluster_key IS NOT NULL
            """
        )

    if from_version < 35:
        # IV multi-level intelligence profiles (Module 2).
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS iv_param_profiles (
                id              TEXT    PRIMARY KEY,
                param_uuid      TEXT    NOT NULL,
                host            TEXT    NOT NULL,
                location        TEXT    NOT NULL,
                param_name      TEXT    NOT NULL,
                schema_version  INTEGER NOT NULL DEFAULT 1,
                profile_version INTEGER NOT NULL DEFAULT 1,
                profile         TEXT    NOT NULL DEFAULT '{}',
                created_at      TEXT    NOT NULL,
                updated_at      TEXT    NOT NULL,
                UNIQUE (param_uuid)
            );
            CREATE INDEX IF NOT EXISTS idx_iv_param_profiles_host
                ON iv_param_profiles (host, location, param_name);

            CREATE TABLE IF NOT EXISTS iv_endpoint_profiles (
                id              TEXT    PRIMARY KEY,
                endpoint_id     TEXT    NOT NULL,
                host            TEXT    NOT NULL DEFAULT '',
                schema_version  INTEGER NOT NULL DEFAULT 1,
                profile_version INTEGER NOT NULL DEFAULT 1,
                profile         TEXT    NOT NULL DEFAULT '{}',
                created_at      TEXT    NOT NULL,
                updated_at      TEXT    NOT NULL,
                UNIQUE (endpoint_id)
            );
            CREATE INDEX IF NOT EXISTS idx_iv_endpoint_profiles_host
                ON iv_endpoint_profiles (host);

            CREATE TABLE IF NOT EXISTS iv_app_profiles (
                id              TEXT    PRIMARY KEY,
                host            TEXT    NOT NULL,
                schema_version  INTEGER NOT NULL DEFAULT 1,
                profile_version INTEGER NOT NULL DEFAULT 1,
                profile         TEXT    NOT NULL DEFAULT '{}',
                created_at      TEXT    NOT NULL,
                updated_at      TEXT    NOT NULL,
                UNIQUE (host)
            );
        """)

    if from_version < 39:
        # Passive Source Intelligence tables + default config row.
        conn.executescript(_PASSIVE_SCHEMA_V39_DDL)
        conn.execute(
            "INSERT OR IGNORE INTO passive_scan_config (id) VALUES ('default')"
        )

    if from_version < 40:
        # Phase 10: virtual document parent linkage + logical name on documents.
        existing_sd = {
            row[1]
            for row in conn.execute(
                "PRAGMA table_info(source_documents)"
            ).fetchall()
        }
        if existing_sd and "parent_document_id" not in existing_sd:
            conn.execute(
                "ALTER TABLE source_documents "
                "ADD COLUMN parent_document_id TEXT"
            )
        if existing_sd and "logical_source_name" not in existing_sd:
            conn.execute(
                "ALTER TABLE source_documents "
                "ADD COLUMN logical_source_name TEXT"
            )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_source_documents_parent "
            "ON source_documents (parent_document_id)"
        )

    if from_version < 41:
        # Soft per-document scan budget (Phase 14 config field).
        existing_cfg = {
            row[1]
            for row in conn.execute(
                "PRAGMA table_info(passive_scan_config)"
            ).fetchall()
        }
        if existing_cfg and "max_scan_time_ms" not in existing_cfg:
            conn.execute(
                "ALTER TABLE passive_scan_config "
                "ADD COLUMN max_scan_time_ms INTEGER NOT NULL DEFAULT 0"
            )

    if from_version < 42:
        # Cross-page / stored reflection: value index + source→sink links.
        conn.executescript(_CROSS_FLOW_SCHEMA_V42_DDL)
        existing_params = {
            row[1]
            for row in conn.execute("PRAGMA table_info(parameters)").fetchall()
        }
        if existing_params:
            cross_flow_cols = [
                ("cross_flow_reflected", "INTEGER NOT NULL DEFAULT 0"),
                ("cross_flow_reflection_count", "INTEGER NOT NULL DEFAULT 0"),
                ("cross_flow_sink_endpoints", "TEXT NOT NULL DEFAULT '[]'"),
            ]
            for col_name, col_def in cross_flow_cols:
                if col_name not in existing_params:
                    conn.execute(
                        f"ALTER TABLE parameters ADD COLUMN {col_name} {col_def}"
                    )

    if from_version < 43:
        # Error Intelligence — clusters, observations, config (no Findings).
        conn.executescript(_ERROR_INTEL_SCHEMA_V43_DDL)
        conn.execute(
            "INSERT OR IGNORE INTO error_intel_config (id) VALUES ('default')"
        )

    if from_version < 46:
        # Intruder sessions + results (Phase 1 CLI engine).
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS intruder_sessions (
                id               TEXT    PRIMARY KEY,
                project_id       TEXT    NOT NULL,
                name             TEXT    NOT NULL DEFAULT '',
                status           TEXT    NOT NULL DEFAULT 'draft',
                base_flow_id     TEXT,
                endpoint_id      TEXT,
                config_json      TEXT    NOT NULL DEFAULT '{}',
                checkpoint_json  TEXT    NOT NULL DEFAULT '{}',
                progress_json    TEXT    NOT NULL DEFAULT '{}',
                job_id           TEXT,
                control_flag     TEXT,
                created_at       TEXT    NOT NULL,
                updated_at       TEXT    NOT NULL,
                started_at       TEXT,
                finished_at      TEXT,
                failure_reason   TEXT,
                schema_version   INTEGER NOT NULL DEFAULT 1
            );
            CREATE INDEX IF NOT EXISTS idx_intruder_sessions_project
                ON intruder_sessions (project_id, status, updated_at DESC);

            CREATE TABLE IF NOT EXISTS intruder_results (
                id               TEXT    PRIMARY KEY,
                session_id       TEXT    NOT NULL REFERENCES intruder_sessions(id) ON DELETE CASCADE,
                attempt_index    INTEGER NOT NULL,
                variables_json   TEXT    NOT NULL DEFAULT '{}',
                status_code      INTEGER,
                success          INTEGER NOT NULL DEFAULT 0,
                failure_reason   TEXT,
                duration_ms      REAL,
                body_length      INTEGER,
                word_count       INTEGER,
                line_count       INTEGER,
                body_hash        TEXT,
                fingerprint_json TEXT    NOT NULL DEFAULT '{}',
                metrics_json     TEXT    NOT NULL DEFAULT '{}',
                interesting      INTEGER NOT NULL DEFAULT 0,
                match_tags_json  TEXT    NOT NULL DEFAULT '[]',
                grepped_json     TEXT    NOT NULL DEFAULT '{}',
                flow_id          TEXT,
                finding_id       TEXT,
                created_at       TEXT    NOT NULL,
                UNIQUE (session_id, attempt_index)
            );
            CREATE INDEX IF NOT EXISTS idx_intruder_results_session
                ON intruder_results (session_id, attempt_index);
            CREATE INDEX IF NOT EXISTS idx_intruder_results_interesting
                ON intruder_results (session_id, interesting) WHERE interesting = 1;
            CREATE INDEX IF NOT EXISTS idx_intruder_results_finding
                ON intruder_results (finding_id) WHERE finding_id IS NOT NULL;
        """)

    if from_version < 47:
        # Intruder Phase 3 extracted value pools.
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS intruder_pools (
                id               TEXT    PRIMARY KEY,
                project_id       TEXT    NOT NULL,
                name             TEXT    NOT NULL,
                session_id       TEXT,
                values_json      TEXT    NOT NULL DEFAULT '[]',
                source_rule      TEXT,
                created_at       TEXT    NOT NULL,
                updated_at       TEXT    NOT NULL,
                UNIQUE (project_id, name)
            );
            CREATE INDEX IF NOT EXISTS idx_intruder_pools_project
                ON intruder_pools (project_id, updated_at DESC);
        """)

    if from_version < 48:
        # Intruder Phase 5: optional findings promote lineage on results.
        cols = {
            row[1]
            for row in conn.execute("PRAGMA table_info(intruder_results)").fetchall()
        }
        if "finding_id" not in cols:
            conn.execute(
                "ALTER TABLE intruder_results ADD COLUMN finding_id TEXT"
            )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_intruder_results_finding
                ON intruder_results (finding_id)
                WHERE finding_id IS NOT NULL
            """
        )

    if from_version < 49:
        # AI Layer Phase A: sessions, audit events, project prefs.
        conn.executescript(_AI_SCHEMA_V49_DDL)


def _seed_default_context(db_path: Path) -> None:
    """
    Purpose:
        Ensure the "global" role and "global" module exist and one of each
        is marked active.  Called after every schema init or migration so the
        proxy always has a defined capture context even before any user
        configuration.
    Input:
        db_path — absolute Path to an already-initialised project DB.
    Side effects:
        - Inserts "global" role if absent (INSERT OR IGNORE on name UNIQUE).
        - Inserts "global" module if absent.
        - Activates "global" role if no role is currently active.
        - Activates "global" module if no module is currently active.
    """
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute(
            "INSERT OR IGNORE INTO roles (id, name, is_active) VALUES (?, 'global', 0)",
            (str(uuid.uuid4()),),
        )
        conn.execute(
            "INSERT OR IGNORE INTO modules (id, name, description, is_active)"
            " VALUES (?, 'global', '', 0)",
            (str(uuid.uuid4()),),
        )

        # Activate "global" role only when no role is currently marked active.
        # Avoids overriding an intentionally-set user role on re-init.
        has_active_role = conn.execute(
            "SELECT 1 FROM roles WHERE is_active = 1 LIMIT 1"
        ).fetchone()
        if has_active_role is None:
            conn.execute("UPDATE roles SET is_active = 1 WHERE name = 'global'")

        has_active_module = conn.execute(
            "SELECT 1 FROM modules WHERE is_active = 1 LIMIT 1"
        ).fetchone()
        if has_active_module is None:
            conn.execute("UPDATE modules SET is_active = 1 WHERE name = 'global'")

        conn.commit()


def migrate_project_db(db_path: Path) -> None:
    """
    Purpose:
        Apply incremental schema migrations to an existing project database.
        Safe to call on a fully up-to-date database — all checks are no-ops when
        the schema is already at SCHEMA_VERSION.
    Input:
        db_path — absolute Path to an existing .db file.
    Output:
        None
    Side effects:
        - May ALTER TABLE flows to add replay columns.
        - Updates schema_version row when a migration is applied.
        - No-op when the DB is already at SCHEMA_VERSION or the file is absent.

    Migration log:
        v6  → v7:  Add source, original_flow_id, replay_error to flows.
        v7  → v8:  Add replay_reason to flows.
        v8  → v9:  Add replay_diffs table.
        v9  → v10: Add auth_config and auth_test_results tables.
        v10 → v11: Add endpoint_annotations table.
        v11 → v12: Add scheduler_jobs table and status/priority index.
        v12 → v13: Add scheduled_at column to scheduler_jobs; add scheduler_config table.
        v14 → v15: Add request_mutations table.
        v15 → v16: Add attack_config table.
        v16 → v17: Add attack_host_exclusions table.
        v17 → v18: Add path column to attack_host_exclusions; update PRIMARY KEY.
        v18 → v19: Add role_auth and role_session_tokens tables.
        v19 → v20: Add meta column to scheduler_jobs; add bac_results table.
        v20 → v21: Add auth_flow_config, role_auth_state, session_health_config,
                   session_health_control_flows, session_suspicion_state tables.
        v21 → v22: Add matched_section, matched_group, matched_rules columns to
                   bac_results for rich decision evidence storage.
        v22 → v23: Add endpoint_policy and policy_rules tables for the
                   Endpoint Policy system (auto-priority, manual-priority,
                   exclusion, path-based rules).
        v33 → v34: Add finding relationships: relation_type (PRIMARY|LINKED),
                   parent_finding_id, cluster_key; partial unique index
                   idx_findings_primary_cluster; backfill existing clusters.
        v23 → v24: Add dangerous and logout columns to endpoint_policy;
                   migrate data from endpoint_annotations.
        v25 → v26: Add flow_id column to iv_param_cache and iv_reflection_cache
                   so each IV analysis is traceable to the base flow used.
        v26 → v27: Add flow_meta JSON column to flows for universal replay metadata.
                   Add iv_probe_results table for per-HTTP-request IV evidence.
        v27 → v28: Slim iv_probe_results — remove duplicated HTTP columns
                   (status_code, content_type, body_length, error) which live in
                   the flows table; rename payload_class → payload_type.
        v28 → v29: Add role_auth_provider, manual_session_config, and
                   scheduler_state tables for the Authentication Provider
                   architecture (AUTO vs MANUAL session management).
        v29 → v30: Add qualified, qualification_reason, baseline_flow_id,
                   baseline_status columns to endpoint_policy for the
                   Endpoint Qualification system. Backfills existing rows.
        v30 → v31: Add Findings subsystem tables: findings, finding_evidence,
                   finding_timeline, finding_groups, finding_group_members.
        v31 → v32: Add mutation_family and mutation columns to bac_results.
                   Add unauth_results table for unauth attack verdicts.
        v32 → v33: Add proxy_config table for configurable upstream-proxy
                   mode (Direct vs Upstream Proxy — Burp/ZAP/corporate proxy).
        v34 → v35: Add IV multi-level profile tables (Module 2):
                   iv_param_profiles, iv_endpoint_profiles, iv_app_profiles.
        v35 → v36: IV multiprobe (Module 4): analyses_multiprobe + probe_strategy
                   on input_validation_config.
        v36 → v37: IV planner (Module 5): max_requests_per_param budget override
                   on input_validation_config.
        v37 → v38: IV surface completeness (Module 9): include_auth_artifacts
                   on input_validation_config (default 0 = skip session/auth).
        v38 → v39: Passive Source Intelligence tables: source_documents,
                   source_occurrences, passive_detections, passive_scan_config
                   (seeded with design-contract defaults).
        v39 → v40: source_documents.parent_document_id + logical_source_name
                   for source-map virtual documents (Phase 10).
        v40 → v41: passive_scan_config.max_scan_time_ms (soft scan budget).
        v41 → v42: Cross-flow reflection: value_index, cross_flow_reflections,
                   parameters.cross_flow_reflected / _count / _sink_endpoints.
        v42 → v43: Error Intelligence: error_clusters, error_observations,
                   error_intel_config (intelligence only; no Findings).
        v43 → v44: error_observations unique index on flow_id (non-null) so
                   concurrent stores cannot double-count the same flow.
        v44 → v45: repeater_tabs table — persistent Repeater workspace archive
                   (tab metadata only; drafts re-materialize from parent flow).
        v45 → v46: intruder_sessions + intruder_results — Intruder Phase 1 engine.
        v46 → v47: intruder_pools — Intruder Phase 3 extracted value pools.
        v47 → v48: intruder_results.finding_id — Phase 5 optional findings promote.
        v48 → v49: AI Layer Phase A — ai_sessions, ai_audit_events, ai_project_prefs.
        v49 → v50: AI Layer Phase B — ai_app_notes, ai_app_note_revisions.
        v50 → v51: AI Layer Phase B — ai_suggestions, ai_execution_plans,
                   ai_observations, ai_task_nodes.
    """
    if not db_path.exists():
        return

    with sqlite3.connect(str(db_path)) as conn:
        version_row = conn.execute("SELECT version FROM schema_version").fetchone()
        if version_row is None:
            # Uninitialised DB — init_project_db will handle full setup.
            return

        current = version_row[0]
        if current >= SCHEMA_VERSION:
            return

        if current < 7:
            # Detect existing columns — ALTER TABLE ADD COLUMN fails if the
            # column already exists, so we guard with pragma introspection.
            existing = {
                row[1]
                for row in conn.execute("PRAGMA table_info(flows)").fetchall()
            }
            if "source" not in existing:
                conn.execute(
                    "ALTER TABLE flows ADD COLUMN source TEXT NOT NULL"
                    " DEFAULT 'proxy_capture'"
                )
            if "original_flow_id" not in existing:
                conn.execute(
                    "ALTER TABLE flows ADD COLUMN original_flow_id TEXT"
                )
            if "replay_error" not in existing:
                conn.execute(
                    "ALTER TABLE flows ADD COLUMN replay_error TEXT"
                )
            conn.execute("UPDATE schema_version SET version = 7")
            conn.commit()

        if current < 8:
            existing = {
                row[1]
                for row in conn.execute("PRAGMA table_info(flows)").fetchall()
            }
            if "replay_reason" not in existing:
                conn.execute(
                    "ALTER TABLE flows ADD COLUMN replay_reason TEXT"
                )
            conn.execute("UPDATE schema_version SET version = 8")
            conn.commit()

        if current < 9:
            # Create replay_diffs table if not present.
            # CREATE TABLE IF NOT EXISTS is safe — no-op on already-migrated DBs.
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS replay_diffs (
                    replay_flow_id   TEXT     PRIMARY KEY REFERENCES flows(id),
                    original_flow_id TEXT     NOT NULL,
                    verdict          TEXT     NOT NULL,
                    status_changed   INTEGER  NOT NULL DEFAULT 0,
                    status_diff      TEXT,
                    length_diff      INTEGER  NOT NULL DEFAULT 0
                )
                """
            )
            conn.execute("UPDATE schema_version SET version = 9")
            conn.commit()

        if current < 10:
            # Add auth_config and auth_test_results tables.
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS auth_config (
                    type   TEXT NOT NULL,
                    name   TEXT NOT NULL,
                    PRIMARY KEY (type, name)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS auth_test_results (
                    replay_flow_id   TEXT PRIMARY KEY REFERENCES flows(id),
                    original_flow_id TEXT NOT NULL,
                    verdict          TEXT NOT NULL
                )
                """
            )
            conn.execute("UPDATE schema_version SET version = 10")
            conn.commit()

        if current < 11:
            # Add endpoint_annotations table for safety tagging.
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS endpoint_annotations (
                    endpoint_id TEXT NOT NULL REFERENCES endpoints(id),
                    tag         TEXT NOT NULL,
                    created_at  TEXT NOT NULL,
                    PRIMARY KEY (endpoint_id, tag)
                )
                """
            )
            conn.execute("UPDATE schema_version SET version = 11")
            conn.commit()

        if current < 12:
            # Add scheduler_jobs table and index for the replay scheduler layer.
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS scheduler_jobs (
                    job_id             TEXT    PRIMARY KEY,
                    endpoint_id        TEXT,
                    flow_id            TEXT,
                    job_type           TEXT    NOT NULL,
                    priority           INTEGER NOT NULL DEFAULT 10,
                    status             TEXT    NOT NULL DEFAULT 'pending',
                    created_at         TEXT    NOT NULL,
                    started_at         TEXT,
                    finished_at        TEXT,
                    failure_reason     TEXT,
                    replayed_flow_id   TEXT,
                    verdict            TEXT
                )
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_scheduler_jobs_status_priority
                    ON scheduler_jobs (status, priority DESC, created_at ASC)
                """
            )
            conn.execute("UPDATE schema_version SET version = 12")
            conn.commit()

        if current < 13:
            # Add scheduled_at column to scheduler_jobs and create scheduler_config.
            conn.execute(
                "ALTER TABLE scheduler_jobs ADD COLUMN scheduled_at TEXT"
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS scheduler_config (
                    min_delay      REAL    NOT NULL DEFAULT 2.0,
                    max_delay      REAL    NOT NULL DEFAULT 6.0,
                    max_queue_size INTEGER NOT NULL DEFAULT 200
                )
                """
            )
            conn.execute("UPDATE schema_version SET version = 13")
            conn.commit()

        if current < 15:
            # Add request_mutations table — static header injections applied
            # to every outgoing request by the proxy addon.
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS request_mutations (
                    id      TEXT    PRIMARY KEY,
                    type    TEXT    NOT NULL,
                    key     TEXT    NOT NULL,
                    value   TEXT    NOT NULL,
                    enabled INTEGER NOT NULL DEFAULT 1
                )
                """
            )
            conn.execute("UPDATE schema_version SET version = 15")
            conn.commit()

        if current < 16:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS attack_config (
                    key   TEXT PRIMARY KEY,
                    value TEXT NOT NULL DEFAULT ''
                )
                """
            )
            conn.execute("UPDATE schema_version SET version = 16")
            conn.commit()

        if current < 17:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS attack_host_exclusions (
                    attack     TEXT NOT NULL,
                    host       TEXT NOT NULL,
                    path       TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    PRIMARY KEY (attack, host, path)
                )
                """
            )
            conn.execute("UPDATE schema_version SET version = 17")
            conn.commit()

        if current < 18:
            # Rebuild attack_host_exclusions to add the path column and
            # change PRIMARY KEY from (attack, host) to (attack, host, path).
            # SQLite does not support ALTER TABLE … ADD COLUMN when it would
            # change a PRIMARY KEY, so we recreate the table.
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS attack_host_exclusions_new (
                    attack     TEXT NOT NULL,
                    host       TEXT NOT NULL,
                    path       TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    PRIMARY KEY (attack, host, path)
                )
                """
            )
            conn.execute(
                """
                INSERT OR IGNORE INTO attack_host_exclusions_new
                    (attack, host, path, created_at)
                SELECT attack, host, '', created_at
                FROM attack_host_exclusions
                """
            )
            conn.execute("DROP TABLE attack_host_exclusions")
            conn.execute(
                "ALTER TABLE attack_host_exclusions_new"
                " RENAME TO attack_host_exclusions"
            )
            conn.execute("UPDATE schema_version SET version = 18")
            conn.commit()

        if current < 19:
            # Add role_auth and role_session_tokens tables for the
            # role-based session management system.
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS role_auth (
                    role_id            TEXT PRIMARY KEY REFERENCES roles(id),
                    login_flow_id      TEXT,
                    checkpoint_flow_id TEXT
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS role_session_tokens (
                    id         TEXT    PRIMARY KEY,
                    role_id    TEXT    NOT NULL REFERENCES roles(id),
                    token      TEXT    NOT NULL,
                    created_at TEXT    NOT NULL,
                    active     INTEGER NOT NULL DEFAULT 0
                )
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_role_session_tokens_role
                    ON role_session_tokens (role_id)
                """
            )
            conn.execute("UPDATE schema_version SET version = 19")
            conn.commit()

        if current < 20:
            # Add meta JSON column to scheduler_jobs for BAC attack metadata.
            existing_sj = {
                row[1]
                for row in conn.execute(
                    "PRAGMA table_info(scheduler_jobs)"
                ).fetchall()
            }
            if "meta" not in existing_sj:
                conn.execute(
                    "ALTER TABLE scheduler_jobs ADD COLUMN meta TEXT"
                )
            # Add bac_results table for BAC attack verdicts.
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS bac_results (
                    replay_flow_id   TEXT PRIMARY KEY REFERENCES flows(id),
                    original_flow_id TEXT NOT NULL,
                    attack_type      TEXT NOT NULL,
                    variant          TEXT NOT NULL,
                    attacker_role_id TEXT NOT NULL,
                    target_role_id   TEXT NOT NULL,
                    module_id        TEXT NOT NULL,
                    verdict          TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_bac_results_verdict
                    ON bac_results (verdict, attack_type)
                """
            )
            conn.execute("UPDATE schema_version SET version = 20")
            conn.commit()

        if current < 21:
            # Add auth_flow_config, role_auth_state, session_health_config,
            # session_health_control_flows, session_suspicion_state tables
            # for the new auth-config model and Session Health Engine.
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS auth_flow_config (
                    id             TEXT    PRIMARY KEY,
                    role_id        TEXT    NOT NULL REFERENCES roles(id),
                    flow_id        TEXT    NOT NULL,
                    extractor_code TEXT,
                    sort_order     INTEGER NOT NULL DEFAULT 0,
                    created_at     TEXT    NOT NULL,
                    UNIQUE (role_id, flow_id)
                )
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_auth_flow_config_role
                    ON auth_flow_config (role_id, sort_order)
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS role_auth_state (
                    role_id      TEXT NOT NULL REFERENCES roles(id),
                    key          TEXT NOT NULL,
                    value        TEXT NOT NULL,
                    collected_at TEXT NOT NULL,
                    PRIMARY KEY (role_id, key)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS session_health_config (
                    role_id                      TEXT PRIMARY KEY REFERENCES roles(id),
                    ttl_seconds                  INTEGER NOT NULL DEFAULT 1200,
                    refresh_before_seconds       INTEGER NOT NULL DEFAULT 120,
                    expiry_body_signals          TEXT    NOT NULL DEFAULT '[]',
                    expiry_header_signals        TEXT    NOT NULL DEFAULT '{}',
                    expiry_status_codes          TEXT    NOT NULL DEFAULT '[]',
                    validation_endpoint_url      TEXT,
                    validation_expected_status   INTEGER NOT NULL DEFAULT 200,
                    validation_body_contains     TEXT    NOT NULL DEFAULT '[]',
                    validation_body_not_contains TEXT    NOT NULL DEFAULT '[]'
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS session_health_control_flows (
                    role_id  TEXT NOT NULL REFERENCES roles(id),
                    flow_id  TEXT NOT NULL,
                    PRIMARY KEY (role_id, flow_id)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS session_suspicion_state (
                    role_id           TEXT PRIMARY KEY REFERENCES roles(id),
                    suspicion_count   INTEGER NOT NULL DEFAULT 0,
                    last_checked_at   TEXT
                )
                """
            )
            conn.execute("UPDATE schema_version SET version = 21")
            conn.commit()

        if current < 22:
            # Add matched_section, matched_group, matched_rules to bac_results
            # for rich BAC decision explainability.
            existing_br = {
                row[1]
                for row in conn.execute("PRAGMA table_info(bac_results)").fetchall()
            }
            if "matched_section" not in existing_br:
                conn.execute(
                    "ALTER TABLE bac_results ADD COLUMN matched_section TEXT"
                )
            if "matched_group" not in existing_br:
                conn.execute(
                    "ALTER TABLE bac_results ADD COLUMN matched_group TEXT"
                )
            if "matched_rules" not in existing_br:
                conn.execute(
                    "ALTER TABLE bac_results ADD COLUMN matched_rules TEXT"
                )
            conn.execute("UPDATE schema_version SET version = 22")
            conn.commit()

        if current < 23:
            # Add endpoint_policy and policy_rules tables for the Endpoint
            # Policy system — centralised priority, exclusion, and metadata.
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS endpoint_policy (
                    endpoint_id     TEXT PRIMARY KEY REFERENCES endpoints(id),
                    auto_priority   TEXT    NOT NULL DEFAULT 'NORMAL',
                    auto_score      INTEGER NOT NULL DEFAULT 0,
                    auto_breakdown  TEXT    NOT NULL DEFAULT '{}',
                    manual_priority TEXT,
                    excluded        INTEGER NOT NULL DEFAULT 0,
                    notes           TEXT    NOT NULL DEFAULT '',
                    tags            TEXT    NOT NULL DEFAULT '[]',
                    updated_at      TEXT    NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS policy_rules (
                    id          TEXT    PRIMARY KEY,
                    project_id  TEXT    NOT NULL,
                    pattern     TEXT    NOT NULL,
                    priority    TEXT,
                    excluded    INTEGER NOT NULL DEFAULT 0,
                    created_at  TEXT    NOT NULL,
                    UNIQUE (project_id, pattern)
                )
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_policy_rules_project
                    ON policy_rules (project_id)
                """
            )
            conn.execute("UPDATE schema_version SET version = 23")
            conn.commit()

        if current < 24:
            # Add dangerous and logout columns to endpoint_policy.
            existing_ep = {
                row[1]
                for row in conn.execute(
                    "PRAGMA table_info(endpoint_policy)"
                ).fetchall()
            }
            if "dangerous" not in existing_ep:
                conn.execute(
                    "ALTER TABLE endpoint_policy"
                    " ADD COLUMN dangerous INTEGER NOT NULL DEFAULT 0"
                )
            if "logout" not in existing_ep:
                conn.execute(
                    "ALTER TABLE endpoint_policy"
                    " ADD COLUMN logout INTEGER NOT NULL DEFAULT 0"
                )
            # Migrate any existing endpoint_annotations rows into endpoint_policy.
            # For each annotated endpoint that has no policy row yet, insert a
            # default row first, then apply the boolean flags.
            conn.execute(
                """
                INSERT OR IGNORE INTO endpoint_policy
                    (endpoint_id, auto_priority, auto_score, auto_breakdown,
                     manual_priority, excluded, dangerous, logout,
                     notes, tags, updated_at)
                SELECT DISTINCT ea.endpoint_id,
                    'NORMAL', 0, '{}', NULL, 0, 0, 0, '', '[]', datetime('now')
                FROM endpoint_annotations ea
                """
            )
            conn.execute(
                """
                UPDATE endpoint_policy
                SET logout = 1
                WHERE endpoint_id IN (
                    SELECT endpoint_id FROM endpoint_annotations WHERE tag = 'logout'
                )
                """
            )
            conn.execute(
                """
                UPDATE endpoint_policy
                SET dangerous = 1
                WHERE endpoint_id IN (
                    SELECT endpoint_id FROM endpoint_annotations WHERE tag = 'dangerous'
                )
                """
            )
            conn.execute("UPDATE schema_version SET version = 24")
            conn.commit()

        if current < 26:
            # Add flow_id column to IV cache tables so each analysis can be
            # traced back to the base flow that was replayed for it.
            existing_ipc = {
                row[1]
                for row in conn.execute(
                    "PRAGMA table_info(iv_param_cache)"
                ).fetchall()
            }
            if "flow_id" not in existing_ipc:
                conn.execute(
                    "ALTER TABLE iv_param_cache ADD COLUMN flow_id TEXT"
                )
            existing_irc = {
                row[1]
                for row in conn.execute(
                    "PRAGMA table_info(iv_reflection_cache)"
                ).fetchall()
            }
            if "flow_id" not in existing_irc:
                conn.execute(
                    "ALTER TABLE iv_reflection_cache ADD COLUMN flow_id TEXT"
                )
            conn.execute("UPDATE schema_version SET version = 26")
            conn.commit()

        if current < 27:
            # Add flow_meta JSON column to flows for universal replay metadata.
            # Every replay flow (IV, BAC, future modules) stores structured
            # metadata describing why it was generated and what was probed.
            existing_flows = {
                row[1]
                for row in conn.execute("PRAGMA table_info(flows)").fetchall()
            }
            if "flow_meta" not in existing_flows:
                conn.execute(
                    "ALTER TABLE flows ADD COLUMN flow_meta TEXT NOT NULL DEFAULT '{}'"
                )

            # Add iv_probe_results table for per-HTTP-request IV evidence.
            # Each probe sent during input validation gets one row here plus
            # one replay flow in the flows table.
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS iv_probe_results (
                    id           TEXT    PRIMARY KEY,
                    param_uuid   TEXT    NOT NULL,
                    endpoint_id  TEXT,
                    host         TEXT    NOT NULL,
                    location     TEXT    NOT NULL,
                    param_name   TEXT    NOT NULL,
                    analysis     TEXT    NOT NULL,
                    payload      TEXT,
                    payload_class TEXT   NOT NULL DEFAULT 'unknown',
                    payload_index INTEGER NOT NULL DEFAULT 0,
                    flow_id      TEXT,
                    status_code  INTEGER,
                    content_type TEXT    NOT NULL DEFAULT '',
                    body_length  INTEGER NOT NULL DEFAULT 0,
                    error        TEXT,
                    status       TEXT    NOT NULL DEFAULT 'pending',
                    created_at   TEXT    NOT NULL,
                    completed_at TEXT,
                    UNIQUE (param_uuid, analysis, payload_class, payload_index)
                )
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_iv_probe_results_param
                    ON iv_probe_results (param_uuid, analysis)
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_iv_probe_results_flow
                    ON iv_probe_results (flow_id)
                """
            )
            conn.execute("UPDATE schema_version SET version = 27")
            conn.commit()

        if current < 28:
            # Recreate iv_probe_results with slimmed schema:
            #   - rename payload_class → payload_type
            #   - remove status_code, content_type, body_length, error
            #     (those are in the flows table and dereferenced via flow_id)
            # Since iv_probe_results was new in v27 and may have no real data yet
            # (it was brand new), we drop and recreate it.
            conn.execute("DROP TABLE IF EXISTS iv_probe_results")
            conn.execute(
                """
                CREATE TABLE iv_probe_results (
                    id           TEXT    PRIMARY KEY,
                    param_uuid   TEXT    NOT NULL,
                    endpoint_id  TEXT,
                    host         TEXT    NOT NULL,
                    location     TEXT    NOT NULL,
                    param_name   TEXT    NOT NULL,
                    analysis     TEXT    NOT NULL,
                    payload      TEXT,
                    payload_type TEXT    NOT NULL DEFAULT 'unknown',
                    payload_index INTEGER NOT NULL DEFAULT 0,
                    flow_id      TEXT,
                    status       TEXT    NOT NULL DEFAULT 'pending',
                    created_at   TEXT    NOT NULL,
                    completed_at TEXT,
                    UNIQUE (param_uuid, analysis, payload_type, payload_index)
                )
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_iv_probe_results_param
                    ON iv_probe_results (param_uuid, analysis)
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_iv_probe_results_flow
                    ON iv_probe_results (flow_id)
                """
            )
            conn.execute("UPDATE schema_version SET version = 28")
            conn.commit()

        if current < 29:
            # Add role_auth_provider, manual_session_config, and scheduler_state
            # tables for the Authentication Provider architecture.
            existing_tables = {
                row[0]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            }
            if "role_auth_provider" not in existing_tables:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS role_auth_provider (
                        role_id    TEXT PRIMARY KEY REFERENCES roles(id),
                        provider   TEXT NOT NULL DEFAULT 'auto',
                        updated_at TEXT NOT NULL
                    )
                    """
                )
            if "manual_session_config" not in existing_tables:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS manual_session_config (
                        role_id      TEXT PRIMARY KEY REFERENCES roles(id),
                        headers_json TEXT NOT NULL DEFAULT '{}',
                        cookies_json TEXT NOT NULL DEFAULT '{}',
                        expires_at   TEXT,
                        ttl_seconds  INTEGER,
                        created_at   TEXT NOT NULL,
                        updated_at   TEXT NOT NULL
                    )
                    """
                )
            if "scheduler_state" not in existing_tables:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS scheduler_state (
                        id         TEXT PRIMARY KEY DEFAULT 'default',
                        state      TEXT NOT NULL DEFAULT 'running',
                        reason     TEXT,
                        updated_at TEXT NOT NULL
                    )
                    """
                )
            conn.execute("UPDATE schema_version SET version = 29")
            conn.commit()

        if current < 30:
            # Add qualification columns to endpoint_policy:
            #   qualified            — 1 when endpoint has a 2xx proxy_capture flow
            #   qualification_reason — human-readable reason string
            #   baseline_flow_id     — pre-computed best baseline flow UUID
            #   baseline_status      — HTTP status of the baseline flow
            # Then backfill qualification state for all existing endpoints
            # that already have qualifying flows.
            existing_ep = {
                row[1]
                for row in conn.execute(
                    "PRAGMA table_info(endpoint_policy)"
                ).fetchall()
            }
            if "qualified" not in existing_ep:
                conn.execute(
                    "ALTER TABLE endpoint_policy"
                    " ADD COLUMN qualified INTEGER NOT NULL DEFAULT 0"
                )
            if "qualification_reason" not in existing_ep:
                conn.execute(
                    "ALTER TABLE endpoint_policy"
                    " ADD COLUMN qualification_reason TEXT NOT NULL DEFAULT 'no_flows'"
                )
            if "baseline_flow_id" not in existing_ep:
                conn.execute(
                    "ALTER TABLE endpoint_policy ADD COLUMN baseline_flow_id TEXT"
                )
            if "baseline_status" not in existing_ep:
                conn.execute(
                    "ALTER TABLE endpoint_policy ADD COLUMN baseline_status INTEGER"
                )
            # Backfill: find the most recent 2xx proxy_capture flow per endpoint
            # and mark those endpoints as qualified.  Only endpoints that are
            # neither logout nor dangerous are eligible.
            conn.execute(
                """
                UPDATE endpoint_policy
                SET qualified = 1,
                    qualification_reason = 'flow_2xx',
                    baseline_flow_id = (
                        SELECT f.id
                        FROM flows f
                        WHERE f.endpoint_id = endpoint_policy.endpoint_id
                          AND f.source = 'proxy_capture'
                          AND f.status_code BETWEEN 200 AND 299
                        ORDER BY f.captured_at DESC
                        LIMIT 1
                    ),
                    baseline_status = (
                        SELECT f.status_code
                        FROM flows f
                        WHERE f.endpoint_id = endpoint_policy.endpoint_id
                          AND f.source = 'proxy_capture'
                          AND f.status_code BETWEEN 200 AND 299
                        ORDER BY f.captured_at DESC
                        LIMIT 1
                    )
                WHERE logout = 0
                  AND dangerous = 0
                  AND EXISTS (
                      SELECT 1
                      FROM flows f
                      WHERE f.endpoint_id = endpoint_policy.endpoint_id
                        AND f.source = 'proxy_capture'
                        AND f.status_code BETWEEN 200 AND 299
                  )
                """
            )
            conn.execute("UPDATE schema_version SET version = 30")
            conn.commit()

        if current < 31:
            # Add Findings subsystem tables introduced in v31.
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS findings (
                    id           TEXT    PRIMARY KEY,
                    project_id   TEXT    NOT NULL,
                    attack_type  TEXT    NOT NULL,
                    verdict      TEXT    NOT NULL,
                    endpoint_id  TEXT,
                    status       TEXT    NOT NULL DEFAULT 'TRIAGING',
                    duplicate_of TEXT,
                    created_at   TEXT    NOT NULL,
                    updated_at   TEXT    NOT NULL,
                    title        TEXT    NOT NULL DEFAULT '',
                    notes        TEXT    NOT NULL DEFAULT ''
                );
                CREATE INDEX IF NOT EXISTS idx_findings_project
                    ON findings (project_id, status, created_at DESC);

                CREATE TABLE IF NOT EXISTS finding_evidence (
                    id            TEXT    PRIMARY KEY,
                    finding_id    TEXT    NOT NULL REFERENCES findings(id),
                    evidence_type TEXT    NOT NULL,
                    reference_id  TEXT,
                    label         TEXT    NOT NULL DEFAULT '',
                    data          TEXT    NOT NULL DEFAULT '{}',
                    created_at    TEXT    NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_finding_evidence_finding
                    ON finding_evidence (finding_id, created_at ASC);

                CREATE TABLE IF NOT EXISTS finding_timeline (
                    id         TEXT    PRIMARY KEY,
                    finding_id TEXT    NOT NULL REFERENCES findings(id),
                    event      TEXT    NOT NULL,
                    actor      TEXT    NOT NULL DEFAULT 'system',
                    created_at TEXT    NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_finding_timeline_finding
                    ON finding_timeline (finding_id, created_at ASC);

                CREATE TABLE IF NOT EXISTS finding_groups (
                    id         TEXT    PRIMARY KEY,
                    project_id TEXT    NOT NULL,
                    name       TEXT    NOT NULL,
                    created_at TEXT    NOT NULL,
                    UNIQUE (project_id, name)
                );
                CREATE INDEX IF NOT EXISTS idx_finding_groups_project
                    ON finding_groups (project_id);

                CREATE TABLE IF NOT EXISTS finding_group_members (
                    group_id   TEXT    NOT NULL REFERENCES finding_groups(id) ON DELETE CASCADE,
                    finding_id TEXT    NOT NULL REFERENCES findings(id),
                    added_at   TEXT    NOT NULL,
                    PRIMARY KEY (group_id, finding_id)
                );
                CREATE INDEX IF NOT EXISTS idx_finding_group_members_finding
                    ON finding_group_members (finding_id);
            """)
            conn.execute("UPDATE schema_version SET version = 31")
            conn.commit()

        if current < 32:
            # Add mutation_family and mutation columns to bac_results for richer
            # reporting. Add unauth_results table for unauth attack verdicts.
            existing_br = {
                row[1]
                for row in conn.execute("PRAGMA table_info(bac_results)").fetchall()
            }
            if "mutation_family" not in existing_br:
                conn.execute(
                    "ALTER TABLE bac_results ADD COLUMN mutation_family TEXT"
                )
            if "mutation" not in existing_br:
                conn.execute(
                    "ALTER TABLE bac_results ADD COLUMN mutation TEXT"
                )
            # Create unauth_results table.
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS unauth_results (
                    replay_flow_id          TEXT PRIMARY KEY REFERENCES flows(id),
                    original_flow_id        TEXT NOT NULL,
                    endpoint_id             TEXT,
                    auth_mutation_family    TEXT NOT NULL,
                    auth_mutation           TEXT NOT NULL,
                    request_mutation_family TEXT,
                    request_mutation        TEXT,
                    verdict                 TEXT NOT NULL,
                    matched_section         TEXT,
                    matched_group           TEXT,
                    matched_rules           TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_unauth_results_verdict
                    ON unauth_results (verdict, auth_mutation_family);
            """)
            conn.execute("UPDATE schema_version SET version = 32")
            conn.commit()

        if current < 33:
            # Add proxy_config table for configurable upstream-proxy mode.
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS proxy_config (
                    id           TEXT PRIMARY KEY DEFAULT 'default',
                    upstream_url TEXT
                )
                """
            )
            conn.execute("UPDATE schema_version SET version = 33")
            conn.commit()

        if current < 34:
            # Finding relationships: PRIMARY / LINKED clustering.
            # relation_type + parent_finding_id + cluster_key, with a partial
            # unique index guaranteeing one PRIMARY per cluster_key.
            existing_findings = {
                row[1]
                for row in conn.execute("PRAGMA table_info(findings)").fetchall()
            }
            if existing_findings:
                if "relation_type" not in existing_findings:
                    conn.execute(
                        "ALTER TABLE findings ADD COLUMN relation_type "
                        "TEXT NOT NULL DEFAULT 'PRIMARY'"
                    )
                if "parent_finding_id" not in existing_findings:
                    conn.execute(
                        "ALTER TABLE findings ADD COLUMN parent_finding_id TEXT"
                    )
                if "cluster_key" not in existing_findings:
                    conn.execute(
                        "ALTER TABLE findings ADD COLUMN cluster_key TEXT"
                    )

                # Backfill cluster_key and flatten multi-finding clusters:
                # oldest finding becomes PRIMARY; later ones become LINKED.
                rows = conn.execute(
                    """
                    SELECT id, attack_type, endpoint_id, created_at
                    FROM findings
                    ORDER BY created_at ASC, id ASC
                    """
                ).fetchall()
                # cluster_key → primary finding id
                primary_by_cluster: dict = {}
                for fid, attack_type, endpoint_id, _created in rows:
                    if not endpoint_id:
                        # No endpoint → standalone PRIMARY, no cluster key.
                        continue
                    at = (attack_type or "").lower()
                    if at == "unauth":
                        ck = f"UNAUTH:{endpoint_id}"
                    elif at == "auth_test":
                        ck = f"AUTH_TEST:{endpoint_id}"
                    elif at == "bac":
                        # Pre-relationship BAC findings lack role pair on the
                        # row; keep them independent PRIMARY with unique keys.
                        ck = f"BAC:{endpoint_id}:{fid}"
                    else:
                        ck = f"{(attack_type or 'UNKNOWN').upper()}:{endpoint_id}"

                    if ck not in primary_by_cluster:
                        primary_by_cluster[ck] = fid
                        conn.execute(
                            """
                            UPDATE findings
                            SET relation_type = 'PRIMARY',
                                parent_finding_id = NULL,
                                cluster_key = ?
                            WHERE id = ?
                            """,
                            (ck, fid),
                        )
                    else:
                        parent_id = primary_by_cluster[ck]
                        conn.execute(
                            """
                            UPDATE findings
                            SET relation_type = 'LINKED',
                                parent_finding_id = ?,
                                cluster_key = ?
                            WHERE id = ?
                            """,
                            (parent_id, ck, fid),
                        )

            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_findings_parent
                    ON findings (parent_finding_id)
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_findings_relation
                    ON findings (project_id, relation_type)
                """
            )
            conn.execute(
                """
                CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_primary_cluster
                    ON findings (cluster_key)
                    WHERE relation_type = 'PRIMARY' AND cluster_key IS NOT NULL
                """
            )
            conn.execute("UPDATE schema_version SET version = 34")
            conn.commit()

        if current < 35:
            # IV multi-level intelligence profiles (Module 2).
            # Separate from iv_param_cache so phase resume and consumer
            # profiles do not share the same row type.
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS iv_param_profiles (
                    id              TEXT    PRIMARY KEY,
                    param_uuid      TEXT    NOT NULL,
                    host            TEXT    NOT NULL,
                    location        TEXT    NOT NULL,
                    param_name      TEXT    NOT NULL,
                    schema_version  INTEGER NOT NULL DEFAULT 1,
                    profile_version INTEGER NOT NULL DEFAULT 1,
                    profile         TEXT    NOT NULL DEFAULT '{}',
                    created_at      TEXT    NOT NULL,
                    updated_at      TEXT    NOT NULL,
                    UNIQUE (param_uuid)
                )
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_iv_param_profiles_host
                    ON iv_param_profiles (host, location, param_name)
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS iv_endpoint_profiles (
                    id              TEXT    PRIMARY KEY,
                    endpoint_id     TEXT    NOT NULL,
                    host            TEXT    NOT NULL DEFAULT '',
                    schema_version  INTEGER NOT NULL DEFAULT 1,
                    profile_version INTEGER NOT NULL DEFAULT 1,
                    profile         TEXT    NOT NULL DEFAULT '{}',
                    created_at      TEXT    NOT NULL,
                    updated_at      TEXT    NOT NULL,
                    UNIQUE (endpoint_id)
                )
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_iv_endpoint_profiles_host
                    ON iv_endpoint_profiles (host)
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS iv_app_profiles (
                    id              TEXT    PRIMARY KEY,
                    host            TEXT    NOT NULL,
                    schema_version  INTEGER NOT NULL DEFAULT 1,
                    profile_version INTEGER NOT NULL DEFAULT 1,
                    profile         TEXT    NOT NULL DEFAULT '{}',
                    created_at      TEXT    NOT NULL,
                    updated_at      TEXT    NOT NULL,
                    UNIQUE (host)
                )
                """
            )
            conn.execute("UPDATE schema_version SET version = 35")
            conn.commit()

        if current < 36:
            # Module 4: multiprobe phase toggle + probe volume strategy.
            existing_iv = {
                row[1]
                for row in conn.execute(
                    "PRAGMA table_info(input_validation_config)"
                ).fetchall()
            }
            if existing_iv:
                if "analyses_multiprobe" not in existing_iv:
                    conn.execute(
                        "ALTER TABLE input_validation_config "
                        "ADD COLUMN analyses_multiprobe INTEGER NOT NULL DEFAULT 1"
                    )
                if "probe_strategy" not in existing_iv:
                    conn.execute(
                        "ALTER TABLE input_validation_config "
                        "ADD COLUMN probe_strategy TEXT NOT NULL DEFAULT 'standard'"
                    )
            conn.execute("UPDATE schema_version SET version = 36")
            conn.commit()

        if current < 37:
            # Module 5: planner hard-cap override per parameter.
            existing_iv = {
                row[1]
                for row in conn.execute(
                    "PRAGMA table_info(input_validation_config)"
                ).fetchall()
            }
            if existing_iv and "max_requests_per_param" not in existing_iv:
                conn.execute(
                    "ALTER TABLE input_validation_config "
                    "ADD COLUMN max_requests_per_param INTEGER NOT NULL DEFAULT 0"
                )
            conn.execute("UPDATE schema_version SET version = 37")
            conn.commit()

        if current < 38:
            # Module 9: auth-artifact skip policy (opt-in probe).
            existing_iv = {
                row[1]
                for row in conn.execute(
                    "PRAGMA table_info(input_validation_config)"
                ).fetchall()
            }
            if existing_iv and "include_auth_artifacts" not in existing_iv:
                conn.execute(
                    "ALTER TABLE input_validation_config "
                    "ADD COLUMN include_auth_artifacts INTEGER NOT NULL DEFAULT 0"
                )
            conn.execute("UPDATE schema_version SET version = 38")
            conn.commit()

        if current < 39:
            # Passive Source Intelligence (Secret Exposure Engine).
            conn.executescript(_PASSIVE_SCHEMA_V39_DDL)
            conn.execute(
                "INSERT OR IGNORE INTO passive_scan_config (id) VALUES ('default')"
            )
            conn.execute("UPDATE schema_version SET version = 39")
            conn.commit()

        if current < 40:
            # Phase 10: parent_document_id for source-map virtual docs.
            existing_sd = {
                row[1]
                for row in conn.execute(
                    "PRAGMA table_info(source_documents)"
                ).fetchall()
            }
            if existing_sd and "parent_document_id" not in existing_sd:
                conn.execute(
                    "ALTER TABLE source_documents "
                    "ADD COLUMN parent_document_id TEXT"
                )
            if existing_sd and "logical_source_name" not in existing_sd:
                conn.execute(
                    "ALTER TABLE source_documents "
                    "ADD COLUMN logical_source_name TEXT"
                )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_source_documents_parent "
                "ON source_documents (parent_document_id)"
            )
            conn.execute("UPDATE schema_version SET version = 40")
            conn.commit()

        if current < 41:
            # Soft per-document scan budget for Passive Source Intelligence.
            existing_cfg = {
                row[1]
                for row in conn.execute(
                    "PRAGMA table_info(passive_scan_config)"
                ).fetchall()
            }
            if existing_cfg and "max_scan_time_ms" not in existing_cfg:
                conn.execute(
                    "ALTER TABLE passive_scan_config "
                    "ADD COLUMN max_scan_time_ms INTEGER NOT NULL DEFAULT 0"
                )
            conn.execute("UPDATE schema_version SET version = 41")
            conn.commit()

        if current < 42:
            # Cross-page / stored reflection value index + link table.
            conn.executescript(_CROSS_FLOW_SCHEMA_V42_DDL)
            existing_params = {
                row[1]
                for row in conn.execute("PRAGMA table_info(parameters)").fetchall()
            }
            if existing_params:
                cross_flow_cols = [
                    ("cross_flow_reflected", "INTEGER NOT NULL DEFAULT 0"),
                    ("cross_flow_reflection_count", "INTEGER NOT NULL DEFAULT 0"),
                    ("cross_flow_sink_endpoints", "TEXT NOT NULL DEFAULT '[]'"),
                ]
                for col_name, col_def in cross_flow_cols:
                    if col_name not in existing_params:
                        conn.execute(
                            f"ALTER TABLE parameters ADD COLUMN {col_name} {col_def}"
                        )
            conn.execute("UPDATE schema_version SET version = 42")
            conn.commit()

        if current < 43:
            # Error Intelligence — clusters, observations, config (no Findings).
            conn.executescript(_ERROR_INTEL_SCHEMA_V43_DDL)
            conn.execute(
                "INSERT OR IGNORE INTO error_intel_config (id) VALUES ('default')"
            )
            conn.execute("UPDATE schema_version SET version = 43")
            conn.commit()

        if current < 44:
            # One observation per non-null flow_id. Dedup any pre-existing
            # duplicates (keep newest by observed_at) before creating the
            # unique index so migration cannot fail on dirty data.
            existing_tables = {
                row[0]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            }
            if "error_observations" in existing_tables:
                # Keep the newest observation per flow_id; drop the rest.
                conn.execute(
                    """
                    DELETE FROM error_observations
                    WHERE flow_id IS NOT NULL
                      AND flow_id != ''
                      AND EXISTS (
                        SELECT 1 FROM error_observations o2
                        WHERE o2.flow_id = error_observations.flow_id
                          AND (
                            o2.observed_at > error_observations.observed_at
                            OR (
                              o2.observed_at = error_observations.observed_at
                              AND o2.id > error_observations.id
                            )
                          )
                      )
                    """
                )
                # Re-derive cluster observation_count after dedup.
                conn.execute(
                    """
                    UPDATE error_clusters
                    SET observation_count = (
                        SELECT COUNT(*) FROM error_observations o
                        WHERE o.error_id = error_clusters.id
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE UNIQUE INDEX IF NOT EXISTS
                        idx_error_observations_flow_unique
                    ON error_observations (flow_id)
                    WHERE flow_id IS NOT NULL AND flow_id != ''
                    """
                )
            conn.execute("UPDATE schema_version SET version = 44")
            conn.commit()

        if current < 45:
            # Persistent Repeater tab archive (metadata only; no draft body).
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS repeater_tabs (
                    id                  TEXT    PRIMARY KEY,
                    project_id          TEXT    NOT NULL,
                    title               TEXT    NOT NULL DEFAULT '',
                    parent_flow_id      TEXT    NOT NULL,
                    original_flow_id    TEXT    NOT NULL,
                    session_id          TEXT,
                    last_execution_id   TEXT,
                    sort_order          INTEGER NOT NULL DEFAULT 0,
                    created_at          TEXT    NOT NULL,
                    updated_at          TEXT    NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_repeater_tabs_project_sort
                    ON repeater_tabs (project_id, sort_order ASC, updated_at DESC)
                """
            )
            conn.execute("UPDATE schema_version SET version = 45")
            conn.commit()

        if current < 46:
            # Intruder Phase 1: sessions + attempt results.
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS intruder_sessions (
                    id               TEXT    PRIMARY KEY,
                    project_id       TEXT    NOT NULL,
                    name             TEXT    NOT NULL DEFAULT '',
                    status           TEXT    NOT NULL DEFAULT 'draft',
                    base_flow_id     TEXT,
                    endpoint_id      TEXT,
                    config_json      TEXT    NOT NULL DEFAULT '{}',
                    checkpoint_json  TEXT    NOT NULL DEFAULT '{}',
                    progress_json    TEXT    NOT NULL DEFAULT '{}',
                    job_id           TEXT,
                    control_flag     TEXT,
                    created_at       TEXT    NOT NULL,
                    updated_at       TEXT    NOT NULL,
                    started_at       TEXT,
                    finished_at      TEXT,
                    failure_reason   TEXT,
                    schema_version   INTEGER NOT NULL DEFAULT 1
                );
                CREATE INDEX IF NOT EXISTS idx_intruder_sessions_project
                    ON intruder_sessions (project_id, status, updated_at DESC);

                CREATE TABLE IF NOT EXISTS intruder_results (
                    id               TEXT    PRIMARY KEY,
                    session_id       TEXT    NOT NULL REFERENCES intruder_sessions(id) ON DELETE CASCADE,
                    attempt_index    INTEGER NOT NULL,
                    variables_json   TEXT    NOT NULL DEFAULT '{}',
                    status_code      INTEGER,
                    success          INTEGER NOT NULL DEFAULT 0,
                    failure_reason   TEXT,
                    duration_ms      REAL,
                    body_length      INTEGER,
                    word_count       INTEGER,
                    line_count       INTEGER,
                    body_hash        TEXT,
                    fingerprint_json TEXT    NOT NULL DEFAULT '{}',
                    metrics_json     TEXT    NOT NULL DEFAULT '{}',
                    interesting      INTEGER NOT NULL DEFAULT 0,
                    match_tags_json  TEXT    NOT NULL DEFAULT '[]',
                    grepped_json     TEXT    NOT NULL DEFAULT '{}',
                    flow_id          TEXT,
                    finding_id       TEXT,
                    created_at       TEXT    NOT NULL,
                    UNIQUE (session_id, attempt_index)
                );
                CREATE INDEX IF NOT EXISTS idx_intruder_results_session
                    ON intruder_results (session_id, attempt_index);
                CREATE INDEX IF NOT EXISTS idx_intruder_results_interesting
                    ON intruder_results (session_id, interesting) WHERE interesting = 1;
                CREATE INDEX IF NOT EXISTS idx_intruder_results_finding
                    ON intruder_results (finding_id) WHERE finding_id IS NOT NULL;
            """)
            conn.execute("UPDATE schema_version SET version = 46")
            conn.commit()

        if current < 47:
            # Intruder Phase 3: project-scoped extracted value pools.
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS intruder_pools (
                    id               TEXT    PRIMARY KEY,
                    project_id       TEXT    NOT NULL,
                    name             TEXT    NOT NULL,
                    session_id       TEXT,
                    values_json      TEXT    NOT NULL DEFAULT '[]',
                    source_rule      TEXT,
                    created_at       TEXT    NOT NULL,
                    updated_at       TEXT    NOT NULL,
                    UNIQUE (project_id, name)
                );
                CREATE INDEX IF NOT EXISTS idx_intruder_pools_project
                    ON intruder_pools (project_id, updated_at DESC);
            """)
            conn.execute("UPDATE schema_version SET version = 47")
            conn.commit()

        if current < 48:
            # Intruder Phase 5: optional findings promote lineage on results.
            try:
                cols = {
                    row[1]
                    for row in conn.execute(
                        "PRAGMA table_info(intruder_results)"
                    ).fetchall()
                }
            except sqlite3.OperationalError:
                cols = set()
            if cols and "finding_id" not in cols:
                conn.execute(
                    "ALTER TABLE intruder_results ADD COLUMN finding_id TEXT"
                )
            if cols:
                conn.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_intruder_results_finding
                        ON intruder_results (finding_id)
                        WHERE finding_id IS NOT NULL
                    """
                )
            conn.execute("UPDATE schema_version SET version = 48")
            conn.commit()

        if current < 49:
            # AI Layer Phase A: sessions, audit events, project prefs.
            conn.executescript(_AI_SCHEMA_V49_DDL)
            conn.execute("UPDATE schema_version SET version = 49")
            conn.commit()

        if current < 50:
            # AI Layer Phase B (PR3): structured app notes + revisions.
            conn.executescript(_AI_SCHEMA_V50_DDL)
            conn.execute("UPDATE schema_version SET version = 50")
            conn.commit()

        if current < 51:
            # AI Layer Phase B (PR4): immutable suggestions, plans, obs, PTT.
            conn.executescript(_AI_SCHEMA_V51_DDL)
            conn.execute("UPDATE schema_version SET version = 51")
            conn.commit()


def get_schema_version(db_path: Path) -> int:
    """
    Purpose: Read the stored schema version from an existing project database.
    Input:   db_path — Path to an existing .db file.
    Output:  Integer schema version; 0 if the table is empty.
    Side effects: None (read-only).
    """
    with sqlite3.connect(str(db_path)) as conn:
        row = conn.execute("SELECT version FROM schema_version").fetchone()
        return row[0] if row else 0
