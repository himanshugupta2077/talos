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


SCHEMA_VERSION = 20

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
    source                   TEXT    NOT NULL DEFAULT 'proxy_capture', -- proxy_capture | manual_replay | auto_replay
    original_flow_id         TEXT,                                      -- FK to flows.id; NULL for proxy_capture flows
    replay_error             TEXT,                                      -- NULL on success; error label on network/HTTP failure
    replay_reason            TEXT                                       -- NULL for proxy_capture; e.g. testing | bac_test | idor_test | validation
);

-- ------------------------------------------------------------------ --
-- endpoints: normalized, deduplicated request shapes                  --
-- ------------------------------------------------------------------ --
CREATE TABLE IF NOT EXISTS endpoints (
    id              TEXT    PRIMARY KEY,     -- UUID
    project_id      TEXT    NOT NULL,
    method          TEXT    NOT NULL,
    host            TEXT    NOT NULL,
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
-- ------------------------------------------------------------------ --
CREATE TABLE IF NOT EXISTS parameters (
    id              TEXT    PRIMARY KEY,     -- UUID
    endpoint_id     TEXT    NOT NULL REFERENCES endpoints(id),
    name            TEXT    NOT NULL,
    location        TEXT    NOT NULL,        -- query | body | header | cookie | path
    param_type      TEXT    NOT NULL DEFAULT 'unknown',  -- int|uuid|hash|enum|json|bool|string
    source          TEXT    NOT NULL DEFAULT 'unknown',  -- user-controlled | server-generated
    volatility      TEXT    NOT NULL DEFAULT 'unknown',  -- static | dynamic
    sensitivity     TEXT    NOT NULL DEFAULT 'unknown',  -- identifier | control | data
    example_values  TEXT    NOT NULL DEFAULT '[]',       -- JSON array (sampled)
    UNIQUE (endpoint_id, name, location)
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
-- client_allowed : what the UI exposes for this role/module pair.   --
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
-- job_type : replay_flow | replay_endpoint | auth_test               --
-- status   : pending | running | done | failed | skipped             --
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
-- out_of_scope_domains: domains that must never be captured           --
-- Out-of-scope check overrides the scope allow-list.                 --
-- Matching: host == domain OR host ends with '.<domain>'             --
-- ------------------------------------------------------------------ --
CREATE TABLE IF NOT EXISTS out_of_scope_domains (
    id         TEXT    PRIMARY KEY,   -- UUID
    project_id TEXT    NOT NULL,
    domain     TEXT    NOT NULL,
    created_at TEXT    NOT NULL,      -- UTC ISO-8601
    UNIQUE (project_id, domain)
);

CREATE INDEX IF NOT EXISTS idx_out_of_scope_project
    ON out_of_scope_domains (project_id);

-- ------------------------------------------------------------------ --
-- request_mutations: static header injections applied to every        --
-- outgoing request before it leaves the proxy.                        --
-- type: 'header' (only supported type)                               --
-- enabled: 1 = active, 0 = paused                                   --
-- ------------------------------------------------------------------ --
CREATE TABLE IF NOT EXISTS request_mutations (
    id      TEXT    PRIMARY KEY,   -- UUID
    type    TEXT    NOT NULL,      -- 'header'
    key     TEXT    NOT NULL,
    value   TEXT    NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1
);

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
-- verdict    : POSSIBLE_BAC | SECURE | UNKNOWN                        --
-- ------------------------------------------------------------------ --
CREATE TABLE IF NOT EXISTS bac_results (
    replay_flow_id   TEXT PRIMARY KEY REFERENCES flows(id),
    original_flow_id TEXT NOT NULL,
    attack_type      TEXT NOT NULL,
    variant          TEXT NOT NULL,
    attacker_role_id TEXT NOT NULL,
    target_role_id   TEXT NOT NULL,
    module_id        TEXT NOT NULL,
    verdict          TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_bac_results_verdict
    ON bac_results (verdict, attack_type);"""


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
