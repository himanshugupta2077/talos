"""
Module: talos.ui.db

Purpose:
    Thin read-only data access layer for the inspection UI.
    Reads registry.json for project metadata and SQLite for flow/endpoint data.
    Provides role-scoped flow views and endpoint exposure queries for BAC analysis.
    No imports from core talos modules — operates entirely on raw storage.

Dependencies: sqlite3, json, pathlib
Data flow:
    FastAPI routes → functions here → registry.json / SQLite → dicts returned to routes
Side effects: None (all operations are read-only).
"""

import json
import sqlite3
from pathlib import Path


# ------------------------------------------------------------------ #
# Registry                                                             #
# ------------------------------------------------------------------ #

def load_registry(projects_root: Path) -> dict[str, dict]:
    """
    Purpose: Load all project records from registry.json.
    Input:   projects_root — Path to the projects directory.
    Output:  Dict mapping project_id → project dict. Empty dict if file absent.
    Side effects: None.
    """
    registry_path = projects_root / "registry.json"
    if not registry_path.exists():
        return {}
    with registry_path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def get_project_record(projects_root: Path, project_id: str) -> dict | None:
    """
    Purpose: Load a single project record from registry.json.
    Input:   projects_root — Path to projects directory; project_id — target id.
    Output:  Project dict, or None if not found.
    Side effects: None.
    """
    registry = load_registry(projects_root)
    return registry.get(project_id)


# ------------------------------------------------------------------ #
# Archive                                                              #
# ------------------------------------------------------------------ #

def get_archive_size_bytes(archive_dir: Path) -> int:
    """
    Purpose: Sum file sizes in the archive directory to compute total stored bytes.
    Input:   archive_dir — Path to <project>/archive/.
    Output:  Total bytes as int; 0 if directory does not exist.
    Side effects: None.
    """
    if not archive_dir.is_dir():
        return 0
    return sum(f.stat().st_size for f in archive_dir.rglob("*") if f.is_file())


# ------------------------------------------------------------------ #
# DB helpers                                                           #
# ------------------------------------------------------------------ #

def _connect(db_path: Path) -> sqlite3.Connection:
    """
    Purpose: Open a read-only SQLite connection in WAL mode.
    Input:   db_path — Path to the project's talos.db.
    Output:  sqlite3.Connection with row_factory set to sqlite3.Row.
    Side effects: Opens file handle (caller must close via context manager).
    """
    # uri=True + ?mode=ro enforces read-only at the SQLite level.
    uri = f"file:{db_path}?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def _table_exists(conn: sqlite3.Connection, table: str) -> bool:
    """
    Purpose: Check whether a table exists in the connected database.
    Input:   conn — open connection; table — table name to check.
    Output:  True if the table exists.
    Side effects: None.
    """
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
    ).fetchone()
    return row is not None


# ------------------------------------------------------------------ #
# Flow queries                                                         #
# ------------------------------------------------------------------ #

def _build_flow_filters(
    source: str | None,
    method: str | None,
    host: str | None,
    status_code: int | None,
    role: str | None,
    module: str | None,
) -> tuple[str, list]:
    """
    Purpose: Build a SQL WHERE clause and params list for flow filter queries.
    Input:   Optional filter values; None values are ignored.
    Output:  Tuple of (where_clause_str, params_list).
             where_clause_str is empty string when no filters are active.
    Side effects: None.
    """
    conditions: list[str] = []
    params: list = []
    if source:
        conditions.append("f.source = ?")
        params.append(source)
    if method:
        conditions.append("f.method = ?")
        params.append(method)
    if host:
        conditions.append("f.host = ?")
        params.append(host)
    if status_code is not None:
        conditions.append("f.status_code = ?")
        params.append(status_code)
    if role:
        conditions.append("COALESCE(r.name, '\u2014') = ?")
        params.append(role)
    if module:
        conditions.append("COALESCE(m.name, '\u2014') = ?")
        params.append(module)
    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    return where, params


def get_flow_count(
    db_path: Path,
    source: str | None = None,
    method: str | None = None,
    host: str | None = None,
    status_code: int | None = None,
    role: str | None = None,
    module: str | None = None,
) -> int:
    """
    Purpose: Count flows in the project database, optionally filtered.
    Input:   db_path — Path to talos.db; optional filter params.
    Output:  Integer count; 0 if DB absent or table missing.
    Side effects: None.
    """
    if not db_path.exists():
        return 0
    with _connect(db_path) as conn:
        if not _table_exists(conn, "flows"):
            return 0
        where, params = _build_flow_filters(source, method, host, status_code, role, module)
        # Role/module filters require JOINs even for COUNT.
        joins = ""
        if role or module:
            joins = """
                LEFT JOIN roles r ON r.id = f.role_id
                LEFT JOIN modules m ON m.id = f.module_id
            """
        row = conn.execute(
            f"SELECT COUNT(*) FROM flows f {joins} {where}", params
        ).fetchone()
        return row[0] if row else 0


def list_flows(
    db_path: Path,
    offset: int,
    limit: int,
    source: str | None = None,
    method: str | None = None,
    host: str | None = None,
    status_code: int | None = None,
    role: str | None = None,
    module: str | None = None,
) -> list[dict]:
    """
    Purpose: Return a paginated slice of flows ordered by capture time descending.
    Input:
        db_path     — Path to talos.db.
        offset      — Row offset (0-based).
        limit       — Max rows to return.
        source/method/host/status_code/role/module — optional filter values.
    Output:  List of dicts with keys: id, method, host, path, query, status_code,
             source, role_name, module_name.
    Side effects: None.
    """
    if not db_path.exists():
        return []
    with _connect(db_path) as conn:
        if not _table_exists(conn, "flows"):
            return []
        where, filter_params = _build_flow_filters(source, method, host, status_code, role, module)
        rows = conn.execute(
            f"""
            SELECT f.id, f.method, f.host, f.path, f.query, f.status_code,
                   f.source,
                   COALESCE(r.name, '\u2014') AS role_name,
                   COALESCE(m.name, '\u2014') AS module_name
            FROM flows f
            LEFT JOIN roles r ON r.id = f.role_id
            LEFT JOIN modules m ON m.id = f.module_id
            {where}
            ORDER BY f.captured_at DESC
            LIMIT ? OFFSET ?
            """,
            (*filter_params, limit, offset),
        ).fetchall()
        return [dict(r) for r in rows]


def get_adjacent_flows(db_path: Path, flow_id: str) -> tuple[str | None, str | None]:
    """
    Purpose:
        Return the IDs of the flow immediately before and after a given flow,
        ordered by captured_at descending (same order as list_flows).
    Input:   db_path — Path to talos.db; flow_id — UUID of current flow.
    Output:  Tuple (prev_id, next_id). Either may be None at list boundaries.
             prev_id = the row above in the list (newer); next_id = row below (older).
    Side effects: None.
    """
    if not db_path.exists():
        return (None, None)
    with _connect(db_path) as conn:
        if not _table_exists(conn, "flows"):
            return (None, None)
        # Use a window-function CTE to find neighbours in the DESC-time ordering.
        row = conn.execute(
            """
            WITH ordered AS (
                SELECT id,
                       LAG(id)  OVER (ORDER BY captured_at DESC) AS prev_id,
                       LEAD(id) OVER (ORDER BY captured_at DESC) AS next_id
                FROM flows
            )
            SELECT prev_id, next_id FROM ordered WHERE id = ?
            """,
            (flow_id,),
        ).fetchone()
        if row is None:
            return (None, None)
        return (row["prev_id"], row["next_id"])


def get_flow_detail(db_path: Path, flow_id: str) -> dict | None:
    """
    Purpose: Fetch all columns for a single flow including resolved role and module names.
    Input:   db_path — Path to talos.db; flow_id — UUID string.
    Output:  Full flow dict with role_name and module_name added, or None if not found.
    Side effects: None.
    """
    if not db_path.exists():
        return None
    with _connect(db_path) as conn:
        if not _table_exists(conn, "flows"):
            return None
        row = conn.execute(
            """
            SELECT f.*,
                   COALESCE(r.name, '—') AS role_name,
                   COALESCE(m.name, '—') AS module_name
            FROM flows f
            LEFT JOIN roles r ON r.id = f.role_id
            LEFT JOIN modules m ON m.id = f.module_id
            WHERE f.id = ?
            """,
            (flow_id,),
        ).fetchone()
        return dict(row) if row else None


# ------------------------------------------------------------------ #
# Endpoint queries                                                     #
# ------------------------------------------------------------------ #

def get_endpoint_count(db_path: Path) -> int:
    """
    Purpose: Count total normalized endpoints in the project database.
    Input:   db_path — Path to talos.db.
    Output:  Integer count; 0 if DB absent or table missing.
    Side effects: None.
    """
    if not db_path.exists():
        return 0
    with _connect(db_path) as conn:
        if not _table_exists(conn, "endpoints"):
            return 0
        row = conn.execute("SELECT COUNT(*) FROM endpoints").fetchone()
        return row[0] if row else 0


def list_endpoints(db_path: Path, offset: int = 0, limit: int = 200) -> list[dict]:
    """
    Purpose: Return a paginated slice of endpoints with flow hit counts, comma-separated
             role names, and comma-separated module names derived from linked flows.
    Input:
        db_path — Path to talos.db.
        offset  — Row offset (0-based).
        limit   — Max rows to return.
    Output:  List of dicts: id, method, host, normalized_path, hit_count,
             roles (from endpoint_roles), modules (from linked flows).
    Side effects: None.
    """
    if not db_path.exists():
        return []
    with _connect(db_path) as conn:
        if not _table_exists(conn, "endpoints"):
            return []
        rows = conn.execute(
            """
            SELECT
                e.id,
                e.method,
                e.host,
                e.normalized_path,
                COUNT(DISTINCT f.id) AS hit_count,
                GROUP_CONCAT(DISTINCT r.name)  AS roles,
                GROUP_CONCAT(DISTINCT m.name)  AS modules
            FROM endpoints e
            LEFT JOIN flows f         ON f.endpoint_id = e.id
            LEFT JOIN modules m       ON m.id = f.module_id
            LEFT JOIN endpoint_roles er ON er.endpoint_id = e.id
            LEFT JOIN roles r         ON r.id = er.role_id
            GROUP BY e.id
            ORDER BY hit_count DESC, e.normalized_path
            LIMIT ? OFFSET ?
            """,
            (limit, offset),
        ).fetchall()
        return [dict(r) for r in rows]


def get_endpoint_detail(db_path: Path, endpoint_id: str) -> dict | None:
    """
    Purpose: Fetch a single endpoint record.
    Input:   db_path — Path to talos.db; endpoint_id — UUID string.
    Output:  Endpoint dict, or None if not found.
    Side effects: None.
    """
    if not db_path.exists():
        return None
    with _connect(db_path) as conn:
        if not _table_exists(conn, "endpoints"):
            return None
        row = conn.execute(
            "SELECT * FROM endpoints WHERE id = ?", (endpoint_id,)
        ).fetchone()
        return dict(row) if row else None


def get_endpoint_parameters(db_path: Path, endpoint_id: str) -> list[dict]:
    """
    Purpose: Fetch all parameters belonging to an endpoint.
    Input:   db_path — Path to talos.db; endpoint_id — UUID string.
    Output:  List of parameter dicts.
    Side effects: None.
    """
    if not db_path.exists():
        return []
    with _connect(db_path) as conn:
        if not _table_exists(conn, "parameters"):
            return []
        rows = conn.execute(
            "SELECT * FROM parameters WHERE endpoint_id = ? ORDER BY location, name",
            (endpoint_id,),
        ).fetchall()
        return [dict(r) for r in rows]


def get_endpoint_flows(db_path: Path, endpoint_id: str, limit: int = 20) -> list[dict]:
    """
    Purpose: Fetch recent flows linked to an endpoint, with resolved role and module names.
    Input:
        db_path     — Path to talos.db.
        endpoint_id — UUID string.
        limit       — Max flows to return (default 20).
    Output:  List of dicts: id, method, path, status_code, captured_at, role_name, module_name.
    Side effects: None.
    """
    if not db_path.exists():
        return []
    with _connect(db_path) as conn:
        if not _table_exists(conn, "flows"):
            return []
        rows = conn.execute(
            """
            SELECT f.id, f.method, f.path, f.status_code, f.captured_at,
                   COALESCE(r.name, '—') AS role_name,
                   COALESCE(m.name, '—') AS module_name
            FROM flows f
            LEFT JOIN roles r ON r.id = f.role_id
            LEFT JOIN modules m ON m.id = f.module_id
            WHERE f.endpoint_id = ?
            ORDER BY f.captured_at DESC
            LIMIT ?
            """,
            (endpoint_id, limit),
        ).fetchall()
        return [dict(r) for r in rows]


def get_adjacent_endpoints(db_path: Path, endpoint_id: str) -> tuple[str | None, str | None]:
    """
    Purpose:
        Return the IDs of the endpoint immediately before and after a given endpoint,
        in the same order used by list_endpoints (hit_count DESC, normalized_path ASC).
        Implemented by fetching all ordered IDs then finding neighbours in Python —
        avoids window-function fragility when the flows table may be absent.
    Input:   db_path — Path to talos.db; endpoint_id — UUID of current endpoint.
    Output:  Tuple (prev_id, next_id). Either may be None at list boundaries.
    Side effects: None.
    """
    if not db_path.exists():
        return (None, None)
    with _connect(db_path) as conn:
        if not _table_exists(conn, "endpoints"):
            return (None, None)
        # Use the same ordering logic as list_endpoints.
        # LEFT JOIN flows so that endpoints with no flows get hit_count=0.
        rows = conn.execute(
            """
            SELECT e.id, COUNT(f.id) AS hit_count
            FROM endpoints e
            LEFT JOIN flows f ON f.endpoint_id = e.id
            GROUP BY e.id
            ORDER BY hit_count DESC, e.normalized_path ASC
            """
        ).fetchall()
    ids = [r["id"] for r in rows]
    try:
        idx = ids.index(endpoint_id)
    except ValueError:
        return (None, None)
    prev_id = ids[idx - 1] if idx > 0 else None
    next_id = ids[idx + 1] if idx < len(ids) - 1 else None
    return (prev_id, next_id)


# ------------------------------------------------------------------ #
# Role-module scoped flow views                                        #
# ------------------------------------------------------------------ #

def list_flows_by_role(
    db_path: Path, role_id: str, offset: int, limit: int
) -> list[dict]:
    """
    Purpose:
        Return a paginated slice of flows captured under a specific role.
    Input:
        db_path — Path to talos.db.
        role_id — UUID of the role to filter by.
        offset  — Row offset (0-based).
        limit   — Max rows to return.
    Output:
        List of dicts: id, method, path, query, status_code, captured_at, module_id.
    Side effects: None.
    """
    if not db_path.exists():
        return []
    with _connect(db_path) as conn:
        if not _table_exists(conn, "flows"):
            return []
        rows = conn.execute(
            """
            SELECT id, method, path, query, status_code, captured_at, module_id
            FROM flows
            WHERE role_id = ?
            ORDER BY captured_at DESC
            LIMIT ? OFFSET ?
            """,
            (role_id, limit, offset),
        ).fetchall()
        return [dict(r) for r in rows]


def list_flows_by_module(
    db_path: Path, module_id: str, offset: int, limit: int
) -> list[dict]:
    """
    Purpose:
        Return a paginated slice of flows captured under a specific module.
    Input:
        db_path   — Path to talos.db.
        module_id — UUID of the module to filter by.
        offset    — Row offset (0-based).
        limit     — Max rows to return.
    Output:
        List of dicts: id, method, path, query, status_code, captured_at, role_id.
    Side effects: None.
    """
    if not db_path.exists():
        return []
    with _connect(db_path) as conn:
        if not _table_exists(conn, "flows"):
            return []
        rows = conn.execute(
            """
            SELECT id, method, path, query, status_code, captured_at, role_id
            FROM flows
            WHERE module_id = ?
            ORDER BY captured_at DESC
            LIMIT ? OFFSET ?
            """,
            (module_id, limit, offset),
        ).fetchall()
        return [dict(r) for r in rows]


def list_flows_by_role_module(
    db_path: Path, role_id: str, module_id: str, offset: int, limit: int
) -> list[dict]:
    """
    Purpose:
        Return flows captured under a specific (role, module) pair.
        This is the primary query path for BAC/IDOR: "what did role X do in module Y?"
    Input:
        db_path   — Path to talos.db.
        role_id   — UUID of the role.
        module_id — UUID of the module.
        offset    — Row offset (0-based).
        limit     — Max rows to return.
    Output:
        List of dicts: id, method, path, query, status_code, captured_at.
    Side effects: None.
    """
    if not db_path.exists():
        return []
    with _connect(db_path) as conn:
        if not _table_exists(conn, "flows"):
            return []
        rows = conn.execute(
            """
            SELECT id, method, path, query, status_code, captured_at
            FROM flows
            WHERE role_id = ? AND module_id = ?
            ORDER BY captured_at DESC
            LIMIT ? OFFSET ?
            """,
            (role_id, module_id, limit, offset),
        ).fetchall()
        return [dict(r) for r in rows]


# ------------------------------------------------------------------ #
# Endpoint exposure queries                                            #
# ------------------------------------------------------------------ #

def list_endpoint_roles(db_path: Path, endpoint_id: str) -> list[dict]:
    """
    Purpose:
        Return all roles that have accessed a given endpoint, with role names
        and the time window of observed access.
    Input:
        db_path     — Path to talos.db.
        endpoint_id — UUID of the endpoint.
    Output:
        List of dicts: role_id, role_name, first_seen, last_seen.
    Side effects: None.
    """
    if not db_path.exists():
        return []
    with _connect(db_path) as conn:
        if not _table_exists(conn, "endpoint_roles"):
            return []
        rows = conn.execute(
            """
            SELECT er.role_id, r.name AS role_name, er.first_seen, er.last_seen
            FROM endpoint_roles er
            JOIN roles r ON r.id = er.role_id
            WHERE er.endpoint_id = ?
            ORDER BY er.first_seen
            """,
            (endpoint_id,),
        ).fetchall()
        return [dict(r) for r in rows]


def list_endpoints_by_role(db_path: Path, role_id: str) -> list[dict]:
    """
    Purpose:
        Return all endpoints accessed by a specific role, joined with endpoint shape.
        Answers: "what attack surface did this role touch?"
    Input:
        db_path — Path to talos.db.
        role_id — UUID of the role.
    Output:
        List of dicts: endpoint_id, method, host, normalized_path, first_seen, last_seen.
    Side effects: None.
    """
    if not db_path.exists():
        return []
    with _connect(db_path) as conn:
        if not _table_exists(conn, "endpoint_roles"):
            return []
        rows = conn.execute(
            """
            SELECT
                er.endpoint_id,
                e.method,
                e.host,
                e.normalized_path,
                er.first_seen,
                er.last_seen
            FROM endpoint_roles er
            JOIN endpoints e ON e.id = er.endpoint_id
            WHERE er.role_id = ?
            ORDER BY e.host, e.normalized_path
            """,
            (role_id,),
        ).fetchall()
        return [dict(r) for r in rows]


def list_endpoints_multi_role(db_path: Path) -> list[dict]:
    """
    Purpose:
        Return endpoints accessed by more than one role.
        These are the primary candidates for BAC/IDOR testing:
        shared endpoints where role boundaries may not be enforced.
    Input:
        db_path — Path to talos.db.
    Output:
        List of dicts: endpoint_id, method, host, normalized_path, role_count,
        role_names (comma-separated resolved role names).
        Ordered by role_count descending (most-shared first).
    Side effects: None.
    """
    if not db_path.exists():
        return []
    with _connect(db_path) as conn:
        if not _table_exists(conn, "endpoint_roles"):
            return []
        rows = conn.execute(
            """
            SELECT
                er.endpoint_id,
                e.method,
                e.host,
                e.normalized_path,
                COUNT(er.role_id)          AS role_count,
                GROUP_CONCAT(r.name, ', ') AS role_names
            FROM endpoint_roles er
            JOIN endpoints e ON e.id = er.endpoint_id
            JOIN roles     r ON r.id = er.role_id
            GROUP BY er.endpoint_id
            HAVING COUNT(er.role_id) > 1
            ORDER BY role_count DESC, e.normalized_path
            """
        ).fetchall()
        return [dict(r) for r in rows]


def list_endpoints_by_role_module(db_path: Path, role_id: str, module_id: str) -> list[dict]:
    """
    Purpose:
        Return all distinct endpoints reached by flows captured under a specific
        (role, module) pair.
        Answers: "what surfaces did role X touch while browsing module Y?"
        This is the (role, module) → endpoints query required for module-aware
        segmentation and BAC surface mapping.
    Input:
        db_path   — Path to talos.db.
        role_id   — UUID of the role.
        module_id — UUID of the module.
    Output:
        List of dicts: endpoint_id, method, host, normalized_path, hit_count.
        Ordered by hit_count descending, then normalized_path.
    Side effects: None.
    """
    if not db_path.exists():
        return []
    with _connect(db_path) as conn:
        if not _table_exists(conn, "flows") or not _table_exists(conn, "endpoints"):
            return []
        rows = conn.execute(
            """
            SELECT
                e.id              AS endpoint_id,
                e.method,
                e.host,
                e.normalized_path,
                COUNT(f.id)       AS hit_count
            FROM flows f
            JOIN endpoints e ON e.id = f.endpoint_id
            WHERE f.role_id = ? AND f.module_id = ?
            GROUP BY e.id
            ORDER BY hit_count DESC, e.normalized_path
            """,
            (role_id, module_id),
        ).fetchall()
        return [dict(r) for r in rows]


def detect_server_deny_endpoints(db_path: Path) -> list[dict]:
    """
    Purpose:
        Return specific endpoints reached under (role, module) pairs where the
        access map asserts server_expected = 'DENY'.

        This is a module boundary violation signal:
        "the backend should block this role from this module, yet traffic reached
        a specific endpoint" — indicating missing server-side enforcement.

        Stronger than detect_deny_with_flows (flow-level) because it names the
        exact endpoint URLs that are exposed, making them directly actionable.
    Input:
        db_path — Path to talos.db.
    Output:
        List of dicts: endpoint_id, method, host, normalized_path,
                       role_name, module_name, client_allowed, server_expected,
                       flow_count.
        Ordered by role_name, module_name, normalized_path.
    Side effects: None.
    """
    if not db_path.exists():
        return []
    with _connect(db_path) as conn:
        if (
            not _table_exists(conn, "access_map")
            or not _table_exists(conn, "flows")
            or not _table_exists(conn, "endpoints")
        ):
            return []
        rows = conn.execute(
            """
            SELECT
                e.id              AS endpoint_id,
                e.method,
                e.host,
                e.normalized_path,
                r.name            AS role_name,
                m.name            AS module_name,
                am.client_allowed,
                am.server_expected,
                COUNT(f.id)       AS flow_count,
                GROUP_CONCAT(f.id) AS flow_ids_raw
            FROM access_map am
            JOIN roles     r ON r.id = am.role_id
            JOIN modules   m ON m.id = am.module_id
            JOIN flows     f ON f.role_id   = am.role_id
                             AND f.module_id = am.module_id
            JOIN endpoints e ON e.id = f.endpoint_id
            WHERE am.server_expected = 'DENY'
            GROUP BY e.id, am.role_id, am.module_id
            ORDER BY r.name, m.name, e.normalized_path
            """
        ).fetchall()
        result = []
        for row in rows:
            d = dict(row)
            # Convert comma-separated UUIDs to a deduplicated list (max 10).
            raw = d.pop("flow_ids_raw", "") or ""
            seen: dict = {}
            for fid in raw.split(","):
                if fid and fid not in seen:
                    seen[fid] = True
                    if len(seen) >= 10:
                        break
            d["flow_ids"] = list(seen.keys())
            result.append(d)
        return result


# ------------------------------------------------------------------ #
# Access map                                                           #
# ------------------------------------------------------------------ #

def get_access_map_rows(db_path: Path) -> list[dict]:
    """
    Purpose:
        Return all access_map rows with resolved role and module names.
        Provides the full picture of: what is ALLOW/DENY/UNKNOWN per (role, module)?
        Used to answer "what is blocked vs allowed vs unknown?"
    Input:
        db_path — Path to talos.db.
    Output:
        List of dicts: role_id, role_name, module_id, module_name,
                       client_allowed, server_expected.
        Ordered by role_name, module_name.
    Side effects: None.
    """
    if not db_path.exists():
        return []
    with _connect(db_path) as conn:
        if not _table_exists(conn, "access_map"):
            return []
        rows = conn.execute(
            """
            SELECT
                am.role_id,
                r.name  AS role_name,
                am.module_id,
                m.name  AS module_name,
                am.client_allowed,
                am.server_expected
            FROM access_map am
            JOIN roles   r ON r.id = am.role_id
            JOIN modules m ON m.id = am.module_id
            ORDER BY r.name, m.name
            """
        ).fetchall()
        return [dict(r) for r in rows]


# ------------------------------------------------------------------ #
# Detection signals (no replay required)                              #
# ------------------------------------------------------------------ #

def detect_deny_with_flows(db_path: Path) -> list[dict]:
    """
    Purpose:
        Case 1 — Client says DENY but traffic exists.
        Signals: UI bypass, hidden feature exposure, or misconfigured access gate.

        Logic:
            access_map.client_allowed = 'DENY'
            AND flows exist for that (role_id, module_id) pair.

    Input:
        db_path — Path to talos.db.
    Output:
        List of dicts: role_id, role_name, module_id, module_name,
                       client_allowed, server_expected, flow_count.
        Ordered by flow_count descending.
    Side effects: None.
    """
    if not db_path.exists():
        return []
    with _connect(db_path) as conn:
        if not _table_exists(conn, "access_map") or not _table_exists(conn, "flows"):
            return []
        rows = conn.execute(
            """
            SELECT
                am.role_id,
                r.name  AS role_name,
                am.module_id,
                m.name  AS module_name,
                am.client_allowed,
                am.server_expected,
                COUNT(f.id) AS flow_count
            FROM access_map am
            JOIN roles   r ON r.id = am.role_id
            JOIN modules m ON m.id = am.module_id
            JOIN flows   f ON f.role_id = am.role_id AND f.module_id = am.module_id
            WHERE am.client_allowed = 'DENY'
            GROUP BY am.role_id, am.module_id
            ORDER BY flow_count DESC
            """
        ).fetchall()
        return [dict(r) for r in rows]


def detect_allow_without_flows(db_path: Path) -> list[dict]:
    """
    Purpose:
        Case 2 — Client says ALLOW but no traffic observed.
        Signals: missing test coverage for this role/module pair.

        Logic:
            access_map.client_allowed = 'ALLOW'
            AND no flows exist for that (role_id, module_id) pair.

    Input:
        db_path — Path to talos.db.
    Output:
        List of dicts: role_id, role_name, module_id, module_name,
                       client_allowed, server_expected.
        Ordered by role_name, module_name.
    Side effects: None.
    """
    if not db_path.exists():
        return []
    with _connect(db_path) as conn:
        if not _table_exists(conn, "access_map") or not _table_exists(conn, "flows"):
            return []
        rows = conn.execute(
            """
            SELECT
                am.role_id,
                r.name  AS role_name,
                am.module_id,
                m.name  AS module_name,
                am.client_allowed,
                am.server_expected
            FROM access_map am
            JOIN roles   r ON r.id = am.role_id
            JOIN modules m ON m.id = am.module_id
            WHERE am.client_allowed = 'ALLOW'
              AND NOT EXISTS (
                  SELECT 1 FROM flows f
                  WHERE f.role_id = am.role_id
                    AND f.module_id = am.module_id
              )
            ORDER BY r.name, m.name
            """
        ).fetchall()
        return [dict(r) for r in rows]


def get_access_coverage(db_path: Path) -> list[dict]:
    """
    Purpose:
        Full join of access_map + observed flow counts + endpoint exposure counts.
        Single query to answer "expected vs observed" for every (role, module) pair
        that has an access_map entry.

        Columns:
            role_name, module_name  — identity of the pair.
            client_allowed          — what the UI exposes.
            server_expected         — asserted backend enforcement.
            flow_count              — flows observed for this pair (0 = none captured).
            endpoint_count          — distinct endpoints touched by this role in this module.

    Input:
        db_path — Path to talos.db.
    Output:
        List of dicts with the columns above, ordered by role_name, module_name.
    Side effects: None.
    """
    if not db_path.exists():
        return []
    with _connect(db_path) as conn:
        if not _table_exists(conn, "access_map"):
            return []
        rows = conn.execute(
            """
            SELECT
                r.name                      AS role_name,
                m.name                      AS module_name,
                am.client_allowed,
                am.server_expected,
                COUNT(DISTINCT f.id)        AS flow_count,
                COUNT(DISTINCT f.endpoint_id) AS endpoint_count
            FROM access_map am
            JOIN roles   r ON r.id = am.role_id
            JOIN modules m ON m.id = am.module_id
            LEFT JOIN flows f ON f.role_id = am.role_id AND f.module_id = am.module_id
            GROUP BY am.role_id, am.module_id
            ORDER BY r.name, m.name
            """
        ).fetchall()
        return [dict(r) for r in rows]


# ------------------------------------------------------------------ #
# Stream / delta queries (used by SSE endpoint)                       #
# ------------------------------------------------------------------ #

def get_latest_flow_captured_at(db_path: Path) -> str | None:
    """
    Purpose:
        Return the captured_at timestamp of the most recent flow.
        Used by the SSE stream to initialise its cursor so only future
        flows are emitted (not the full history on first connect).
    Input:   db_path — Path to talos.db.
    Output:  ISO timestamp string, or None when the flows table is empty or absent.
    Side effects: None.
    """
    if not db_path.exists():
        return None
    with _connect(db_path) as conn:
        if not _table_exists(conn, "flows"):
            return None
        row = conn.execute(
            "SELECT captured_at FROM flows ORDER BY captured_at DESC LIMIT 1"
        ).fetchone()
        return row["captured_at"] if row else None


def list_flows_after(
    db_path: Path, after_captured_at: str, limit: int = 50
) -> list[dict]:
    """
    Purpose:
        Return flows captured strictly after a given ISO timestamp, ordered
        ascending (oldest first so the client can prepend in the right sequence).
        Used exclusively by the SSE stream for incremental flow delivery.
    Input:
        db_path          — Path to talos.db.
        after_captured_at — ISO-format timestamp string used as exclusive lower bound.
        limit             — Maximum rows to return per poll cycle (default 50).
    Output:
        List of dicts: id, method, host, path, query, status_code, captured_at,
        source, role_name, module_name.  Same shape as list_flows for compatibility with
        the client-side row renderer.
    Side effects: None.
    """
    if not db_path.exists():
        return []
    with _connect(db_path) as conn:
        if not _table_exists(conn, "flows"):
            return []
        rows = conn.execute(
            """
            SELECT f.id, f.method, f.host, f.path, f.query, f.status_code,
                   f.captured_at, f.source,
                   COALESCE(r.name, '\u2014') AS role_name,
                   COALESCE(m.name, '\u2014') AS module_name
            FROM flows f
            LEFT JOIN roles r ON r.id = f.role_id
            LEFT JOIN modules m ON m.id = f.module_id
            WHERE f.captured_at > ?
            ORDER BY f.captured_at ASC
            LIMIT ?
            """,
            (after_captured_at, limit),
        ).fetchall()
        return [dict(r) for r in rows]


def get_flow_filter_options(db_path: Path) -> dict:
    """
    Purpose:
        Return distinct values for each flow filter dimension.
        Used to populate filter dropdowns on the flows list page.
    Input:   db_path — Path to talos.db.
    Output:  Dict with keys: sources, methods, hosts, statuses, roles, modules.
             Each value is a sorted list of distinct strings/ints present in flows.
    Side effects: None.
    """
    empty: dict = {"sources": [], "methods": [], "hosts": [], "statuses": [], "roles": [], "modules": []}
    if not db_path.exists():
        return empty
    with _connect(db_path) as conn:
        if not _table_exists(conn, "flows"):
            return empty
        sources = [
            r[0] for r in conn.execute(
                "SELECT DISTINCT source FROM flows WHERE source IS NOT NULL ORDER BY source"
            ).fetchall()
        ]
        methods = [
            r[0] for r in conn.execute(
                "SELECT DISTINCT method FROM flows ORDER BY method"
            ).fetchall()
        ]
        hosts = [
            r[0] for r in conn.execute(
                "SELECT DISTINCT host FROM flows ORDER BY host"
            ).fetchall()
        ]
        statuses = [
            r[0] for r in conn.execute(
                "SELECT DISTINCT status_code FROM flows WHERE status_code IS NOT NULL ORDER BY status_code"
            ).fetchall()
        ]
        roles = [
            r[0] for r in conn.execute(
                """
                SELECT DISTINCT r.name
                FROM flows f JOIN roles r ON r.id = f.role_id
                ORDER BY r.name
                """
            ).fetchall()
        ]
        modules = [
            r[0] for r in conn.execute(
                """
                SELECT DISTINCT m.name
                FROM flows f JOIN modules m ON m.id = f.module_id
                ORDER BY m.name
                """
            ).fetchall()
        ]
        return {
            "sources": sources,
            "methods": methods,
            "hosts": hosts,
            "statuses": statuses,
            "roles": roles,
            "modules": modules,
        }


# ------------------------------------------------------------------ #
# Unauth coverage queries (attack modules)                            #
# ------------------------------------------------------------------ #

_UNAUTH_STATUS_CTE = """
    WITH unauth AS (
        SELECT
            e.id                  AS endpoint_id,
            e.method,
            e.host,
            e.normalized_path,
            atr.verdict           AS unauth_verdict,
            atr.last_run,
            atr.replay_flow_id    AS unauth_replay_flow_id,
            sj_run.job_id         AS running_job_id,
            sj_pend.job_id        AS queued_job_id,
            CASE
                WHEN atr.verdict IS NOT NULL        THEN 'done'
                WHEN sj_run.job_id IS NOT NULL      THEN 'running'
                WHEN sj_pend.job_id IS NOT NULL     THEN 'queued'
                ELSE 'not_tested'
            END AS unauth_status
        FROM endpoints e
        LEFT JOIN (
            -- SQLite picks non-aggregated columns from the row with MAX(captured_at).
            SELECT f2.endpoint_id, atr2.verdict, MAX(f2.captured_at) AS last_run,
                   atr2.replay_flow_id
            FROM auth_test_results atr2
            JOIN flows f2 ON f2.id = atr2.replay_flow_id
            WHERE f2.endpoint_id IS NOT NULL
            GROUP BY f2.endpoint_id
        ) atr ON atr.endpoint_id = e.id
        LEFT JOIN (
            SELECT endpoint_id, MIN(job_id) AS job_id
            FROM scheduler_jobs
            WHERE job_type = 'auth_test' AND status = 'running'
            GROUP BY endpoint_id
        ) sj_run ON sj_run.endpoint_id = e.id
        LEFT JOIN (
            SELECT endpoint_id, MIN(job_id) AS job_id
            FROM scheduler_jobs
            WHERE job_type = 'auth_test' AND status = 'pending'
            GROUP BY endpoint_id
        ) sj_pend ON sj_pend.endpoint_id = e.id
    )
"""


def get_unauth_coverage(db_path: Path) -> dict:
    """
    Purpose:
        Return aggregate counts describing unauth test coverage across all endpoints.
        Derives status from scheduler_jobs + auth_test_results — no separate state table.
    Input:   db_path — Path to talos.db.
    Output:
        Dict with integer keys:
            total, not_tested, queued, running,
            bypass, secure, unknown   (done-subcategories by verdict)
        All values default to 0 when tables are absent.
    Side effects: None.
    """
    if not db_path.exists():
        return {
            "total": 0, "not_tested": 0, "queued": 0,
            "running": 0, "bypass": 0, "secure": 0, "unknown": 0,
        }
    with _connect(db_path) as conn:
        if not _table_exists(conn, "endpoints"):
            return {
                "total": 0, "not_tested": 0, "queued": 0,
                "running": 0, "bypass": 0, "secure": 0, "unknown": 0,
            }
        row = conn.execute(
            _UNAUTH_STATUS_CTE + """
            SELECT
                COUNT(*)                                               AS total,
                SUM(CASE WHEN unauth_status = 'not_tested' THEN 1 ELSE 0 END) AS not_tested,
                SUM(CASE WHEN unauth_status = 'queued'     THEN 1 ELSE 0 END) AS queued,
                SUM(CASE WHEN unauth_status = 'running'    THEN 1 ELSE 0 END) AS running,
                SUM(CASE WHEN unauth_status = 'done'
                          AND unauth_verdict = 'BYPASS'    THEN 1 ELSE 0 END) AS bypass,
                SUM(CASE WHEN unauth_status = 'done'
                          AND unauth_verdict = 'SECURE'    THEN 1 ELSE 0 END) AS secure,
                SUM(CASE WHEN unauth_status = 'done'
                          AND unauth_verdict = 'UNKNOWN'   THEN 1 ELSE 0 END) AS unknown
            FROM unauth
            """
        ).fetchone()
        if row is None:
            return {
                "total": 0, "not_tested": 0, "queued": 0,
                "running": 0, "bypass": 0, "secure": 0, "unknown": 0,
            }
        return {
            "total":      row["total"] or 0,
            "not_tested": row["not_tested"] or 0,
            "queued":     row["queued"] or 0,
            "running":    row["running"] or 0,
            "bypass":     row["bypass"] or 0,
            "secure":     row["secure"] or 0,
            "unknown":    row["unknown"] or 0,
        }


def list_endpoint_unauth_status(
    db_path: Path,
    offset: int = 0,
    limit: int = 200,
) -> list[dict]:
    """
    Purpose:
        Return per-endpoint unauth test status, ordered so actionable items
        (bypass first, then not_tested, queued, running, secure, unknown) surface first.
    Input:
        db_path — Path to talos.db.
        offset  — Row offset (0-based) for pagination.
        limit   — Max rows; capped by caller at 500.
    Output:
        List of dicts per endpoint:
            endpoint_id, method, host, normalized_path,
            unauth_status   — not_tested | queued | running | done
            unauth_verdict  — BYPASS | SECURE | UNKNOWN | None
            last_run        — ISO-8601 string or None
    Side effects: None.
    """
    if not db_path.exists():
        return []
    with _connect(db_path) as conn:
        if not _table_exists(conn, "endpoints"):
            return []
        rows = conn.execute(
            _UNAUTH_STATUS_CTE + """
            SELECT
                endpoint_id,
                method,
                host,
                normalized_path,
                unauth_status,
                unauth_verdict,
                last_run,
                unauth_replay_flow_id
            FROM unauth
            ORDER BY
                CASE unauth_verdict WHEN 'BYPASS' THEN 0 ELSE 1 END,
                CASE unauth_status
                    WHEN 'not_tested' THEN 1
                    WHEN 'queued'     THEN 2
                    WHEN 'running'    THEN 3
                    WHEN 'done'       THEN 4
                    ELSE 5
                END,
                host, normalized_path
            LIMIT ? OFFSET ?
            """,
            (limit, offset),
        ).fetchall()
        return [dict(r) for r in rows]

