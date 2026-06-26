"""
Module: talos.projects.policy

Purpose:
    Endpoint Policy engine — the single authority that answers:
        - What is the effective priority of an endpoint?
        - Is this endpoint excluded from candidate generation?
        - Which rule produced that decision?
        - Give me all testable endpoints, ordered by effective priority.

    Policy is stored in two tables:
        endpoint_policy  — per-endpoint overrides: auto_priority, manual_priority,
                           excluded, notes, tags.
        policy_rules     — project-scoped path-pattern rules: pattern, priority,
                           excluded.

    Effective priority resolution:
        1. Exact endpoint rule — manual_priority in endpoint_policy (highest specificity).
        2. Path rule           — matching pattern in policy_rules.
        3. Auto priority       — auto_priority in endpoint_policy (computed by policy_score).

    Exclusion resolution:
        1. endpoint_policy.excluded = 1 for this endpoint_id.
        2. Any matching policy_rules row with excluded = 1.
        Exclusion is independent of priority — an endpoint is either in or out.

    Priority levels (ordered): CRITICAL > HIGH > NORMAL > LOW
    Numeric mapping used for DB ordering:
        CRITICAL = 3, HIGH = 2, NORMAL = 1, LOW = 0

Dependencies: sqlite3, json, pathlib, fnmatch, talos.projects.db,
              talos.projects.policy_score
Data flow:
    endpoint_cli → set_manual_priority / clear_manual_priority /
                   set_excluded / set_path_rule / ...
    attack modules / BAC / unauth → get_testable_endpoints()
    worker → upsert_auto_priority()
Side effects:
    - DB write functions modify endpoint_policy or policy_rules.
    - Read functions call migrate_project_db on entry.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from fnmatch import fnmatch
from pathlib import Path
from typing import Optional

from talos.projects.db import migrate_project_db


# ------------------------------------------------------------------ #
# Priority level helpers                                               #
# ------------------------------------------------------------------ #

VALID_LEVELS: frozenset[str] = frozenset({"CRITICAL", "HIGH", "NORMAL", "LOW"})

_LEVEL_ORDER: dict[str, int] = {
    "CRITICAL": 3,
    "HIGH":     2,
    "NORMAL":   1,
    "LOW":      0,
}


def _level_to_int(level: str | None) -> int:
    """
    Purpose: Convert a priority level string to an integer for comparisons.
    Input:   level — 'CRITICAL' | 'HIGH' | 'NORMAL' | 'LOW' | None.
    Output:  Integer 0-3, or -1 when level is None.
    Side effects: None.
    """
    if level is None:
        return -1
    return _LEVEL_ORDER.get(level.upper(), 0)


def _now_iso() -> str:
    """Return current UTC time as an ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()


# ------------------------------------------------------------------ #
# Effective Policy dataclass                                           #
# ------------------------------------------------------------------ #

@dataclass
class EffectivePolicy:
    """
    Purpose:
        Carry the resolved policy for a single endpoint.

    Fields:
        endpoint_id      — UUID of the endpoint.
        effective_level  — resolved priority: 'CRITICAL'|'HIGH'|'NORMAL'|'LOW'.
        excluded         — True when the endpoint must be skipped in all attack modules.
        dangerous        — True when the endpoint performs irreversible actions.
                           Auto-replay skips dangerous endpoints; manual replay is allowed.
        logout           — True when the endpoint invalidates auth sessions.
                           All replay modes skip logout endpoints.
        source           — what produced the effective level:
                               'manual'  — explicit manual_priority on endpoint_policy.
                               'rule'    — matching path rule in policy_rules.
                               'auto'    — auto_priority from policy_score.
                               'default' — no policy record; treated as NORMAL.
        matching_rule    — the path pattern that produced the decision (when source='rule').
        auto_score       — raw auto score integer (0 when no record exists).
        auto_breakdown   — dict of contributor → delta (empty when no record).
        manual_priority  — tester-assigned level, or None.
        notes            — free-form tester notes.
        tags             — list of tester-assigned string labels.
    """

    endpoint_id: str
    effective_level: str
    excluded: bool
    dangerous: bool
    logout: bool
    source: str
    matching_rule: Optional[str]
    auto_score: int
    auto_breakdown: dict[str, int]
    manual_priority: Optional[str]
    notes: str
    tags: list[str]


# ------------------------------------------------------------------ #
# Pattern matching                                                     #
# ------------------------------------------------------------------ #

def _path_matches_pattern(path: str, pattern: str) -> bool:
    """
    Purpose:
        Test whether a normalised endpoint path matches a policy rule pattern.
        Patterns support '*' as a wildcard:
            /static/*   — matches /static/ and any path below it.
            /admin/*    — matches /admin/users, /admin/roles, etc.
            /health     — exact prefix match (no wildcard).
    Input:
        path    — normalised endpoint path (e.g. '/api/users/settings').
        pattern — rule pattern (e.g. '/api/*' or '/health').
    Output:
        True when the path matches the pattern.
    Side effects: None.
    """
    # Normalise both sides to lowercase for comparison.
    path_lc = path.lower()
    pattern_lc = pattern.lower()

    if "*" not in pattern_lc:
        # Exact match or prefix without wildcard.
        return path_lc == pattern_lc or path_lc.startswith(pattern_lc.rstrip("/") + "/")

    # fnmatch handles glob-style '*' (not '**'); suitable for single-level prefix patterns.
    # Strip trailing '/*' and check prefix for prefix-style rules.
    if pattern_lc.endswith("/*"):
        prefix = pattern_lc[:-2]
        return path_lc == prefix or path_lc.startswith(prefix + "/")

    return fnmatch(path_lc, pattern_lc)


# ------------------------------------------------------------------ #
# DB connection helpers                                                #
# ------------------------------------------------------------------ #

def _connect_rw(db_path: Path) -> sqlite3.Connection:
    """Open a read-write connection with row_factory."""
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    return conn


def _connect_ro(db_path: Path) -> sqlite3.Connection:
    """Open a read-only connection with row_factory."""
    uri = f"file:{db_path}?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    conn.row_factory = sqlite3.Row
    return conn


# ------------------------------------------------------------------ #
# Auto-priority upsert (called by worker on endpoint insert/update)   #
# ------------------------------------------------------------------ #

def upsert_auto_priority(
    conn: sqlite3.Connection,
    endpoint_id: str,
    auto_priority: str,
    auto_score: int,
    auto_breakdown: dict[str, int],
) -> None:
    """
    Purpose:
        Insert or update the auto_priority fields in endpoint_policy.
        Called by the FlowWorker after each endpoint upsert.
        Does NOT overwrite manual_priority or excluded — those are tester-owned.
    Input:
        conn          — open read-write SQLite connection (caller manages commit).
        endpoint_id   — UUID of the endpoint.
        auto_priority — computed priority level string.
        auto_score    — raw integer score.
        auto_breakdown — dict of contributor label → signed delta.
    Output: None.
    Side effects:
        INSERT OR IGNORE creates the policy row on first observation.
        UPDATE always refreshes auto_priority, auto_score, auto_breakdown, updated_at.
    """
    now = _now_iso()
    breakdown_json = json.dumps(auto_breakdown)

    # Ensure the row exists (INSERT OR IGNORE so tester edits are preserved).
    conn.execute(
        """
        INSERT OR IGNORE INTO endpoint_policy
            (endpoint_id, auto_priority, auto_score, auto_breakdown,
             manual_priority, excluded, dangerous, logout,
             notes, tags, updated_at)
        VALUES (?, ?, ?, ?, NULL, 0, 0, 0, '', '[]', ?)
        """,
        (endpoint_id, auto_priority, auto_score, breakdown_json, now),
    )
    # Always refresh the auto fields — scoring may improve with more observations.
    conn.execute(
        """
        UPDATE endpoint_policy
        SET auto_priority  = ?,
            auto_score     = ?,
            auto_breakdown = ?,
            updated_at     = ?
        WHERE endpoint_id = ?
        """,
        (auto_priority, auto_score, breakdown_json, now, endpoint_id),
    )


# ------------------------------------------------------------------ #
# Manual priority CRUD                                                 #
# ------------------------------------------------------------------ #

def set_manual_priority(
    db_path: Path,
    endpoint_id: str,
    level: str,
) -> None:
    """
    Purpose:
        Assign a manual priority override to an endpoint.
        Manual priority always supersedes auto priority during candidate
        generation.
    Input:
        db_path     — Path to the project's talos.db.
        endpoint_id — UUID of the endpoint.
        level       — 'CRITICAL' | 'HIGH' | 'NORMAL' | 'LOW'.
    Output: None.
    Side effects:
        Upserts endpoint_policy row; sets manual_priority.
    Raises:
        ValueError if level is not one of the valid levels.
    """
    level = level.upper()
    if level not in VALID_LEVELS:
        raise ValueError(
            f"Invalid priority level '{level}'. Valid: {sorted(VALID_LEVELS)}"
        )

    migrate_project_db(db_path)
    now = _now_iso()

    with _connect_rw(db_path) as conn:
        conn.execute(
            """
            INSERT INTO endpoint_policy
                (endpoint_id, auto_priority, auto_score, auto_breakdown,
                 manual_priority, excluded, dangerous, logout,
                 notes, tags, updated_at)
            VALUES (?, 'NORMAL', 0, '{}', ?, 0, 0, 0, '', '[]', ?)
            ON CONFLICT(endpoint_id) DO UPDATE SET
                manual_priority = excluded.manual_priority,
                updated_at      = excluded.updated_at
            """,
            (endpoint_id, level, now),
        )
        # Ensure the manual_priority is actually set (the ON CONFLICT block
        # uses the values from the INSERT attempt via 'excluded' alias).
        conn.execute(
            """
            UPDATE endpoint_policy
            SET manual_priority = ?, updated_at = ?
            WHERE endpoint_id = ?
            """,
            (level, now, endpoint_id),
        )
        conn.commit()


def clear_manual_priority(
    db_path: Path,
    endpoint_id: str,
) -> None:
    """
    Purpose:
        Remove the manual priority override from an endpoint.
        After this call the endpoint falls back to auto_priority.
    Input:
        db_path     — Path to the project's talos.db.
        endpoint_id — UUID of the endpoint.
    Output: None.
    Side effects:
        Sets manual_priority = NULL in endpoint_policy.
        No-op when no row exists.
    """
    migrate_project_db(db_path)
    now = _now_iso()
    with _connect_rw(db_path) as conn:
        conn.execute(
            """
            UPDATE endpoint_policy
            SET manual_priority = NULL, updated_at = ?
            WHERE endpoint_id = ?
            """,
            (now, endpoint_id),
        )
        conn.commit()


# ------------------------------------------------------------------ #
# Exclusion CRUD                                                       #
# ------------------------------------------------------------------ #

def set_excluded(
    db_path: Path,
    endpoint_id: str,
    excluded: bool,
) -> None:
    """
    Purpose:
        Mark or unmark an endpoint as excluded from attack candidate generation.
        Exclusion is independent of priority — an excluded endpoint is never
        returned by get_testable_endpoints() regardless of its priority level.
    Input:
        db_path     — Path to the project's talos.db.
        endpoint_id — UUID of the endpoint.
        excluded    — True to exclude; False to re-include.
    Output: None.
    Side effects:
        Upserts endpoint_policy row; sets excluded flag.
    """
    migrate_project_db(db_path)
    now = _now_iso()
    val = 1 if excluded else 0

    with _connect_rw(db_path) as conn:
        conn.execute(
            """
            INSERT INTO endpoint_policy
                (endpoint_id, auto_priority, auto_score, auto_breakdown,
                 manual_priority, excluded, dangerous, logout,
                 notes, tags, updated_at)
            VALUES (?, 'NORMAL', 0, '{}', NULL, ?, 0, 0, '', '[]', ?)
            ON CONFLICT(endpoint_id) DO UPDATE SET
                excluded   = excluded.excluded,
                updated_at = excluded.updated_at
            """,
            (endpoint_id, val, now),
        )
        conn.execute(
            """
            UPDATE endpoint_policy
            SET excluded = ?, updated_at = ?
            WHERE endpoint_id = ?
            """,
            (val, now, endpoint_id),
        )
        conn.commit()


# ------------------------------------------------------------------ #
# Notes and tags CRUD                                                  #
# ------------------------------------------------------------------ #

def set_notes(
    db_path: Path,
    endpoint_id: str,
    notes: str,
) -> None:
    """
    Purpose:
        Store free-form tester notes on an endpoint policy record.
    Input:
        db_path     — Path to the project's talos.db.
        endpoint_id — UUID of the endpoint.
        notes       — arbitrary text; replaces existing notes.
    Output: None.
    Side effects: Upserts endpoint_policy; sets notes column.
    """
    migrate_project_db(db_path)
    now = _now_iso()
    with _connect_rw(db_path) as conn:
        conn.execute(
            """
            INSERT INTO endpoint_policy
                (endpoint_id, auto_priority, auto_score, auto_breakdown,
                 manual_priority, excluded, dangerous, logout,
                 notes, tags, updated_at)
            VALUES (?, 'NORMAL', 0, '{}', NULL, 0, 0, 0, ?, '[]', ?)
            ON CONFLICT(endpoint_id) DO UPDATE SET
                notes      = excluded.notes,
                updated_at = excluded.updated_at
            """,
            (endpoint_id, notes, now),
        )
        conn.execute(
            "UPDATE endpoint_policy SET notes = ?, updated_at = ? WHERE endpoint_id = ?",
            (notes, now, endpoint_id),
        )
        conn.commit()


def set_tags(
    db_path: Path,
    endpoint_id: str,
    tags: list[str],
) -> None:
    """
    Purpose:
        Replace the tag list on an endpoint policy record.
    Input:
        db_path     — Path to the project's talos.db.
        endpoint_id — UUID of the endpoint.
        tags        — list of arbitrary string labels.
    Output: None.
    Side effects: Upserts endpoint_policy; sets tags column.
    """
    migrate_project_db(db_path)
    now = _now_iso()
    tags_json = json.dumps(tags)
    with _connect_rw(db_path) as conn:
        conn.execute(
            """
            INSERT INTO endpoint_policy
                (endpoint_id, auto_priority, auto_score, auto_breakdown,
                 manual_priority, excluded, dangerous, logout,
                 notes, tags, updated_at)
            VALUES (?, 'NORMAL', 0, '{}', NULL, 0, 0, 0, '', ?, ?)
            ON CONFLICT(endpoint_id) DO UPDATE SET
                tags       = excluded.tags,
                updated_at = excluded.updated_at
            """,
            (endpoint_id, tags_json, now),
        )
        conn.execute(
            "UPDATE endpoint_policy SET tags = ?, updated_at = ? WHERE endpoint_id = ?",
            (tags_json, now, endpoint_id),
        )
        conn.commit()


def set_dangerous(
    db_path: Path,
    endpoint_id: str,
    dangerous: bool,
) -> None:
    """
    Purpose:
        Mark or unmark an endpoint as dangerous.
        Dangerous endpoints perform irreversible actions.  Auto-replay skips
        them; manual replay is still allowed.
    Input:
        db_path     — Path to the project's talos.db.
        endpoint_id — UUID of the endpoint.
        dangerous   — True to mark; False to unmark.
    Output: None.
    Side effects: Upserts endpoint_policy; sets dangerous column.
    """
    migrate_project_db(db_path)
    now = _now_iso()
    val = 1 if dangerous else 0
    with _connect_rw(db_path) as conn:
        conn.execute(
            """
            INSERT INTO endpoint_policy
                (endpoint_id, auto_priority, auto_score, auto_breakdown,
                 manual_priority, excluded, dangerous, logout,
                 notes, tags, updated_at)
            VALUES (?, 'NORMAL', 0, '{}', NULL, 0, ?, 0, '', '[]', ?)
            ON CONFLICT(endpoint_id) DO UPDATE SET
                dangerous  = excluded.dangerous,
                updated_at = excluded.updated_at
            """,
            (endpoint_id, val, now),
        )
        conn.execute(
            "UPDATE endpoint_policy SET dangerous = ?, updated_at = ? WHERE endpoint_id = ?",
            (val, now, endpoint_id),
        )
        conn.commit()


def set_logout(
    db_path: Path,
    endpoint_id: str,
    logout: bool,
) -> None:
    """
    Purpose:
        Mark or unmark an endpoint as a logout endpoint.
        Logout endpoints invalidate auth sessions.  All replay modes skip them.
    Input:
        db_path     — Path to the project's talos.db.
        endpoint_id — UUID of the endpoint.
        logout      — True to mark; False to unmark.
    Output: None.
    Side effects: Upserts endpoint_policy; sets logout column.
    """
    migrate_project_db(db_path)
    now = _now_iso()
    val = 1 if logout else 0
    with _connect_rw(db_path) as conn:
        conn.execute(
            """
            INSERT INTO endpoint_policy
                (endpoint_id, auto_priority, auto_score, auto_breakdown,
                 manual_priority, excluded, dangerous, logout,
                 notes, tags, updated_at)
            VALUES (?, 'NORMAL', 0, '{}', NULL, 0, 0, ?, '', '[]', ?)
            ON CONFLICT(endpoint_id) DO UPDATE SET
                logout     = excluded.logout,
                updated_at = excluded.updated_at
            """,
            (endpoint_id, val, now),
        )
        conn.execute(
            "UPDATE endpoint_policy SET logout = ?, updated_at = ? WHERE endpoint_id = ?",
            (val, now, endpoint_id),
        )
        conn.commit()


# ------------------------------------------------------------------ #
# Path rule CRUD                                                       #
# ------------------------------------------------------------------ #

def set_path_rule(
    db_path: Path,
    project_id: str,
    pattern: str,
    priority: str | None = None,
    excluded: bool = False,
) -> None:
    """
    Purpose:
        Create or update a path-based policy rule.
        A rule applies to all endpoints whose normalised path matches the pattern.
    Input:
        db_path    — Path to the project's talos.db.
        project_id — Project identifier.
        pattern    — Path glob pattern (e.g. '/static/*', '/api/admin/*').
        priority   — Optional priority override for matching endpoints.
                     None to leave priority unaffected by this rule.
        excluded   — True to exclude all matching endpoints.
    Output: None.
    Side effects:
        INSERT OR REPLACE into policy_rules.
    Raises:
        ValueError when priority is provided but not a valid level.
    """
    if priority is not None:
        priority = priority.upper()
        if priority not in VALID_LEVELS:
            raise ValueError(
                f"Invalid priority level '{priority}'. Valid: {sorted(VALID_LEVELS)}"
            )

    migrate_project_db(db_path)
    rule_id = str(uuid.uuid4())
    now = _now_iso()
    excl_int = 1 if excluded else 0

    with _connect_rw(db_path) as conn:
        # Check if a rule already exists for this pattern.
        existing = conn.execute(
            "SELECT id FROM policy_rules WHERE project_id = ? AND pattern = ?",
            (project_id, pattern),
        ).fetchone()

        if existing:
            conn.execute(
                """
                UPDATE policy_rules
                SET priority = ?, excluded = ?, created_at = ?
                WHERE project_id = ? AND pattern = ?
                """,
                (priority, excl_int, now, project_id, pattern),
            )
        else:
            conn.execute(
                """
                INSERT INTO policy_rules (id, project_id, pattern, priority, excluded, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (rule_id, project_id, pattern, priority, excl_int, now),
            )
        conn.commit()


def delete_path_rule(
    db_path: Path,
    project_id: str,
    pattern: str,
) -> bool:
    """
    Purpose:
        Remove a path rule by pattern.
    Input:
        db_path    — Path to the project's talos.db.
        project_id — Project identifier.
        pattern    — Exact pattern string to remove.
    Output:
        True when a rule was deleted; False when no matching rule existed.
    Side effects:
        Deletes one row from policy_rules.
    """
    migrate_project_db(db_path)
    with _connect_rw(db_path) as conn:
        cur = conn.execute(
            "DELETE FROM policy_rules WHERE project_id = ? AND pattern = ?",
            (project_id, pattern),
        )
        conn.commit()
        return cur.rowcount > 0


def list_path_rules(
    db_path: Path,
    project_id: str,
) -> list[dict]:
    """
    Purpose:
        Return all path rules for a project, ordered by creation time.
    Input:
        db_path    — Path to the project's talos.db.
        project_id — Project identifier.
    Output:
        List of rule dicts with keys: id, pattern, priority, excluded, created_at.
    Side effects: None (read-only after migration).
    """
    migrate_project_db(db_path)
    if not db_path.exists():
        return []
    with _connect_ro(db_path) as conn:
        rows = conn.execute(
            """
            SELECT id, pattern, priority, excluded, created_at
            FROM policy_rules
            WHERE project_id = ?
            ORDER BY created_at ASC
            """,
            (project_id,),
        ).fetchall()
    return [dict(r) for r in rows]


# ------------------------------------------------------------------ #
# Effective policy resolution                                          #
# ------------------------------------------------------------------ #

def get_effective_policy(
    db_path: Path,
    project_id: str,
    endpoint_id: str,
    normalized_path: str,
) -> EffectivePolicy:
    """
    Purpose:
        Resolve the effective policy for a single endpoint.
        Precedence:
            1. manual_priority in endpoint_policy  (most specific)
            2. matching path rule in policy_rules
            3. auto_priority in endpoint_policy
            4. default: NORMAL, not excluded

    Input:
        db_path         — Path to the project's talos.db.
        project_id      — Project identifier (scopes path rules).
        endpoint_id     — UUID of the endpoint.
        normalized_path — canonical path used for rule pattern matching.
    Output:
        EffectivePolicy instance.
    Side effects:
        Calls migrate_project_db on entry.
    """
    migrate_project_db(db_path)

    if not db_path.exists():
        return _default_policy(endpoint_id)

    with _connect_ro(db_path) as conn:
        ep_row = conn.execute(
            """
            SELECT auto_priority, auto_score, auto_breakdown,
                   manual_priority, excluded, dangerous, logout,
                   notes, tags
            FROM endpoint_policy
            WHERE endpoint_id = ?
            """,
            (endpoint_id,),
        ).fetchone()

        rules = conn.execute(
            """
            SELECT pattern, priority, excluded
            FROM policy_rules
            WHERE project_id = ?
            ORDER BY created_at ASC
            """,
            (project_id,),
        ).fetchall()

    return _resolve_policy(endpoint_id, normalized_path, ep_row, rules)


def _default_policy(endpoint_id: str) -> EffectivePolicy:
    """Return a default NORMAL, non-excluded policy for endpoints with no data."""
    return EffectivePolicy(
        endpoint_id=endpoint_id,
        effective_level="NORMAL",
        excluded=False,
        dangerous=False,
        logout=False,
        source="default",
        matching_rule=None,
        auto_score=0,
        auto_breakdown={},
        manual_priority=None,
        notes="",
        tags=[],
    )


def _resolve_policy(
    endpoint_id: str,
    normalized_path: str,
    ep_row: sqlite3.Row | None,
    rules: list[sqlite3.Row],
) -> EffectivePolicy:
    """
    Purpose:
        Apply resolution logic to produce an EffectivePolicy.
    Input:
        endpoint_id     — UUID string.
        normalized_path — canonical path.
        ep_row          — row from endpoint_policy, or None.
        rules           — rows from policy_rules for the project.
    Output:
        EffectivePolicy.
    Side effects: None.
    """
    # Unpack endpoint_policy row.
    auto_priority   = "NORMAL"
    auto_score      = 0
    auto_breakdown  = {}
    manual_priority = None
    endpoint_excluded = False
    endpoint_dangerous = False
    endpoint_logout = False
    notes = ""
    tags: list[str] = []

    if ep_row is not None:
        auto_priority   = ep_row["auto_priority"] or "NORMAL"
        auto_score      = ep_row["auto_score"] or 0
        endpoint_excluded  = bool(ep_row["excluded"])
        endpoint_dangerous = bool(ep_row["dangerous"]) if ep_row["dangerous"] is not None else False
        endpoint_logout    = bool(ep_row["logout"]) if ep_row["logout"] is not None else False
        manual_priority = ep_row["manual_priority"]
        notes           = ep_row["notes"] or ""
        try:
            auto_breakdown = json.loads(ep_row["auto_breakdown"] or "{}")
        except (json.JSONDecodeError, TypeError):
            auto_breakdown = {}
        try:
            tags = json.loads(ep_row["tags"] or "[]")
        except (json.JSONDecodeError, TypeError):
            tags = []

    # -- Exclusion resolution --
    # Endpoint-level exclusion always wins.
    excluded = endpoint_excluded

    # Check path rules for exclusion (if not already excluded at endpoint level).
    matching_excl_rule: str | None = None
    if not excluded:
        for rule in rules:
            if rule["excluded"] and _path_matches_pattern(normalized_path, rule["pattern"]):
                excluded = True
                matching_excl_rule = rule["pattern"]
                break

    # -- Priority resolution --
    effective_level: str
    source: str
    matching_rule: str | None = None

    if manual_priority is not None:
        # Explicit tester override — always wins.
        effective_level = manual_priority
        source = "manual"
    else:
        # Find the first matching path rule with a priority set.
        rule_level: str | None = None
        for rule in rules:
            if rule["priority"] and _path_matches_pattern(normalized_path, rule["pattern"]):
                rule_level = rule["priority"]
                matching_rule = rule["pattern"]
                break

        if rule_level is not None:
            effective_level = rule_level
            source = "rule"
        else:
            effective_level = auto_priority
            source = "auto"

    # If excluded via path rule, record which rule caused it.
    if matching_excl_rule and matching_rule is None:
        matching_rule = matching_excl_rule

    return EffectivePolicy(
        endpoint_id=endpoint_id,
        effective_level=effective_level,
        excluded=excluded,
        dangerous=endpoint_dangerous,
        logout=endpoint_logout,
        source=source,
        matching_rule=matching_rule,
        auto_score=auto_score,
        auto_breakdown=auto_breakdown,
        manual_priority=manual_priority,
        notes=notes,
        tags=tags,
    )


# ------------------------------------------------------------------ #
# Testable endpoint enumeration                                        #
# ------------------------------------------------------------------ #

def get_testable_endpoints(
    db_path: Path,
    project_id: str,
) -> list[dict]:
    """
    Purpose:
        Return all non-excluded endpoints for the project, ordered by effective
        priority descending (CRITICAL first, then HIGH, NORMAL, LOW).
        This is the primary API for attack modules to obtain their target list.

        Every attack module should call this instead of querying endpoints
        directly — it respects manual overrides, path rules, auto-scoring, and
        exclusions in a single consistent call.

    Input:
        db_path    — Path to the project's talos.db.
        project_id — Project identifier; scopes both endpoints and path rules.
    Output:
        List of endpoint dicts, each containing:
            id, method, host, normalized_path, content_type, auth_required,
            roles_seen, first_seen, last_seen,
            effective_level, auto_score, manual_priority, excluded, source.
        Ordered by effective priority (CRITICAL first), then auto_score descending
        within the same level, then first_seen ascending (stable tiebreak).
    Side effects:
        Calls migrate_project_db on entry.
    """
    migrate_project_db(db_path)
    if not db_path.exists():
        return []

    with _connect_ro(db_path) as conn:
        endpoints = conn.execute(
            """
            SELECT e.id, e.method, e.host, e.normalized_path,
                   e.content_type, e.auth_required, e.roles_seen,
                   e.first_seen, e.last_seen,
                   ep.auto_priority, ep.auto_score, ep.manual_priority,
                   ep.excluded, ep.dangerous, ep.logout,
                   ep.notes, ep.tags
            FROM endpoints e
            LEFT JOIN endpoint_policy ep ON ep.endpoint_id = e.id
            WHERE e.project_id = ?
            """,
            (project_id,),
        ).fetchall()

        rules = conn.execute(
            """
            SELECT pattern, priority, excluded
            FROM policy_rules
            WHERE project_id = ?
            ORDER BY created_at ASC
            """,
            (project_id,),
        ).fetchall()

    results = []
    for row in endpoints:
        endpoint_id = row["id"]
        normalized_path = row["normalized_path"]

        # Build a minimal ep_row-like object for the resolver.
        # Use a dict comprehension so _resolve_policy can index by name.
        ep_dict = {
            "auto_priority":   row["auto_priority"],
            "auto_score":      row["auto_score"],
            "auto_breakdown":  "{}",
            "manual_priority": row["manual_priority"],
            "excluded":        row["excluded"],
            "dangerous":       row["dangerous"],
            "logout":          row["logout"],
            "notes":           row["notes"] or "",
            "tags":            row["tags"] or "[]",
        }

        policy = _resolve_policy(
            endpoint_id=endpoint_id,
            normalized_path=normalized_path,
            ep_row=_DictRow(ep_dict),
            rules=rules,
        )

        if policy.excluded:
            continue

        results.append({
            "id":              endpoint_id,
            "method":          row["method"],
            "host":            row["host"],
            "normalized_path": normalized_path,
            "content_type":    row["content_type"],
            "auth_required":   bool(row["auth_required"]),
            "roles_seen":      row["roles_seen"],
            "first_seen":      row["first_seen"],
            "last_seen":       row["last_seen"],
            "effective_level": policy.effective_level,
            "auto_score":      policy.auto_score or 0,
            "manual_priority": policy.manual_priority,
            "excluded":        policy.excluded,
            "dangerous":       policy.dangerous,
            "logout":          policy.logout,
            "source":          policy.source,
        })

    # Sort: effective level descending, then auto_score descending, then first_seen ascending.
    results.sort(
        key=lambda e: (
            -_level_to_int(e["effective_level"]),
            -(e["auto_score"] or 0),
            e["first_seen"] or "",
        )
    )
    return results


# ------------------------------------------------------------------ #
# Internal dict-row shim                                               #
# ------------------------------------------------------------------ #

class _DictRow:
    """
    Purpose:
        Thin wrapper that makes a plain dict subscriptable by string key,
        matching the sqlite3.Row interface expected by _resolve_policy.
    Input:
        data — plain dict.
    """

    __slots__ = ("_data",)

    def __init__(self, data: dict) -> None:
        self._data = data

    def __getitem__(self, key: str):  # noqa: ANN001
        return self._data.get(key)
