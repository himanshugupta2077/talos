"""
Module: talos.projects.policy

Purpose:
    Endpoint Policy engine — the single authority that answers:
        - What is the effective priority of an endpoint?
        - Is this endpoint excluded from candidate generation?
        - Is this endpoint qualified for automated testing?
        - What is the pre-computed baseline flow for this endpoint?
        - Which rule produced that decision?
        - Give me all testable endpoints, ordered by effective priority.

    Policy is stored in two tables:
        endpoint_policy  — per-endpoint overrides: auto_priority, manual_priority,
                           excluded, notes, tags, qualified, qualification_reason,
                           baseline_flow_id, baseline_status.
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

    Qualification:
        An endpoint is qualified when it has at least one proxy_capture flow with a
        2xx HTTP status AND the endpoint is not marked logout or dangerous.
        Qualification is computed incrementally by update_endpoint_qualification(),
        which is called by the FlowWorker after each proxy_capture flow is persisted.

        Qualification criterion:
            status_code BETWEEN 200 AND 299
            AND source = 'proxy_capture'
            AND endpoint_policy.logout = 0
            AND endpoint_policy.dangerous = 0

        qualification_reason values:
            'no_flows'        — no proxy_capture flows captured yet.
            'no_2xx_response' — flows exist but none returned 2xx.
            'only_redirects'  — all observed flows returned 3xx.
            'is_logout'       — endpoint is a logout endpoint.
            'is_dangerous'    — endpoint is marked dangerous.
            'flow_2xx'        — at least one 2xx proxy_capture flow exists.

    Baseline flow:
        baseline_flow_id caches the most recently captured 2xx proxy_capture flow
        for the endpoint.  Attack modules and the replay engine read this field
        instead of running SELECT … ORDER BY captured_at DESC LIMIT 1 each time.

    Priority levels (ordered): CRITICAL > HIGH > NORMAL > LOW
    Numeric mapping used for DB ordering:
        CRITICAL = 3, HIGH = 2, NORMAL = 1, LOW = 0

Dependencies: sqlite3, json, pathlib, fnmatch, talos.projects.db,
              talos.projects.policy_score
Data flow:
    endpoint_cli → bulk_* / set_manual_priority / set_excluded /
                   set_path_rule / add_path_rule / update_path_rule /
                   list_endpoints / explain_endpoint_policy /
                   preview_path_rule_impact / ...
    attack modules / BAC / unauth / IV → get_testable_endpoints()
    endpoint list CLI → list_endpoints() + format_endpoint_list_json()
    worker → upsert_auto_priority() + update_endpoint_qualification()
Side effects:
    - DB write functions modify endpoint_policy or policy_rules.
    - Bulk mutations validate all IDs then write in one transaction.
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

# HTTP status codes that qualify an endpoint for automated testing.
# Any 2xx response from a proxy_capture flow qualifies an endpoint.
# Applications legitimately return 201, 202, 204, 206, etc.
QUALIFYING_STATUSES: frozenset[int] = frozenset(range(200, 300))

# Qualification reason constants — stored in endpoint_policy.qualification_reason.
QUAL_REASON_NO_FLOWS        = "no_flows"
QUAL_REASON_NO_2XX          = "no_2xx_response"
QUAL_REASON_ONLY_REDIRECTS  = "only_redirects"
QUAL_REASON_IS_LOGOUT       = "is_logout"
QUAL_REASON_IS_DANGEROUS    = "is_dangerous"
QUAL_REASON_FLOW_2XX        = "flow_2xx"


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
        endpoint_id          — UUID of the endpoint.
        effective_level      — resolved priority: 'CRITICAL'|'HIGH'|'NORMAL'|'LOW'.
        excluded         — True when the endpoint must be skipped in all attack modules.
        dangerous        — True when the endpoint performs irreversible actions.
                           Auto-replay skips dangerous endpoints; manual replay is allowed.
        logout           — True when the endpoint invalidates auth sessions.
                           All replay modes skip logout endpoints.
        qualified        — True when the endpoint has at least one 2xx proxy_capture
                           flow and is eligible for automated testing.
        qualification_reason — Why the endpoint is qualified or not:
                           'no_flows' | 'no_2xx_response' | 'only_redirects' |
                           'is_logout' | 'is_dangerous' | 'flow_2xx'.
        baseline_flow_id — Pre-computed UUID of the best 2xx proxy_capture flow;
                           None until the first qualifying flow is captured.
        baseline_status  — HTTP status code of the baseline flow; None until set.
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
        auto_priority    — raw auto_priority level before manual/rule override.
        exclusion_source — what produced exclusion: 'endpoint' | 'path_rule' | None.
        exclusion_rule_id — policy_rules.id when exclusion_source='path_rule'.
        exclusion_rule_pattern — pattern when exclusion_source='path_rule'.
        priority_rule_id — policy_rules.id when source='rule'.
    """

    endpoint_id: str
    effective_level: str
    excluded: bool
    dangerous: bool
    logout: bool
    qualified: bool
    qualification_reason: str
    baseline_flow_id: Optional[str]
    baseline_status: Optional[int]
    source: str
    matching_rule: Optional[str]
    auto_score: int
    auto_breakdown: dict[str, int]
    manual_priority: Optional[str]
    notes: str
    tags: list[str]
    auto_priority: str = "NORMAL"
    exclusion_source: Optional[str] = None
    exclusion_rule_id: Optional[str] = None
    exclusion_rule_pattern: Optional[str] = None
    priority_rule_id: Optional[str] = None


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
# Endpoint qualification update (called by FlowWorker)                #
# ------------------------------------------------------------------ #

def update_endpoint_qualification(
    conn: sqlite3.Connection,
    endpoint_id: str,
    flow_id: str,
    status_code: int,
) -> None:
    """
    Purpose:
        Update qualification state for an endpoint after a new proxy_capture
        flow is persisted.  Called by FlowWorker in the same DB session used
        for endpoint/flow persistence (caller commits).

        Qualification rule:
            An endpoint is qualified when it has at least one proxy_capture flow
            with status_code BETWEEN 200 AND 299 AND the endpoint is neither
            logout nor dangerous.

        Baseline rule:
            baseline_flow_id always points to the most recently captured 2xx
            proxy_capture flow.  This eliminates per-attack SELECT … ORDER BY
            queries \u2014 callers read the pre-computed flow ID directly.

        Non-qualifying flows update the qualification_reason so operators can
        see why an endpoint is not testable yet (e.g. 'only_redirects').
        The reason is only updated when the endpoint is not yet qualified;
        once qualified, the state is permanent unless tester action is taken.

    Input:
        conn        \u2014 open read-write SQLite connection (caller manages commit).
        endpoint_id \u2014 UUID of the endpoint whose policy row to update.
        flow_id     \u2014 UUID of the newly persisted proxy_capture flow.
        status_code \u2014 HTTP response status of the new flow.
    Output: None.
    Side effects:
        Updates endpoint_policy row in the open connection.
        No-op when the policy row does not yet exist (upsert_auto_priority
        always runs first and creates the row).
    """
    now = _now_iso()

    if status_code in QUALIFYING_STATUSES:
        # Read logout/dangerous flags \u2014 those endpoints must never be qualified.
        row = conn.execute(
            "SELECT logout, dangerous FROM endpoint_policy WHERE endpoint_id = ?",
            (endpoint_id,),
        ).fetchone()
        if row is None:
            # Row should exist (upsert_auto_priority runs first) \u2014 skip safely.
            return
        if row["logout"]:
            # Update reason to reflect the permanent blocker.
            conn.execute(
                """
                UPDATE endpoint_policy
                SET qualification_reason = ?, updated_at = ?
                WHERE endpoint_id = ? AND qualified = 0
                """,
                (QUAL_REASON_IS_LOGOUT, now, endpoint_id),
            )
            return
        if row["dangerous"]:
            conn.execute(
                """
                UPDATE endpoint_policy
                SET qualification_reason = ?, updated_at = ?
                WHERE endpoint_id = ? AND qualified = 0
                """,
                (QUAL_REASON_IS_DANGEROUS, now, endpoint_id),
            )
            return
        # Qualify the endpoint and record the baseline flow.
        conn.execute(
            """
            UPDATE endpoint_policy
            SET qualified            = 1,
                qualification_reason = ?,
                baseline_flow_id     = ?,
                baseline_status      = ?,
                updated_at           = ?
            WHERE endpoint_id = ?
            """,
            (QUAL_REASON_FLOW_2XX, flow_id, status_code, now, endpoint_id),
        )
    else:
        # Non-qualifying flow: update reason only if not yet qualified.
        reason = _not_qualified_reason(status_code)
        conn.execute(
            """
            UPDATE endpoint_policy
            SET qualification_reason = ?, updated_at = ?
            WHERE endpoint_id = ? AND qualified = 0
            """,
            (reason, now, endpoint_id),
        )


def _not_qualified_reason(status_code: int) -> str:
    """
    Purpose:
        Derive a qualification_reason string for a non-2xx response status.
    Input:   status_code \u2014 HTTP response status code.
    Output:  One of the QUAL_REASON_* constants.
    Side effects: None.
    """
    if 300 <= status_code < 400:
        return QUAL_REASON_ONLY_REDIRECTS
    return QUAL_REASON_NO_2XX


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


def get_notes_and_tags(
    db_path: Path,
    endpoint_id: str,
) -> tuple[str, list[str]]:
    """
    Purpose:
        Read free-form notes and tester tags for an endpoint policy row.
    Input:
        db_path     — Path to the project's talos.db.
        endpoint_id — UUID of the endpoint.
    Output:
        (notes, tags) — notes is '' and tags is [] when no policy row exists.
    Side effects:
        Calls migrate_project_db on entry; read-only after migration.
    """
    migrate_project_db(db_path)
    if not db_path.exists():
        return "", []
    with _connect_ro(db_path) as conn:
        row = conn.execute(
            "SELECT notes, tags FROM endpoint_policy WHERE endpoint_id = ?",
            (endpoint_id,),
        ).fetchone()
    if row is None:
        return "", []
    notes = row["notes"] if row["notes"] is not None else ""
    try:
        tags = json.loads(row["tags"] or "[]")
        if not isinstance(tags, list):
            tags = []
    except (json.JSONDecodeError, TypeError):
        tags = []
    return notes, [str(t) for t in tags]


def add_tags(
    db_path: Path,
    endpoint_id: str,
    new_tags: list[str],
) -> list[str]:
    """
    Purpose:
        Merge labels into the endpoint's tag list (order-preserving, no duplicates).
    Input:
        db_path     — Path to the project's talos.db.
        endpoint_id — UUID of the endpoint.
        new_tags    — labels to add (empty strings ignored).
    Output:
        The resulting tag list after the merge.
    Side effects:
        Upserts endpoint_policy via set_tags().
    """
    _, current = get_notes_and_tags(db_path, endpoint_id)
    seen = set(current)
    merged = list(current)
    for tag in new_tags:
        label = tag.strip()
        if not label or label in seen:
            continue
        seen.add(label)
        merged.append(label)
    set_tags(db_path, endpoint_id, merged)
    return merged


def remove_tags(
    db_path: Path,
    endpoint_id: str,
    tags_to_remove: list[str],
) -> list[str]:
    """
    Purpose:
        Remove labels from the endpoint's tag list (exact string match).
    Input:
        db_path        — Path to the project's talos.db.
        endpoint_id    — UUID of the endpoint.
        tags_to_remove — labels to drop.
    Output:
        The resulting tag list after removal.
    Side effects:
        Upserts endpoint_policy via set_tags().
    """
    remove_set = {t.strip() for t in tags_to_remove if t.strip()}
    _, current = get_notes_and_tags(db_path, endpoint_id)
    remaining = [t for t in current if t not in remove_set]
    set_tags(db_path, endpoint_id, remaining)
    return remaining


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
) -> str:
    """
    Purpose:
        Create or update a path-based policy rule by pattern.
        A rule applies to all endpoints whose normalised path matches the pattern.
        Canonical entry point used by both legacy priority/exclude path commands
        and the first-class ``endpoint rule`` resource.
    Input:
        db_path    — Path to the project's talos.db.
        project_id — Project identifier.
        pattern    — Path glob pattern (e.g. '/static/*', '/api/admin/*').
        priority   — Optional priority override for matching endpoints.
                     None to leave priority unaffected by this rule.
        excluded   — True to exclude all matching endpoints.
    Output:
        The rule UUID (existing id when the pattern already had a rule).
    Side effects:
        INSERT or UPDATE into policy_rules.
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
            rule_id = existing["id"]
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
    return rule_id


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
        ``excluded`` is a bool for machine-readable consumers.
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
    return [
        {
            "id": r["id"],
            "pattern": r["pattern"],
            "priority": r["priority"],
            "excluded": bool(r["excluded"]),
            "created_at": r["created_at"],
        }
        for r in rows
    ]


def get_path_rule(
    db_path: Path,
    project_id: str,
    rule_id: str,
) -> dict | None:
    """
    Purpose:
        Fetch one policy rule by UUID within a project.
    Input:
        db_path / project_id / rule_id — scope and rule identity.
    Output:
        Rule dict (id, pattern, priority, excluded, created_at) or None.
    Side effects: migrate_project_db on entry.
    """
    migrate_project_db(db_path)
    if not db_path.exists():
        return None
    with _connect_ro(db_path) as conn:
        row = conn.execute(
            """
            SELECT id, pattern, priority, excluded, created_at
            FROM policy_rules
            WHERE project_id = ? AND id = ?
            """,
            (project_id, rule_id),
        ).fetchone()
    if row is None:
        return None
    return {
        "id": row["id"],
        "pattern": row["pattern"],
        "priority": row["priority"],
        "excluded": bool(row["excluded"]),
        "created_at": row["created_at"],
    }


def add_path_rule(
    db_path: Path,
    project_id: str,
    pattern: str,
    *,
    priority: str | None = None,
    excluded: bool = False,
) -> dict:
    """
    Purpose:
        Create a path rule (or fully replace an existing rule with the same pattern).
        Canonical API for ``talos endpoint rule add``.
    Input:
        pattern  — path glob.
        priority — optional level.
        excluded — exclusion flag.
    Output:
        The resulting rule dict.
    Side effects: Writes policy_rules via set_path_rule.
    """
    rule_id = set_path_rule(
        db_path, project_id, pattern, priority=priority, excluded=excluded
    )
    rule = get_path_rule(db_path, project_id, rule_id)
    assert rule is not None
    return rule


def update_path_rule(
    db_path: Path,
    project_id: str,
    rule_id: str,
    *,
    priority: str | None | object = ...,
    excluded: bool | None = None,
    clear_priority: bool = False,
) -> dict:
    """
    Purpose:
        Partial update of a path rule by id.
        Priority and exclusion are independent fields on the same resource.
    Input:
        rule_id         — existing rule UUID.
        priority        — new level when provided (use clear_priority to null it).
        excluded        — True/False to set exclusion; None leaves unchanged.
        clear_priority  — True sets priority to NULL.
    Output:
        Updated rule dict.
    Side effects: UPDATE policy_rules.
    Raises:
        ValueError when the rule is missing or priority is invalid.
    """
    migrate_project_db(db_path)
    existing = get_path_rule(db_path, project_id, rule_id)
    if existing is None:
        raise ValueError(f"Policy rule '{rule_id}' not found.")

    new_priority = existing["priority"]
    if clear_priority:
        new_priority = None
    elif priority is not ...:
        if priority is None:
            new_priority = None
        else:
            level = str(priority).upper()
            if level not in VALID_LEVELS:
                raise ValueError(
                    f"Invalid priority level '{level}'. Valid: {sorted(VALID_LEVELS)}"
                )
            new_priority = level

    new_excluded = existing["excluded"] if excluded is None else bool(excluded)

    with _connect_rw(db_path) as conn:
        conn.execute(
            """
            UPDATE policy_rules
            SET priority = ?, excluded = ?
            WHERE project_id = ? AND id = ?
            """,
            (new_priority, 1 if new_excluded else 0, project_id, rule_id),
        )
        conn.commit()

    updated = get_path_rule(db_path, project_id, rule_id)
    assert updated is not None
    return updated


def delete_path_rule_by_id(
    db_path: Path,
    project_id: str,
    rule_id: str,
) -> bool:
    """
    Purpose:
        Delete a path rule by UUID.
    Output:
        True when a row was deleted.
    Side effects: DELETE from policy_rules.
    """
    migrate_project_db(db_path)
    with _connect_rw(db_path) as conn:
        cur = conn.execute(
            "DELETE FROM policy_rules WHERE project_id = ? AND id = ?",
            (project_id, rule_id),
        )
        conn.commit()
        return cur.rowcount > 0


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
                   qualified, qualification_reason,
                   baseline_flow_id, baseline_status,
                   notes, tags
            FROM endpoint_policy
            WHERE endpoint_id = ?
            """,
            (endpoint_id,),
        ).fetchone()

        rules = conn.execute(
            """
            SELECT id, pattern, priority, excluded
            FROM policy_rules
            WHERE project_id = ?
            ORDER BY created_at ASC
            """,
            (project_id,),
        ).fetchall()

    return _resolve_policy(endpoint_id, normalized_path, ep_row, rules)


def _default_policy(endpoint_id: str) -> EffectivePolicy:
    """Return a default NORMAL, non-excluded, unqualified policy for endpoints with no data."""
    return EffectivePolicy(
        endpoint_id=endpoint_id,
        effective_level="NORMAL",
        excluded=False,
        dangerous=False,
        logout=False,
        qualified=False,
        qualification_reason=QUAL_REASON_NO_FLOWS,
        baseline_flow_id=None,
        baseline_status=None,
        source="default",
        matching_rule=None,
        auto_score=0,
        auto_breakdown={},
        manual_priority=None,
        notes="",
        tags=[],
        auto_priority="NORMAL",
        exclusion_source=None,
        exclusion_rule_id=None,
        exclusion_rule_pattern=None,
        priority_rule_id=None,
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
        Single shared resolver used by get_effective_policy, list_endpoints,
        get_testable_endpoints, explain_endpoint_policy, and rule preview.
    Input:
        endpoint_id     — UUID string.
        normalized_path — canonical path.
        ep_row          — row from endpoint_policy, or None.
        rules           — rows from policy_rules for the project (may include id).
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
    endpoint_qualified = False
    endpoint_qualification_reason = QUAL_REASON_NO_FLOWS
    endpoint_baseline_flow_id: Optional[str] = None
    endpoint_baseline_status: Optional[int] = None
    notes = ""
    tags: list[str] = []

    if ep_row is not None:
        auto_priority   = ep_row["auto_priority"] or "NORMAL"
        auto_score      = ep_row["auto_score"] or 0
        endpoint_excluded  = bool(ep_row["excluded"])
        endpoint_dangerous = bool(ep_row["dangerous"]) if ep_row["dangerous"] is not None else False
        endpoint_logout    = bool(ep_row["logout"]) if ep_row["logout"] is not None else False
        endpoint_qualified = bool(ep_row["qualified"]) if ep_row["qualified"] is not None else False
        endpoint_qualification_reason = ep_row["qualification_reason"] or QUAL_REASON_NO_FLOWS
        endpoint_baseline_flow_id = ep_row["baseline_flow_id"]
        endpoint_baseline_status  = ep_row["baseline_status"]
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
    # Endpoint-level exclusion always wins over path rules.
    excluded = False
    exclusion_source: str | None = None
    exclusion_rule_id: str | None = None
    exclusion_rule_pattern: str | None = None

    if endpoint_excluded:
        excluded = True
        exclusion_source = "endpoint"
    else:
        for rule in rules:
            if rule["excluded"] and _path_matches_pattern(normalized_path, rule["pattern"]):
                excluded = True
                exclusion_source = "path_rule"
                exclusion_rule_pattern = rule["pattern"]
                try:
                    exclusion_rule_id = rule["id"]
                except (KeyError, IndexError, TypeError):
                    exclusion_rule_id = None
                break

    # -- Priority resolution --
    effective_level: str
    source: str
    matching_rule: str | None = None
    priority_rule_id: str | None = None

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
                try:
                    priority_rule_id = rule["id"]
                except (KeyError, IndexError, TypeError):
                    priority_rule_id = None
                break

        if rule_level is not None:
            effective_level = rule_level
            source = "rule"
        else:
            effective_level = auto_priority
            source = "auto"

    # Surface exclusion path pattern in matching_rule when priority has no rule.
    if exclusion_rule_pattern and matching_rule is None:
        matching_rule = exclusion_rule_pattern

    return EffectivePolicy(
        endpoint_id=endpoint_id,
        effective_level=effective_level,
        excluded=excluded,
        dangerous=endpoint_dangerous,
        logout=endpoint_logout,
        qualified=endpoint_qualified,
        qualification_reason=endpoint_qualification_reason,
        baseline_flow_id=endpoint_baseline_flow_id,
        baseline_status=endpoint_baseline_status,
        source=source,
        matching_rule=matching_rule,
        auto_score=auto_score,
        auto_breakdown=auto_breakdown,
        manual_priority=manual_priority,
        notes=notes,
        tags=tags if isinstance(tags, list) else [],
        auto_priority=auto_priority,
        exclusion_source=exclusion_source,
        exclusion_rule_id=exclusion_rule_id,
        exclusion_rule_pattern=exclusion_rule_pattern,
        priority_rule_id=priority_rule_id,
    )


# ------------------------------------------------------------------ #
# Testable endpoint enumeration                                        #
# ------------------------------------------------------------------ #

def get_testable_endpoints(
    db_path: Path,
    project_id: str,
    *,
    endpoint_id: Optional[str] = None,
    module_id: Optional[str] = None,
) -> list[dict]:
    """
    Purpose:
        Return non-excluded, qualified endpoints for the project, ordered by
        effective priority descending (CRITICAL first, then HIGH, NORMAL, LOW).
        This is the primary API for attack modules to obtain their target list.

        An endpoint is included only when:
            - It has at least one 2xx proxy_capture flow (qualified = 1).
            - It is not excluded by endpoint_policy or a path rule.

        Optional scope filters (mutually exclusive — at most one):
            endpoint_id — return at most that single endpoint (O(1) lookup).
            module_id   — return only endpoints that have at least one flow
                          tagged with this module (avoids project-wide load).

        Every attack module and IV engine should call this instead of querying
        endpoints directly — it respects qualification, manual overrides, path
        rules, auto-scoring, and exclusions in a single consistent call.

    Input:
        db_path     — Path to the project's talos.db.
        project_id  — Project identifier; scopes both endpoints and path rules.
        endpoint_id — Optional single-endpoint scope.
        module_id   — Optional module scope (endpoints with flows in the module).
    Output:
        List of endpoint dicts, each containing:
            id, method, host, normalized_path, content_type, auth_required,
            roles_seen, first_seen, last_seen,
            effective_level, auto_score, manual_priority, excluded, source,
            qualified, qualification_reason, baseline_flow_id, baseline_status.
        Ordered by effective priority (CRITICAL first), then auto_score descending
        within the same level, then first_seen ascending (stable tiebreak).
    Side effects:
        Calls migrate_project_db on entry.
    Raises:
        ValueError when both endpoint_id and module_id are provided.
    """
    if endpoint_id is not None and module_id is not None:
        raise ValueError(
            "endpoint_id and module_id are mutually exclusive scope filters"
        )

    migrate_project_db(db_path)
    if not db_path.exists():
        return []

    with _connect_ro(db_path) as conn:
        sql = """
            SELECT e.id, e.method, e.host, e.normalized_path,
                   e.content_type, e.auth_required, e.roles_seen,
                   e.first_seen, e.last_seen,
                   ep.auto_priority, ep.auto_score, ep.manual_priority,
                   ep.excluded, ep.dangerous, ep.logout,
                   ep.qualified, ep.qualification_reason,
                   ep.baseline_flow_id, ep.baseline_status,
                   ep.notes, ep.tags
            FROM endpoints e
            LEFT JOIN endpoint_policy ep ON ep.endpoint_id = e.id
            WHERE e.project_id = ?
              AND ep.qualified = 1
        """
        params: list = [project_id]

        if endpoint_id is not None:
            sql += " AND e.id = ?"
            params.append(endpoint_id)
        elif module_id is not None:
            # Endpoints observed under this module (via tagged proxy captures).
            sql += """
              AND EXISTS (
                  SELECT 1 FROM flows f
                  WHERE f.endpoint_id = e.id
                    AND f.project_id  = ?
                    AND f.module_id   = ?
              )
            """
            params.extend([project_id, module_id])

        endpoints = conn.execute(sql, params).fetchall()

        rules = conn.execute(
            """
            SELECT id, pattern, priority, excluded
            FROM policy_rules
            WHERE project_id = ?
            ORDER BY created_at ASC
            """,
            (project_id,),
        ).fetchall()

    results = []
    for row in endpoints:
        eid = row["id"]
        normalized_path = row["normalized_path"]

        # Build a minimal ep_row-like object for the resolver.
        # Use a dict comprehension so _resolve_policy can index by name.
        ep_dict = {
            "auto_priority":          row["auto_priority"],
            "auto_score":             row["auto_score"],
            "auto_breakdown":         "{}",
            "manual_priority":        row["manual_priority"],
            "excluded":               row["excluded"],
            "dangerous":              row["dangerous"],
            "logout":                 row["logout"],
            "qualified":              row["qualified"],
            "qualification_reason":   row["qualification_reason"],
            "baseline_flow_id":       row["baseline_flow_id"],
            "baseline_status":        row["baseline_status"],
            "notes":                  row["notes"] or "",
            "tags":                   row["tags"] or "[]",
        }

        policy = _resolve_policy(
            endpoint_id=eid,
            normalized_path=normalized_path,
            ep_row=_DictRow(ep_dict),
            rules=rules,
        )

        if policy.excluded:
            continue

        origin, host_display = split_origin_identity(row["host"] or "")
        results.append({
            "id":                   eid,
            "method":               row["method"],
            "host":                 row["host"],
            "origin":               origin,
            "host_display":         host_display,
            "normalized_path":      normalized_path,
            "content_type":         row["content_type"],
            "auth_required":        bool(row["auth_required"]),
            "roles_seen":           row["roles_seen"],
            "first_seen":           row["first_seen"],
            "last_seen":            row["last_seen"],
            "effective_level":      policy.effective_level,
            "auto_score":           policy.auto_score or 0,
            "manual_priority":      policy.manual_priority,
            "excluded":             policy.excluded,
            "dangerous":            policy.dangerous,
            "logout":               policy.logout,
            "qualified":            policy.qualified,
            "qualification_reason": policy.qualification_reason,
            "baseline_flow_id":     policy.baseline_flow_id,
            "baseline_status":      policy.baseline_status,
            "source":               policy.source,
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


def is_endpoint_testable(
    db_path: Path,
    project_id: str,
    endpoint_id: str,
) -> bool:
    """
    Purpose:
        Return True when a single endpoint is currently testable under
        Endpoint Policy (qualified and not excluded by endpoint or path rule).
        Thin convenience wrapper over get_testable_endpoints(endpoint_id=…).
    Input:
        db_path     — Path to the project's talos.db.
        project_id  — Project identifier.
        endpoint_id — UUID of the endpoint to check.
    Output:
        True if the endpoint would be returned by get_testable_endpoints.
    Side effects: None (read-only; may call migrate_project_db).
    """
    return bool(
        get_testable_endpoints(
            db_path, project_id, endpoint_id=endpoint_id
        )
    )


# ------------------------------------------------------------------ #
# Full endpoint inventory (CLI discovery)                              #
# ------------------------------------------------------------------ #

def list_endpoints(
    db_path: Path,
    project_id: str,
    *,
    method: Optional[str] = None,
    host: Optional[str] = None,
    qualified: Optional[bool] = None,
    excluded: Optional[bool] = None,
    search: Optional[str] = None,
    role_id: Optional[str] = None,
    priority: Optional[str] = None,
) -> list[dict]:
    """
    Purpose:
        Return the full endpoint inventory for a project with effective policy
        resolved for each row.  Unlike get_testable_endpoints(), this includes
        unqualified and excluded endpoints so operators can discover UUIDs and
        inspect qualification / exclusion state from the CLI.

        Optional filters (all optional; combined with AND when multiple set):
            method    — HTTP method, case-insensitive exact match.
            host      — host, case-insensitive exact match.
            qualified — when True/False, keep only rows with that qualification.
            excluded  — when True/False, keep only rows with that effective
                        exclusion (endpoint flag or matching path rule).
            search    — case-insensitive substring match on host or path.
            role_id   — keep endpoints whose roles_seen JSON contains this role UUID.
            priority  — effective priority level (CRITICAL|HIGH|NORMAL|LOW).

    Input:
        db_path    — Path to the project's talos.db.
        project_id — Project identifier; scopes endpoints and path rules.
        method / host / qualified / excluded / search / role_id / priority
                   — optional filters (see above).
    Output:
        List of endpoint dicts, each containing resolved policy fields plus
        identity helpers (origin, host_display), tags, parameter_count, and
        parsed roles_seen.  See format_endpoint_list_json() for the Control
        Panel / --format json shape.
    Side effects:
        Calls migrate_project_db on entry.
    Raises:
        ValueError when priority is set to an invalid level string.
    """
    if priority is not None:
        level = priority.upper()
        if level not in VALID_LEVELS:
            raise ValueError(
                f"Invalid priority '{priority}'. "
                f"Valid levels: {', '.join(sorted(VALID_LEVELS))}"
            )
        priority = level

    migrate_project_db(db_path)
    if not db_path.exists():
        return []

    with _connect_ro(db_path) as conn:
        rows = conn.execute(
            """
            SELECT e.id, e.method, e.host, e.normalized_path,
                   e.content_type, e.auth_required, e.roles_seen,
                   e.first_seen, e.last_seen,
                   ep.auto_priority, ep.auto_score, ep.auto_breakdown,
                   ep.manual_priority,
                   ep.excluded, ep.dangerous, ep.logout,
                   ep.qualified, ep.qualification_reason,
                   ep.baseline_flow_id, ep.baseline_status,
                   ep.notes, ep.tags,
                   (SELECT COUNT(*) FROM parameters p
                    WHERE p.endpoint_id = e.id) AS parameter_count
            FROM endpoints e
            LEFT JOIN endpoint_policy ep ON ep.endpoint_id = e.id
            WHERE e.project_id = ?
            """,
            (project_id,),
        ).fetchall()

        rules = conn.execute(
            """
            SELECT id, pattern, priority, excluded
            FROM policy_rules
            WHERE project_id = ?
            ORDER BY created_at ASC
            """,
            (project_id,),
        ).fetchall()

        role_name_by_id = {
            r["id"]: r["name"]
            for r in conn.execute("SELECT id, name FROM roles").fetchall()
        }

    method_filter = method.upper() if method else None
    host_filter = host.lower() if host else None
    search_filter = search.lower() if search else None

    results: list[dict] = []
    for row in rows:
        eid = row["id"]
        normalized_path = row["normalized_path"]
        row_method = row["method"] or ""
        row_host = row["host"] or ""
        origin, host_display = split_origin_identity(row_host)

        # Cheap SQL-equivalent filters before policy resolution.
        # host filter matches either stored origin or display hostname.
        if method_filter is not None and row_method.upper() != method_filter:
            continue
        if host_filter is not None:
            if (
                row_host.lower() != host_filter
                and host_display.lower() != host_filter
                and origin.lower() != host_filter
            ):
                continue
        if search_filter is not None:
            haystack = f"{row_host} {host_display} {normalized_path}".lower()
            if search_filter not in haystack:
                continue
        if role_id is not None:
            try:
                seen = json.loads(row["roles_seen"] or "[]")
            except (json.JSONDecodeError, TypeError):
                seen = []
            if not isinstance(seen, list) or role_id not in seen:
                continue

        ep_dict = {
            "auto_priority":        row["auto_priority"],
            "auto_score":           row["auto_score"],
            "auto_breakdown":       row["auto_breakdown"] or "{}",
            "manual_priority":      row["manual_priority"],
            "excluded":             row["excluded"] if row["excluded"] is not None else 0,
            "dangerous":            row["dangerous"] if row["dangerous"] is not None else 0,
            "logout":               row["logout"] if row["logout"] is not None else 0,
            "qualified":            row["qualified"] if row["qualified"] is not None else 0,
            "qualification_reason": row["qualification_reason"],
            "baseline_flow_id":     row["baseline_flow_id"],
            "baseline_status":      row["baseline_status"],
            "notes":                row["notes"] or "",
            "tags":                 row["tags"] or "[]",
        }

        policy = _resolve_policy(
            endpoint_id=eid,
            normalized_path=normalized_path,
            ep_row=_DictRow(ep_dict),
            rules=rules,
        )

        if qualified is not None and policy.qualified != qualified:
            continue
        if excluded is not None and policy.excluded != excluded:
            continue
        if priority is not None and policy.effective_level != priority:
            continue

        try:
            roles_raw = json.loads(row["roles_seen"] or "[]")
            if not isinstance(roles_raw, list):
                roles_raw = []
        except (json.JSONDecodeError, TypeError):
            roles_raw = []
        roles_seen_names = [
            role_name_by_id.get(rid, rid) for rid in roles_raw if isinstance(rid, str)
        ]

        results.append({
            "id":                   eid,
            "method":               row_method,
            "host":                 row_host,
            "origin":               origin,
            "host_display":         host_display,
            "normalized_path":      normalized_path,
            "content_type":         row["content_type"],
            "auth_required":        bool(row["auth_required"]),
            "roles_seen":           roles_seen_names,
            "roles_seen_ids":       roles_raw,
            "first_seen":           row["first_seen"],
            "last_seen":            row["last_seen"],
            "effective_level":      policy.effective_level,
            "auto_score":           policy.auto_score or 0,
            "manual_priority":      policy.manual_priority,
            "excluded":             policy.excluded,
            "exclusion_source":     policy.exclusion_source,
            "dangerous":            policy.dangerous,
            "logout":               policy.logout,
            "qualified":            policy.qualified,
            "qualification_reason": policy.qualification_reason,
            "baseline_flow_id":     policy.baseline_flow_id,
            "baseline_status":      policy.baseline_status,
            "source":               policy.source,
            "matching_rule":        policy.matching_rule,
            "tags":                 list(policy.tags),
            "notes":                policy.notes,
            "parameter_count":      int(row["parameter_count"] or 0),
        })

    results.sort(
        key=lambda e: (
            -_level_to_int(e["effective_level"]),
            -(e["auto_score"] or 0),
            e["first_seen"] or "",
        )
    )
    return results


# ------------------------------------------------------------------ #
# Origin identity helpers                                              #
# ------------------------------------------------------------------ #

def split_origin_identity(stored_host: str) -> tuple[str, str]:
    """
    Purpose:
        Split the endpoints.host column (canonical origin since the scope
        redesign) into (origin, host_display) for list/show JSON and tables.
        Legacy host-only values (no scheme) are treated as both origin and host.
    Input:
        stored_host — value from endpoints.host.
    Output:
        (origin, host) where host is the hostname without port when possible.
    Side effects: None.
    """
    value = (stored_host or "").strip()
    if not value:
        return "", ""
    if "://" not in value:
        # Legacy hostname-only storage.
        return value, value
    try:
        from urllib.parse import urlsplit

        parsed = urlsplit(value)
        hostname = parsed.hostname or value
        return value, hostname
    except ValueError:
        return value, value


def format_endpoint_list_json(endpoints: list[dict]) -> dict:
    """
    Purpose:
        Build the Control Panel / CLI ``--format json`` payload for endpoint
        inventory. Returns **resolved** policy state, not raw DB rows.
    Input:
        endpoints — rows from list_endpoints().
    Output:
        {"endpoints": [...], "count": N}
    Side effects: None.
    """
    items = []
    for e in endpoints:
        items.append({
            "id": e["id"],
            "method": e.get("method"),
            "origin": e.get("origin") or e.get("host"),
            "host": e.get("host_display") or e.get("host"),
            "path": e.get("normalized_path"),
            "priority": {
                "effective": e.get("effective_level"),
                "source": e.get("source"),
            },
            "qualified": bool(e.get("qualified")),
            "qualification_reason": e.get("qualification_reason"),
            "excluded": bool(e.get("excluded")),
            "exclusion_source": e.get("exclusion_source"),
            "dangerous": bool(e.get("dangerous")),
            "logout": bool(e.get("logout")),
            "roles_seen": e.get("roles_seen") or [],
            "parameter_count": int(e.get("parameter_count") or 0),
            "baseline_flow_id": e.get("baseline_flow_id"),
            "baseline_status": e.get("baseline_status"),
            "tags": e.get("tags") or [],
            "last_seen": e.get("last_seen"),
            "first_seen": e.get("first_seen"),
            "content_type": e.get("content_type"),
            "auth_required": bool(e.get("auth_required")),
            "auto_score": e.get("auto_score"),
            "manual_priority": e.get("manual_priority"),
            "matching_rule": e.get("matching_rule"),
        })
    return {"endpoints": items, "count": len(items)}


def explain_endpoint_policy(
    db_path: Path,
    project_id: str,
    endpoint_id: str,
    normalized_path: str,
) -> dict:
    """
    Purpose:
        Build a structured explanation of **why** the effective policy for an
        endpoint is what it is — for CLI operators and the Endpoint Detail
        Policy tab.
    Input:
        db_path / project_id / endpoint_id / normalized_path — identity + scope.
    Output:
        Nested dict: priority, exclusion, qualification, safety, baseline.
    Side effects: read-only after migrate.
    """
    policy = get_effective_policy(
        db_path, project_id, endpoint_id, normalized_path
    )

    priority_source = {
        "manual": "manual",
        "rule": "path_rule",
        "auto": "auto",
        "default": "default",
    }.get(policy.source, policy.source)

    rule_block = None
    if policy.source == "rule" and policy.matching_rule:
        rule_block = {
            "id": policy.priority_rule_id,
            "pattern": policy.matching_rule,
            "priority": policy.effective_level,
        }

    excl_source = policy.exclusion_source
    return {
        "endpoint_id": endpoint_id,
        "priority": {
            "effective": policy.effective_level,
            "source": priority_source,
            "manual": policy.manual_priority,
            "rule": rule_block,
            "auto": {
                "priority": policy.auto_priority,
                "score": policy.auto_score,
                "breakdown": policy.auto_breakdown,
            },
        },
        "exclusion": {
            "effective": policy.excluded,
            "source": excl_source,
            "rule_id": policy.exclusion_rule_id,
            "rule_pattern": policy.exclusion_rule_pattern,
        },
        "qualification": {
            "qualified": policy.qualified,
            "reason": policy.qualification_reason,
        },
        "safety": {
            "dangerous": policy.dangerous,
            "logout": policy.logout,
        },
        "baseline": {
            "flow_id": policy.baseline_flow_id,
            "status": policy.baseline_status,
        },
        "notes": policy.notes,
        "tags": list(policy.tags),
        # Flat fields retained for show --format json compatibility consumers.
        "effective_level": policy.effective_level,
        "source": policy.source,
        "excluded": policy.excluded,
        "dangerous": policy.dangerous,
        "logout": policy.logout,
        "qualified": policy.qualified,
        "qualification_reason": policy.qualification_reason,
        "baseline_flow_id": policy.baseline_flow_id,
        "baseline_status": policy.baseline_status,
        "manual_priority": policy.manual_priority,
        "matching_rule": policy.matching_rule,
        "auto_score": policy.auto_score,
        "auto_breakdown": policy.auto_breakdown,
        "auto_priority": policy.auto_priority,
    }


def preview_path_rule_impact(
    db_path: Path,
    project_id: str,
    pattern: str,
    *,
    priority: str | None = None,
    excluded: bool | None = None,
) -> dict:
    """
    Purpose:
        Preview which endpoints match a path pattern and how proposed
        priority/exclusion changes would affect them.
        Uses the **same** matcher and effective-policy resolver as live policy.
    Input:
        pattern  — path glob (e.g. /api/admin/*).
        priority — optional proposed priority level for impact stats.
        excluded — optional proposed exclusion (True) for impact stats.
    Output:
        Dict with matching counts, current-state histogram, proposed impact,
        and a sample of affected endpoint identities.
    Side effects: read-only after migrate.
    Raises:
        ValueError on invalid priority.
    """
    if priority is not None:
        level = priority.upper()
        if level not in VALID_LEVELS:
            raise ValueError(
                f"Invalid priority level '{level}'. Valid: {sorted(VALID_LEVELS)}"
            )
        priority = level

    migrate_project_db(db_path)
    if not db_path.exists():
        return {
            "pattern": pattern,
            "matching_count": 0,
            "current": _empty_preview_histogram(),
            "proposed": {
                "priority": priority,
                "excluded": excluded,
                "newly_excluded": 0,
                "already_excluded": 0,
                "priority_changes": 0,
            },
            "endpoints": [],
        }

    with _connect_ro(db_path) as conn:
        rows = conn.execute(
            """
            SELECT e.id, e.method, e.host, e.normalized_path,
                   ep.auto_priority, ep.auto_score, ep.auto_breakdown,
                   ep.manual_priority, ep.excluded, ep.dangerous, ep.logout,
                   ep.qualified, ep.qualification_reason,
                   ep.baseline_flow_id, ep.baseline_status,
                   ep.notes, ep.tags
            FROM endpoints e
            LEFT JOIN endpoint_policy ep ON ep.endpoint_id = e.id
            WHERE e.project_id = ?
            """,
            (project_id,),
        ).fetchall()
        rules = conn.execute(
            """
            SELECT id, pattern, priority, excluded
            FROM policy_rules
            WHERE project_id = ?
            ORDER BY created_at ASC
            """,
            (project_id,),
        ).fetchall()

    current = _empty_preview_histogram()
    matching: list[dict] = []
    newly_excluded = 0
    already_excluded = 0
    priority_changes = 0

    for row in rows:
        path = row["normalized_path"] or ""
        if not _path_matches_pattern(path, pattern):
            continue

        ep_dict = {
            "auto_priority": row["auto_priority"],
            "auto_score": row["auto_score"],
            "auto_breakdown": row["auto_breakdown"] or "{}",
            "manual_priority": row["manual_priority"],
            "excluded": row["excluded"] if row["excluded"] is not None else 0,
            "dangerous": row["dangerous"] if row["dangerous"] is not None else 0,
            "logout": row["logout"] if row["logout"] is not None else 0,
            "qualified": row["qualified"] if row["qualified"] is not None else 0,
            "qualification_reason": row["qualification_reason"],
            "baseline_flow_id": row["baseline_flow_id"],
            "baseline_status": row["baseline_status"],
            "notes": row["notes"] or "",
            "tags": row["tags"] or "[]",
        }
        policy = _resolve_policy(
            endpoint_id=row["id"],
            normalized_path=path,
            ep_row=_DictRow(ep_dict),
            rules=rules,
        )

        current["total"] += 1
        if policy.qualified:
            current["qualified"] += 1
        if policy.excluded:
            current["excluded"] += 1
        level_key = (policy.effective_level or "NORMAL").lower()
        if level_key in current["by_priority"]:
            current["by_priority"][level_key] += 1

        origin, host_display = split_origin_identity(row["host"] or "")
        matching.append({
            "id": row["id"],
            "method": row["method"],
            "origin": origin,
            "host": host_display,
            "path": path,
            "effective_level": policy.effective_level,
            "excluded": policy.excluded,
            "qualified": policy.qualified,
        })

        if excluded is True:
            if policy.excluded:
                already_excluded += 1
            else:
                newly_excluded += 1

        if priority is not None and policy.manual_priority is None:
            # Path rule would apply only when no manual override exists.
            if policy.effective_level != priority:
                # Only count as change when current source is not already this
                # pattern at this priority; still useful as "would become".
                if not (
                    policy.source == "rule"
                    and policy.matching_rule == pattern
                    and policy.effective_level == priority
                ):
                    priority_changes += 1

    return {
        "pattern": pattern,
        "matching_count": len(matching),
        "current": current,
        "proposed": {
            "priority": priority,
            "excluded": excluded,
            "newly_excluded": newly_excluded,
            "already_excluded": already_excluded,
            "priority_changes": priority_changes,
        },
        "endpoints": matching,
    }


def _empty_preview_histogram() -> dict:
    """Zeroed current-state counters for rule preview."""
    return {
        "total": 0,
        "qualified": 0,
        "excluded": 0,
        "by_priority": {
            "critical": 0,
            "high": 0,
            "normal": 0,
            "low": 0,
        },
    }


# ------------------------------------------------------------------ #
# Bulk endpoint mutations (atomic, all-or-nothing)                     #
# ------------------------------------------------------------------ #

class BulkEndpointError(ValueError):
    """Raised when bulk validation fails before any mutation (no partial writes)."""


def dedupe_endpoint_ids(endpoint_ids: list[str]) -> list[str]:
    """
    Purpose:
        Deduplicate endpoint IDs while preserving first-seen order.
    Input:
        endpoint_ids — raw CLI / API list (may contain repeats).
    Output:
        Ordered unique non-empty IDs.
    Side effects: None.
    """
    seen: set[str] = set()
    out: list[str] = []
    for raw in endpoint_ids:
        eid = (raw or "").strip()
        if not eid or eid in seen:
            continue
        seen.add(eid)
        out.append(eid)
    return out


def validate_endpoint_ids_exist(
    db_path: Path,
    endpoint_ids: list[str],
) -> list[dict]:
    """
    Purpose:
        Ensure every requested endpoint UUID exists before bulk mutation.
        Rejects the complete operation if any ID is invalid.
    Input:
        db_path       — project DB.
        endpoint_ids  — already-deduplicated IDs.
    Output:
        List of endpoint rows {id, method, host, normalized_path} in request order.
    Raises:
        BulkEndpointError listing missing IDs.
    Side effects: migrate_project_db.
    """
    ids = dedupe_endpoint_ids(endpoint_ids)
    if not ids:
        raise BulkEndpointError("At least one endpoint ID is required.")

    migrate_project_db(db_path)
    if not db_path.exists():
        raise BulkEndpointError(
            f"Endpoint(s) not found: {', '.join(ids)}"
        )

    with _connect_ro(db_path) as conn:
        placeholders = ",".join("?" for _ in ids)
        rows = conn.execute(
            f"""
            SELECT id, method, host, normalized_path
            FROM endpoints
            WHERE id IN ({placeholders})
            """,
            ids,
        ).fetchall()

    by_id = {r["id"]: dict(r) for r in rows}
    missing = [eid for eid in ids if eid not in by_id]
    if missing:
        raise BulkEndpointError(
            "Endpoint(s) not found: " + ", ".join(missing)
        )
    return [by_id[eid] for eid in ids]


def bulk_set_safety(
    db_path: Path,
    endpoint_ids: list[str],
    *,
    dangerous: bool | None = None,
    logout: bool | None = None,
    clear_all: bool = False,
) -> dict:
    """
    Purpose:
        Atomically set or clear safety flags on many endpoints.
        Validates all IDs first; one transaction; no partial silent mutation.
    Input:
        endpoint_ids — one or more endpoint UUIDs (deduped).
        dangerous / logout — when not None, set that flag to the bool value.
        clear_all — set both dangerous and logout to False (mark --safe).
    Output:
        {affected, unchanged, affected_ids, unchanged_ids, endpoints}
    Side effects: Writes endpoint_policy in one transaction.
    Raises:
        BulkEndpointError when any ID is missing.
    """
    endpoints = validate_endpoint_ids_exist(db_path, endpoint_ids)
    ids = [e["id"] for e in endpoints]
    now = _now_iso()

    with _connect_rw(db_path) as conn:
        affected_ids: list[str] = []
        unchanged_ids: list[str] = []
        for eid in ids:
            row = conn.execute(
                "SELECT dangerous, logout FROM endpoint_policy WHERE endpoint_id = ?",
                (eid,),
            ).fetchone()
            cur_d = bool(row["dangerous"]) if row else False
            cur_l = bool(row["logout"]) if row else False

            if clear_all:
                new_d, new_l = False, False
            else:
                new_d = cur_d if dangerous is None else bool(dangerous)
                new_l = cur_l if logout is None else bool(logout)

            if cur_d == new_d and cur_l == new_l:
                # Already at desired safety state (including default-safe with no row).
                unchanged_ids.append(eid)
                continue

            conn.execute(
                """
                INSERT INTO endpoint_policy
                    (endpoint_id, auto_priority, auto_score, auto_breakdown,
                     manual_priority, excluded, dangerous, logout,
                     notes, tags, updated_at)
                VALUES (?, 'NORMAL', 0, '{}', NULL, 0, ?, ?, '', '[]', ?)
                ON CONFLICT(endpoint_id) DO UPDATE SET
                    dangerous  = excluded.dangerous,
                    logout     = excluded.logout,
                    updated_at = excluded.updated_at
                """,
                (eid, 1 if new_d else 0, 1 if new_l else 0, now),
            )
            conn.execute(
                """
                UPDATE endpoint_policy
                SET dangerous = ?, logout = ?, updated_at = ?
                WHERE endpoint_id = ?
                """,
                (1 if new_d else 0, 1 if new_l else 0, now, eid),
            )
            affected_ids.append(eid)
        conn.commit()

    return _bulk_result(endpoints, affected_ids, unchanged_ids)


def bulk_set_manual_priority(
    db_path: Path,
    endpoint_ids: list[str],
    level: str | None,
) -> dict:
    """
    Purpose:
        Atomically set or clear manual priority on many endpoints.
        level=None clears manual_priority (reverts to auto/rule).
    Output:
        Bulk result dict (affected / unchanged counts and ids).
    Raises:
        BulkEndpointError / ValueError.
    """
    if level is not None:
        level = level.upper()
        if level not in VALID_LEVELS:
            raise ValueError(
                f"Invalid priority level '{level}'. Valid: {sorted(VALID_LEVELS)}"
            )

    endpoints = validate_endpoint_ids_exist(db_path, endpoint_ids)
    ids = [e["id"] for e in endpoints]
    now = _now_iso()

    with _connect_rw(db_path) as conn:
        affected_ids: list[str] = []
        unchanged_ids: list[str] = []
        for eid in ids:
            row = conn.execute(
                "SELECT manual_priority FROM endpoint_policy WHERE endpoint_id = ?",
                (eid,),
            ).fetchone()
            cur = row["manual_priority"] if row else None
            if cur == level:
                # Already at desired state (including both None for clear).
                unchanged_ids.append(eid)
                continue

            if level is None:
                conn.execute(
                    """
                    UPDATE endpoint_policy
                    SET manual_priority = NULL, updated_at = ?
                    WHERE endpoint_id = ?
                    """,
                    (now, eid),
                )
            else:
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
                    (eid, level, now),
                )
                conn.execute(
                    """
                    UPDATE endpoint_policy
                    SET manual_priority = ?, updated_at = ?
                    WHERE endpoint_id = ?
                    """,
                    (level, now, eid),
                )
            affected_ids.append(eid)
        conn.commit()

    return _bulk_result(endpoints, affected_ids, unchanged_ids)


def bulk_set_excluded(
    db_path: Path,
    endpoint_ids: list[str],
    excluded: bool,
) -> dict:
    """
    Purpose:
        Atomically set endpoint-level exclusion on many endpoints.
    Output / Raises: same bulk contract as bulk_set_safety.
    """
    endpoints = validate_endpoint_ids_exist(db_path, endpoint_ids)
    ids = [e["id"] for e in endpoints]
    now = _now_iso()
    val = 1 if excluded else 0

    with _connect_rw(db_path) as conn:
        affected_ids: list[str] = []
        unchanged_ids: list[str] = []
        for eid in ids:
            row = conn.execute(
                "SELECT excluded FROM endpoint_policy WHERE endpoint_id = ?",
                (eid,),
            ).fetchone()
            cur = bool(row["excluded"]) if row else False
            if cur == excluded and (row is not None or not excluded):
                if row is None and not excluded:
                    unchanged_ids.append(eid)
                    continue
                if row is not None and cur == excluded:
                    unchanged_ids.append(eid)
                    continue

            if row is None and not excluded:
                unchanged_ids.append(eid)
                continue

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
                (eid, val, now),
            )
            conn.execute(
                """
                UPDATE endpoint_policy
                SET excluded = ?, updated_at = ?
                WHERE endpoint_id = ?
                """,
                (val, now, eid),
            )
            affected_ids.append(eid)
        conn.commit()

    return _bulk_result(endpoints, affected_ids, unchanged_ids)


def bulk_add_tags(
    db_path: Path,
    endpoint_ids: list[str],
    tags: list[str],
) -> dict:
    """Atomically merge tags onto many endpoints (one transaction)."""
    cleaned = _clean_tag_list(tags)
    if not cleaned:
        raise BulkEndpointError("At least one non-empty tag is required.")

    endpoints = validate_endpoint_ids_exist(db_path, endpoint_ids)
    return _bulk_mutate_tags(db_path, endpoints, mode="add", tags=cleaned)


def bulk_remove_tags(
    db_path: Path,
    endpoint_ids: list[str],
    tags: list[str],
) -> dict:
    """Atomically remove tags from many endpoints."""
    cleaned = _clean_tag_list(tags)
    if not cleaned:
        raise BulkEndpointError("At least one non-empty tag is required.")

    endpoints = validate_endpoint_ids_exist(db_path, endpoint_ids)
    return _bulk_mutate_tags(db_path, endpoints, mode="remove", tags=cleaned)


def bulk_set_tags(
    db_path: Path,
    endpoint_ids: list[str],
    tags: list[str],
) -> dict:
    """Atomically replace the full tag list on many endpoints."""
    cleaned = _clean_tag_list(tags)
    endpoints = validate_endpoint_ids_exist(db_path, endpoint_ids)
    return _bulk_mutate_tags(db_path, endpoints, mode="set", tags=cleaned)


def bulk_clear_tags(
    db_path: Path,
    endpoint_ids: list[str],
) -> dict:
    """Atomically clear all tags on many endpoints."""
    endpoints = validate_endpoint_ids_exist(db_path, endpoint_ids)
    return _bulk_mutate_tags(db_path, endpoints, mode="set", tags=[])


def clean_tag_list(tags: list[str]) -> list[str]:
    """
    Purpose:
        Strip empties and dedupe tags preserving order (public helper for CLI).
    """
    seen: set[str] = set()
    out: list[str] = []
    for raw in tags:
        label = (raw or "").strip()
        if not label or label in seen:
            continue
        seen.add(label)
        out.append(label)
    return out


# Back-compat alias for internal callers.
_clean_tag_list = clean_tag_list


def _bulk_mutate_tags(
    db_path: Path,
    endpoints: list[dict],
    *,
    mode: str,
    tags: list[str],
) -> dict:
    """Shared tag bulk writer (add / remove / set)."""
    ids = [e["id"] for e in endpoints]
    now = _now_iso()
    remove_set = set(tags)

    with _connect_rw(db_path) as conn:
        affected_ids: list[str] = []
        unchanged_ids: list[str] = []
        for eid in ids:
            row = conn.execute(
                "SELECT tags FROM endpoint_policy WHERE endpoint_id = ?",
                (eid,),
            ).fetchone()
            try:
                current = json.loads(row["tags"] if row else "[]") or []
                if not isinstance(current, list):
                    current = []
            except (json.JSONDecodeError, TypeError):
                current = []
            current = [str(t) for t in current]

            if mode == "add":
                seen = set(current)
                merged = list(current)
                for t in tags:
                    if t not in seen:
                        seen.add(t)
                        merged.append(t)
                new_tags = merged
            elif mode == "remove":
                new_tags = [t for t in current if t not in remove_set]
            else:  # set
                new_tags = list(tags)

            if new_tags == current and row is not None:
                unchanged_ids.append(eid)
                continue
            if new_tags == current and row is None and not new_tags:
                unchanged_ids.append(eid)
                continue

            tags_json = json.dumps(new_tags)
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
                (eid, tags_json, now),
            )
            conn.execute(
                "UPDATE endpoint_policy SET tags = ?, updated_at = ? WHERE endpoint_id = ?",
                (tags_json, now, eid),
            )
            affected_ids.append(eid)
        conn.commit()

    return _bulk_result(endpoints, affected_ids, unchanged_ids)


def _bulk_result(
    endpoints: list[dict],
    affected_ids: list[str],
    unchanged_ids: list[str],
) -> dict:
    """
    Purpose:
        Normalize bulk mutation result for CLI table/json output.
    """
    by_id = {e["id"]: e for e in endpoints}
    return {
        "affected": len(affected_ids),
        "unchanged": len(unchanged_ids),
        "affected_ids": affected_ids,
        "unchanged_ids": unchanged_ids,
        "endpoints": [
            {
                "id": e["id"],
                "method": e.get("method"),
                "host": e.get("host"),
                "path": e.get("normalized_path"),
                "status": (
                    "affected" if e["id"] in set(affected_ids) else "unchanged"
                ),
            }
            for e in endpoints
        ],
        "count": len(endpoints),
    }


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
