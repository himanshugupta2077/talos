"""
Module: talos.replay.db

Purpose:
    Data access layer for the replay engine.
    Reads flows and endpoints to supply replay input.
    Writes replayed flows (source=auto_replay) linked to their original.
    Calls migrate_project_db before any read or write to ensure the schema
    is at v7 (replay columns present) on databases created before this feature.

Dependencies: sqlite3, json, pathlib
Data flow:
    replay/engine.py → functions here → project SQLite
Side effects:
    - get_flow_for_replay, get_best_flow_for_endpoint: read-only after migration.
    - insert_replayed_flow: inserts one row into flows.
    - All functions call migrate_project_db(db_path) on entry to handle
      pre-v7 databases transparently.
"""

import json
import sqlite3
from pathlib import Path
from typing import Optional

from talos.projects.db import migrate_project_db


# ------------------------------------------------------------------ #
# Internal helpers                                                     #
# ------------------------------------------------------------------ #

def _connect_rw(db_path: Path) -> sqlite3.Connection:
    """
    Purpose: Open a read-write SQLite connection with row_factory set.
    Input:   db_path — absolute Path to the project's talos.db.
    Output:  sqlite3.Connection. Caller is responsible for closing.
    Side effects: Opens file descriptor.
    """
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    return conn


def _connect_ro(db_path: Path) -> sqlite3.Connection:
    """
    Purpose: Open a read-only SQLite connection with row_factory set.
    Input:   db_path — absolute Path to the project's talos.db.
    Output:  sqlite3.Connection (read-only URI mode). Caller must close.
    Side effects: Opens file descriptor.
    """
    uri = f"file:{db_path}?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    conn.row_factory = sqlite3.Row
    return conn


# ------------------------------------------------------------------ #
# Read operations                                                      #
# ------------------------------------------------------------------ #

def get_flow_for_replay(db_path: Path, flow_id: str) -> Optional[dict]:
    """
    Purpose:
        Fetch all fields needed to reconstruct and replay a stored flow.
    Input:
        db_path — absolute Path to the project's talos.db.
        flow_id — UUID string of the target flow.
    Output:
        Full flow dict, or None if the flow does not exist.
    Side effects:
        Calls migrate_project_db to ensure replay columns exist.
    """
    migrate_project_db(db_path)
    if not db_path.exists():
        return None
    with _connect_ro(db_path) as conn:
        row = conn.execute(
            """
            SELECT id, method, url, host, path, query,
                   request_headers, request_cookies,
                   request_body, request_body_truncated,
                   status_code, response_body, response_headers, content_type,
                   endpoint_id, role_id, module_id,
                   source, captured_at
            FROM flows
            WHERE id = ?
            """,
            (flow_id,),
        ).fetchone()
    return dict(row) if row else None


def get_best_flow_for_endpoint(db_path: Path, endpoint_id: str) -> Optional[dict]:
    """
    Purpose:
        Select the best qualifying flow for an endpoint to use as a replay
        baseline.  Qualifying means: proxy_capture source AND 2xx status code.

        Fast path: reads endpoint_policy.baseline_flow_id (pre-computed by
        FlowWorker on each qualifying proxy_capture flow).  When the field is
        set and the referenced flow still exists and qualifies, returns that
        flow directly (O(1) lookup).

        Fallback: if the pre-computed baseline is absent or its flow was removed,
        falls back to a full scan ordered by captured_at DESC.

    Input:
        db_path     — absolute Path to the project's talos.db.
        endpoint_id — UUID string of the target endpoint.
    Output:
        Flow dict with all fields needed for replay, or None when no qualifying
        flow exists for this endpoint.
    Side effects:
        Calls migrate_project_db to ensure replay columns exist.

    Selection criterion:
        source = 'proxy_capture' AND status_code BETWEEN 200 AND 299.
        Most recent (captured_at DESC) when baseline_flow_id is not available.
    """
    migrate_project_db(db_path)
    if not db_path.exists():
        return None

    _FLOW_COLS = """
        id, method, url, host, path, query,
        request_headers, request_cookies,
        request_body, request_body_truncated,
        status_code, endpoint_id, role_id, module_id, source
    """

    with _connect_ro(db_path) as conn:
        # Fast path: use pre-computed baseline_flow_id from endpoint_policy.
        policy_row = conn.execute(
            "SELECT baseline_flow_id FROM endpoint_policy WHERE endpoint_id = ?",
            (endpoint_id,),
        ).fetchone()

        if policy_row and policy_row["baseline_flow_id"]:
            row = conn.execute(
                f"""
                SELECT {_FLOW_COLS}
                FROM flows
                WHERE id = ?
                  AND source = 'proxy_capture'
                  AND status_code BETWEEN 200 AND 299
                """,
                (policy_row["baseline_flow_id"],),
            ).fetchone()
            if row:
                return dict(row)

        # Fallback: scan all flows for this endpoint ordered by recency.
        row = conn.execute(
            f"""
            SELECT {_FLOW_COLS}
            FROM flows
            WHERE endpoint_id = ?
              AND status_code BETWEEN 200 AND 299
              AND source = 'proxy_capture'
            ORDER BY captured_at DESC
            LIMIT 1
            """,
            (endpoint_id,),
        ).fetchone()
        return dict(row) if row else None


def get_endpoint_by_id(db_path: Path, endpoint_id: str) -> Optional[dict]:
    """
    Purpose:
        Fetch a single endpoint record for display in CLI feedback.
    Input:
        db_path     — absolute Path to the project's talos.db.
        endpoint_id — UUID string.
    Output:
        Endpoint dict, or None if not found.
    Side effects: None (read-only; assumes migration already done by caller).
    """
    if not db_path.exists():
        return None
    with _connect_ro(db_path) as conn:
        row = conn.execute(
            "SELECT id, method, host, normalized_path FROM endpoints WHERE id = ?",
            (endpoint_id,),
        ).fetchone()
    return dict(row) if row else None


# ------------------------------------------------------------------ #
# Write operations                                                     #
# ------------------------------------------------------------------ #

def insert_replayed_flow(db_path: Path, flow: dict) -> None:
    """
    Purpose:
        Persist a replayed flow to the flows table.
        The flow dict must already carry source='auto_replay', original_flow_id,
        and all request/response fields.  This function performs no validation
        beyond structural — caller (engine.py) owns correctness.
    Input:
        db_path — absolute Path to the project's talos.db.
        flow    — dict with all fields for the flows INSERT (see columns below).
    Output:
        None
    Side effects:
        Inserts one row into flows.
        After successful INSERT: best-effort cross-flow index/scan via
        on_flow_committed (non-fatal; multiprobe canaries + sink GET responses).
        Raises sqlite3.Error on DB write failure — caller handles.

    Columns written:
        id, project_id, captured_at, response_end, method, url, host, path,
        query, request_headers, request_cookies, request_body,
        request_body_truncated, status_code, response_headers, response_body,
        response_body_truncated, content_type, session_id, endpoint_id,
        role_id, module_id, tags, source, original_flow_id, replay_error,
        replay_reason, flow_meta
    """
    with _connect_rw(db_path) as conn:
        conn.execute(
            """
            INSERT INTO flows (
                id, project_id, captured_at, response_end,
                method, url, host, path, query,
                request_headers, request_cookies,
                request_body, request_body_truncated,
                status_code,
                response_headers, response_body, response_body_truncated,
                content_type, session_id, endpoint_id,
                role_id, module_id, tags,
                source, original_flow_id, replay_error, replay_reason, flow_meta
            ) VALUES (
                ?, ?, ?, ?,
                ?, ?, ?, ?, ?,
                ?, ?,
                ?, ?,
                ?,
                ?, ?, ?,
                ?, ?, ?,
                ?, ?, ?,
                ?, ?, ?, ?, ?
            )
            """,
            (
                flow["id"],
                flow["project_id"],
                flow["captured_at"],
                flow.get("response_end"),
                flow["method"],
                flow["url"],
                flow["host"],
                flow["path"],
                flow.get("query", ""),
                # Ensure headers/cookies are stored as JSON strings.
                _to_json(flow.get("request_headers", {})),
                _to_json(flow.get("request_cookies", {})),
                flow.get("request_body"),           # BLOB or None
                1 if flow.get("request_body_truncated") else 0,
                flow.get("status_code"),            # None on connection failure
                _to_json(flow.get("response_headers", {})),
                flow.get("response_body"),          # BLOB or None
                1 if flow.get("response_body_truncated") else 0,
                flow.get("content_type", ""),
                None,                               # session_id: not resolved for replays
                flow.get("endpoint_id"),
                flow["role_id"],
                flow["module_id"],
                "[]",                               # tags: empty for replay flows
                flow["source"],
                flow["original_flow_id"],
                flow.get("replay_error"),
                flow.get("replay_reason"),
                _to_json(flow.get("flow_meta") or {}),
            ),
        )
        conn.commit()

        # Cross-flow reflection (PR3b): index multiprobe canaries + scan sinks.
        # Non-fatal — flow is already committed. Uses process-cached config only
        # (never ConfigurationManager.load per insert).
        try:
            _maybe_cross_flow_on_replay(conn, db_path, flow)
            conn.commit()
        except Exception:  # noqa: BLE001
            conn.rollback()
            import logging
            logging.getLogger(__name__).debug(
                "Cross-flow reflection on replay failed — flow_id=%s — skipping",
                flow.get("id"),
                exc_info=True,
            )

    # Error Intelligence (Phase 6): cheap gate + inline scan when no proxy
    # worker queue is available (scheduler / IV / BAC / unauth path).
    # Non-fatal — never fails the replay insert.
    try:
        _maybe_error_intel_on_replay(db_path, flow)
    except Exception:  # noqa: BLE001
        import logging
        logging.getLogger(__name__).debug(
            "Error intel on replay failed — flow_id=%s — skipping",
            flow.get("id"),
            exc_info=True,
        )


def _maybe_error_intel_on_replay(db_path: Path, flow: dict) -> None:
    """
    Purpose:
        Best-effort Error Intelligence scan after a successfully inserted
        replay / attack flow. Uses inline process (no proxy ErrorIntelQueue
        in the scheduler process). Attack context is taken from flow_meta
        (IV parameter_uuid, BAC attack_module, …).
    Side effects:
        May write error_clusters / error_observations. Never raises.
    """
    from talos.error_intel.worker import maybe_enqueue_error_scan

    project_id = flow.get("project_id") or ""
    if not project_id:
        return
    content_type = flow.get("content_type") or ""
    # Ensure id is available as flow_id for the enqueue helper.
    enriched = dict(flow)
    if not enriched.get("flow_id") and enriched.get("id"):
        enriched["flow_id"] = enriched["id"]
    maybe_enqueue_error_scan(
        error_queue=None,
        db_path=db_path,
        project_id=str(project_id),
        flow=enriched,
        endpoint_id=flow.get("endpoint_id"),
        content_type=str(content_type),
        inline_if_no_queue=True,
    )


def _maybe_cross_flow_on_replay(
    conn: sqlite3.Connection,
    db_path: Path,
    flow: dict,
) -> None:
    """
    Purpose:
        Best-effort on_flow_committed for a successfully inserted replay flow.
        Re-extracts params when possible; always tries multiprobe meta canary.
    Side effects:
        May write value_index / cross_flow_reflections / parameters flags.
    """
    from talos.projects.value_reflection import (
        ensure_process_cross_flow_config,
        on_flow_committed,
    )

    # Load layered config at most once per process (scheduler has no FlowWorker).
    cfg = ensure_process_cross_flow_config(db_path.parent)
    if not cfg.enabled:
        return

    endpoint_id = flow.get("endpoint_id")
    if not endpoint_id:
        return

    # Best-effort param re-extract from the replay request.
    params = None
    try:
        from talos.projects.parameters import extract_flow_params

        raw_headers = flow.get("request_headers") or {}
        if isinstance(raw_headers, str):
            raw_headers = json.loads(raw_headers) if raw_headers else {}
        raw_cookies = flow.get("request_cookies") or {}
        if isinstance(raw_cookies, str):
            raw_cookies = json.loads(raw_cookies) if raw_cookies else {}

        # Prefer normalized_path from endpoint when available.
        ep_path = ""
        row = conn.execute(
            "SELECT normalized_path FROM endpoints WHERE id = ?",
            (endpoint_id,),
        ).fetchone()
        if row is not None:
            ep_path = row[0] if not isinstance(row, sqlite3.Row) else row["normalized_path"]

        params = extract_flow_params(
            query=flow.get("query") or "",
            request_body=flow.get("request_body"),
            request_headers=raw_headers if isinstance(raw_headers, dict) else {},
            request_cookies=raw_cookies if isinstance(raw_cookies, dict) else {},
            path=flow.get("path") or "",
            normalized_path=ep_path or "",
            role_id=flow.get("role_id") or "",
            module_id=flow.get("module_id") or "",
        )
    except Exception:  # noqa: BLE001
        params = None

    flow_meta = flow.get("flow_meta") or {}
    if isinstance(flow_meta, str):
        try:
            flow_meta = json.loads(flow_meta) if flow_meta else {}
        except (ValueError, TypeError):
            flow_meta = {}

    multiprobe_meta = None
    if isinstance(flow_meta, dict):
        multiprobe_meta = flow_meta.get("multiprobe")
        if multiprobe_meta is not None and not isinstance(multiprobe_meta, dict):
            multiprobe_meta = None

    on_flow_committed(
        conn,
        db_path=db_path,
        flow=flow,
        endpoint_id=endpoint_id,
        params=params,
        multiprobe_meta=multiprobe_meta if isinstance(multiprobe_meta, dict) else None,
        cfg=cfg,
    )


def _to_json(value: object) -> str:
    """
    Purpose:
        Ensure a value is a JSON string for storage in a TEXT column.
        Already-serialised strings are returned as-is to avoid double-encoding.
    Input:   value — dict or already-serialised JSON string.
    Output:  JSON string.
    Side effects: None.
    """
    if isinstance(value, str):
        return value
    return json.dumps(value)


def get_flow_meta(db_path: Path, flow_id: str) -> dict:
    """
    Purpose:
        Read the flow_meta JSON for a single flow.
    Input:
        db_path — Path to the project's talos.db.
        flow_id — UUID of the target flow.
    Output:
        Parsed dict; empty dict when the flow has no meta or does not exist.
    Side effects: Read-only.
    """
    if not db_path.exists():
        return {}
    with _connect_ro(db_path) as conn:
        row = conn.execute(
            "SELECT flow_meta FROM flows WHERE id = ?", (flow_id,)
        ).fetchone()
    if row is None:
        return {}
    try:
        return json.loads(row[0]) if row[0] else {}
    except (ValueError, TypeError):
        return {}
    if isinstance(value, str):
        return value
    return json.dumps(value)


# ------------------------------------------------------------------ #
# Diff operations                                                      #
# ------------------------------------------------------------------ #

def insert_replay_diff(db_path: Path, diff_row: dict) -> None:
    """
    Purpose:
        Persist a diff result to the replay_diffs table.
        Called immediately after insert_replayed_flow in the engine.
    Input:
        db_path  — absolute Path to the project's talos.db.
        diff_row — dict with keys:
                     replay_flow_id   (str)          — PK; UUID of the replay flow.
                     original_flow_id (str)          — UUID of the source flow.
                     verdict          (str)          — SAME | DIFFERENT | ERROR.
                     status_changed   (bool/int)     — 1 or 0.
                     status_diff      (str or None)  — e.g. "200→403" or NULL.
                     length_diff      (int)          — signed byte delta.
    Output: None
    Side effects:
        Inserts one row into replay_diffs.
        Raises sqlite3.Error on write failure — caller handles.
    """
    with _connect_rw(db_path) as conn:
        conn.execute(
            """
            INSERT INTO replay_diffs (
                replay_flow_id, original_flow_id,
                verdict, status_changed, status_diff, length_diff
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                diff_row["replay_flow_id"],
                diff_row["original_flow_id"],
                diff_row["verdict"],
                1 if diff_row["status_changed"] else 0,
                diff_row.get("status_diff"),
                diff_row["length_diff"],
            ),
        )
        conn.commit()


def insert_auth_test_result(db_path: Path, result_row: dict) -> None:
    """
    Purpose:
        Persist an auth-bypass test verdict to the auth_test_results table.
        Called immediately after insert_replay_diff in auth_strip._execute_stripped_replay.
    Input:
        db_path    — absolute Path to the project's talos.db.
        result_row — dict with keys:
                       replay_flow_id   (str) — PK; UUID of the auth-test replay flow.
                       original_flow_id (str) — UUID of the source flow.
                       verdict          (str) — SECURE | BYPASS | UNKNOWN.
    Output: None
    Side effects:
        Inserts one row into auth_test_results.
        Raises sqlite3.Error on write failure — caller handles.
    """
    with _connect_rw(db_path) as conn:
        conn.execute(
            """
            INSERT INTO auth_test_results (
                replay_flow_id, original_flow_id, verdict
            ) VALUES (?, ?, ?)
            """,
            (
                result_row["replay_flow_id"],
                result_row["original_flow_id"],
                result_row["verdict"],
            ),
        )
        conn.commit()


def insert_bac_result(db_path: Path, result_row: dict) -> None:
    """
    Purpose:
        Persist a BAC attack verdict to the bac_results table.
        Called immediately after insert_replay_diff in bac.engine._send_and_store.
    Input:
        db_path    — absolute Path to the project's talos.db.
        result_row — dict with keys:
                       replay_flow_id   (str)       — PK; UUID of the BAC replay flow.
                       original_flow_id (str)       — UUID of the target-role source flow.
                       attack_type      (str)       — BAC job type constant.
                       variant          (str)       — mutation variant name.
                       attacker_role_id (str)       — UUID of the role performing the attack.
                       target_role_id   (str)       — UUID of the role with legitimate access.
                       module_id        (str)       — UUID of the module under test.
                       verdict          (str)       — POSSIBLE_BAC | SECURE | UNKNOWN.
                       matched_section  (str|None)  — 'passed_detection' | 'failed_detection' | None.
                       matched_group    (str|None)  — group_id or auto-label; None when heuristic.
                       matched_rules    (str|None)  — JSON array of rule description strings.
    Output: None
    Side effects:
        Inserts one row into bac_results.
        Raises sqlite3.Error on write failure — caller handles.
    """
    with _connect_rw(db_path) as conn:
        conn.execute(
            """
            INSERT INTO bac_results (
                replay_flow_id, original_flow_id,
                attack_type, variant,
                attacker_role_id, target_role_id, module_id,
                verdict, matched_section, matched_group, matched_rules
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                result_row["replay_flow_id"],
                result_row["original_flow_id"],
                result_row["attack_type"],
                result_row["variant"],
                result_row["attacker_role_id"],
                result_row["target_role_id"],
                result_row["module_id"],
                result_row["verdict"],
                result_row.get("matched_section"),
                result_row.get("matched_group"),
                result_row.get("matched_rules"),
            ),
        )
        conn.commit()


def insert_bac_result_v2(db_path: Path, result_row: dict) -> None:
    """
    Purpose:
        Persist a BAC attack verdict to the bac_results table with
        mutation_family and mutation fields for richer reporting.
    Input:
        db_path    — absolute Path to the project's talos.db.
        result_row — dict with all bac_results columns plus:
                       mutation_family (str|None) — high-level family (e.g. 'method-fuzz').
                       mutation        (str|None) — specific label (e.g. 'GET→POST').
    Output: None
    Side effects:
        Inserts one row into bac_results.
        Raises sqlite3.Error on write failure — caller handles.
    """
    with _connect_rw(db_path) as conn:
        conn.execute(
            """
            INSERT INTO bac_results (
                replay_flow_id, original_flow_id,
                attack_type, variant, mutation_family, mutation,
                attacker_role_id, target_role_id, module_id,
                verdict, matched_section, matched_group, matched_rules
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                result_row["replay_flow_id"],
                result_row["original_flow_id"],
                result_row["attack_type"],
                result_row["variant"],
                result_row.get("mutation_family"),
                result_row.get("mutation"),
                result_row["attacker_role_id"],
                result_row["target_role_id"],
                result_row["module_id"],
                result_row["verdict"],
                result_row.get("matched_section"),
                result_row.get("matched_group"),
                result_row.get("matched_rules"),
            ),
        )
        conn.commit()


def insert_unauth_result(db_path: Path, result_row: dict) -> None:
    """
    Purpose:
        Persist an unauth attack verdict to the unauth_results table.
        Called from unauth.engine after each replay+decision.
    Input:
        db_path    — absolute Path to the project's talos.db.
        result_row — dict with keys:
                       replay_flow_id          (str)      — PK; UUID of the replay flow.
                       original_flow_id        (str)      — UUID of the source flow.
                       endpoint_id             (str|None) — UUID of the endpoint under test.
                       auth_mutation_family    (str)      — e.g. 'remove-auth'.
                       auth_mutation           (str)      — e.g. 'remove_authorization_header'.
                       request_mutation_family (str|None) — e.g. 'method-fuzz'; None for baseline.
                       request_mutation        (str|None) — e.g. 'X-HTTP-Method-Override:GET'; None.
                       verdict                 (str)      — BYPASS | SECURE | UNKNOWN.
                       matched_section  (str|None)  — 'passed_detection' | 'failed_detection'.
                       matched_group    (str|None)  — group_id or label; None when heuristic.
                       matched_rules    (str|None)  — JSON array of matched rule descriptions.
    Output: None
    Side effects:
        Inserts one row into unauth_results.
        Raises sqlite3.Error on write failure — caller handles.
    """
    with _connect_rw(db_path) as conn:
        conn.execute(
            """
            INSERT INTO unauth_results (
                replay_flow_id, original_flow_id, endpoint_id,
                auth_mutation_family, auth_mutation,
                request_mutation_family, request_mutation,
                verdict, matched_section, matched_group, matched_rules
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                result_row["replay_flow_id"],
                result_row["original_flow_id"],
                result_row.get("endpoint_id"),
                result_row["auth_mutation_family"],
                result_row["auth_mutation"],
                result_row.get("request_mutation_family"),
                result_row.get("request_mutation"),
                result_row["verdict"],
                result_row.get("matched_section"),
                result_row.get("matched_group"),
                result_row.get("matched_rules"),
            ),
        )
        conn.commit()


def list_unauth_results(db_path: Path) -> list[dict]:
    """
    Purpose:
        Return all unauth_results rows (for offline reclassification).
    Input:
        db_path — absolute Path to the project's talos.db.
    Output:
        List of result dicts (may be empty).
    Side effects:
        Read-only after migrate.
    """
    migrate_project_db(db_path)
    if not db_path.exists():
        return []
    with _connect_ro(db_path) as conn:
        rows = conn.execute("SELECT * FROM unauth_results").fetchall()
    return [dict(r) for r in rows]


def update_unauth_result_verdict(
    db_path: Path,
    replay_flow_id: str,
    *,
    verdict: str,
    matched_section: Optional[str] = None,
    matched_group: Optional[str] = None,
    matched_rules: Optional[str] = None,
) -> bool:
    """
    Purpose:
        Rewrite the decision-filter verdict and match metadata on an existing
        unauth_results row (used by offline filter apply / reclassify).
    Input:
        db_path         — absolute Path to the project's talos.db.
        replay_flow_id  — PK of the unauth_results row.
        verdict         — BYPASS | SECURE | UNKNOWN.
        matched_section — 'passed_detection' | 'failed_detection' | None.
        matched_group   — group_id or None.
        matched_rules   — JSON array string of rule IDs, or None.
    Output:
        True if a row was updated; False if replay_flow_id not found.
    Side effects:
        Updates unauth_results; commits.
    """
    migrate_project_db(db_path)
    with _connect_rw(db_path) as conn:
        cur = conn.execute(
            """
            UPDATE unauth_results
            SET verdict = ?,
                matched_section = ?,
                matched_group = ?,
                matched_rules = ?
            WHERE replay_flow_id = ?
            """,
            (
                verdict,
                matched_section,
                matched_group,
                matched_rules,
                replay_flow_id,
            ),
        )
        conn.commit()
    return cur.rowcount > 0


def list_bac_results(db_path: Path) -> list[dict]:
    """
    Purpose:
        Return all bac_results rows (for offline reclassification).
    Input:
        db_path — absolute Path to the project's talos.db.
    Output:
        List of result dicts (may be empty).
    Side effects:
        Read-only after migrate.
    """
    migrate_project_db(db_path)
    if not db_path.exists():
        return []
    with _connect_ro(db_path) as conn:
        rows = conn.execute("SELECT * FROM bac_results").fetchall()
    return [dict(r) for r in rows]


def update_bac_result_verdict(
    db_path: Path,
    replay_flow_id: str,
    *,
    verdict: str,
    matched_section: Optional[str] = None,
    matched_group: Optional[str] = None,
    matched_rules: Optional[str] = None,
) -> bool:
    """
    Purpose:
        Rewrite the decision-filter verdict and match metadata on an existing
        bac_results row (used by offline filter apply / reclassify).
    Input:
        db_path         — absolute Path to the project's talos.db.
        replay_flow_id  — PK of the bac_results row.
        verdict         — POSSIBLE_BAC | SECURE | UNKNOWN.
        matched_section — 'passed_detection' | 'failed_detection' | None.
        matched_group   — group_id or None.
        matched_rules   — JSON array string of rule descriptions, or None.
    Output:
        True if a row was updated; False if replay_flow_id not found.
    Side effects:
        Updates bac_results; commits.
    """
    migrate_project_db(db_path)
    with _connect_rw(db_path) as conn:
        cur = conn.execute(
            """
            UPDATE bac_results
            SET verdict = ?,
                matched_section = ?,
                matched_group = ?,
                matched_rules = ?
            WHERE replay_flow_id = ?
            """,
            (
                verdict,
                matched_section,
                matched_group,
                matched_rules,
                replay_flow_id,
            ),
        )
        conn.commit()
    return cur.rowcount > 0
