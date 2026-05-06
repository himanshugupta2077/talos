"""
Module: talos.worker.worker

Purpose:
    Drains the flow queue and persists every valid flow to two stores:
      1. Project SQLite database (structured truth).
      2. Per-day JSONL archive file (ground truth / replay source).

    Runs as a daemon thread started by the proxy addon at session startup
    and stopped when the addon signals done().

Architecture:
    FlowQueue → FlowWorker._run() loop → _validate_flow()
                                       → _persist_db()
                                           ↳ normalize path/query (pure; failure → NULL endpoint_id)
                                           ↳ upsert endpoint (failure → rollback, NULL endpoint_id)
                                           ↳ insert flow (endpoint_id may be NULL on normalization error)
                                           ↳ upsert endpoint_roles (skipped when endpoint_id is NULL)
                                           ↳ commit
                                           ↳ extract + upsert parameters (skipped on NULL endpoint_id; failure → rollback param writes only)
                                       → _persist_archive()

Design decisions:
    - project_id is attached here, never inside the proxy thread.
    - role_id and module_id are resolved by the addon at proxy start and carried
      in the flow dict — the worker persists them as-is. The worker never infers
      or defaults role/module; a flow missing either is dropped.
        - Every persisted flow is normalized into a stable endpoint identity using
            (method, host, normalized_path).
        - endpoint_roles is updated in the same transaction as the flow insert so
            access views do not drift from normalized endpoint state.
    - Worker fetches the active project once at construction time.
    - Queue is drained on shutdown so no captured flows are silently lost.
    - Archive rolls to a new file at UTC midnight (one file per day).
    - DB connection is opened per-insert; SQLite WAL handles concurrent readers.

Dependencies:
    sqlite3, json, base64, threading, time, logging, pathlib, datetime
        talos.projects.endpoints, talos.projects.model, talos.proxy.queue,
        talos.projects.outscope, talos.proxy.scope
Data flow:
    FlowQueue.get() → flow dict → attach project_id → validate
                                     → out-of-scope safety check
                                     → normalize path/query → upsert endpoint + endpoint_roles
                                     → INSERT INTO flows (db) → append to flows-YYYY-MM-DD.jsonl (archive)
Side effects:
    - Writes to project SQLite database.
    - Creates/appends to JSONL archive files under <data_dir>/archive/.
    - Logs dropped (invalid) flows at WARNING level.
"""

import base64
import json
import logging
import sqlite3
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import IO, Optional

from talos.projects.endpoints import NormalizedFlowURL, normalize_flow_url
from talos.projects.model import Project
from talos.projects.outscope import load_domain_set
from talos.projects.parameters import extract_flow_params, upsert_endpoint_params
from talos.proxy.queue import FlowQueue
from talos.proxy.scope import is_out_of_scope

logger = logging.getLogger(__name__)

# DB write retry: 2 attempts total (1 retry) with a short delay between them.
# Handles transient lock contention under WAL; does not retry integrity violations.
_DB_RETRY_ATTEMPTS: int = 2
_DB_RETRY_DELAY: float = 0.1  # seconds

# Emit a rolling stats log line every N seconds while the worker is active.
_STATS_LOG_INTERVAL: float = 30.0


class FlowWorker:
    """
    Purpose:
        Consume flows from the queue and persist them to DB + archive.
        One instance per proxy session, bound to the active project.

    Fields:
        _project        — Active project supplying db_path and archive_dir.
        _queue          — Shared FlowQueue drained by this worker.
        _blocked_domains — Frozenset of out-of-scope domain strings; loaded once at
                            init as a safety backstop — the proxy addon is the primary
                            enforcement point.
        _stop_event     — Set to signal the run loop to exit cleanly.
        _thread         — Daemon thread running _run().
        _archive_date   — UTC date string of the currently open archive file.
        _archive_handle — Open file handle for the current archive file.
        _last_stats_at  — Monotonic timestamp of the last stats log line.
        processed_count — Flows successfully persisted to DB (and attempted archive).
        dropped_count   — Flows rejected by validation or queue corruption checks.
        db_error_count  — DB writes that failed after all retry attempts.

    Invariant:
        Only one FlowWorker should be active per FlowQueue at a time.
        start() must be called before any flows are enqueued to avoid drops.
    """

    def __init__(self, project: Project, queue: FlowQueue) -> None:
        # Why store project, not just paths: may need project metadata later
        # without reloading from registry.
        self._project = project
        self._queue = queue
        self._stop_event = threading.Event()
        self._thread = threading.Thread(
            target=self._run,
            daemon=True,
            name="talos-worker",
        )
        # Load out-of-scope domains once at worker startup as a safety backstop.
        # The proxy addon is the primary enforcement point; this guard catches
        # any flow that slips through (e.g. races at startup or direct queue
        # injection in tests).
        self._blocked_domains: frozenset[str] = load_domain_set(project.db_path)
        # Archive file state — managed by _persist_archive(); None when not yet opened.
        self._archive_date: Optional[str] = None

        self._archive_handle: Optional[IO[str]] = None

        # Observability counters — read directly by CLI stats callers.
        self.processed_count: int = 0
        self.dropped_count: int = 0
        self.db_error_count: int = 0
        # Tracks when the last rolling stats line was emitted.
        self._last_stats_at: float = time.monotonic()

    def start(self) -> None:
        """
        Purpose:
            Start the worker daemon thread.
        Side effects:
            - Spawns a new thread.
            - Logs start at INFO.
        """
        self._thread.start()
        logger.info(
            "FlowWorker started — project=%s db=%s",
            self._project.id,
            self._project.db_path,
        )

    def stop(self, timeout: float = 5.0) -> None:
        """
        Purpose:
            Signal the worker to stop and wait for it to drain the queue
            and exit cleanly.
        Input:
            timeout — seconds to wait for the thread to join before giving up.
        Side effects:
            - Sets the stop event (causes _run loop to begin shutdown).
            - Joins the worker thread up to timeout seconds.
            - Closes the open archive file handle.
        """
        self._stop_event.set()
        self._thread.join(timeout=timeout)
        self._close_archive()
        logger.info(
            "FlowWorker stopped — project=%s processed=%d dropped=%d "
            "db_errors=%d queue_drops=%d",
            self._project.id,
            self.processed_count,
            self.dropped_count,
            self.db_error_count,
            self._queue.dropped_flow_count,
        )

    # ------------------------------------------------------------------ #
    # Internal run loop                                                    #
    # ------------------------------------------------------------------ #

    def _run(self) -> None:
        """
        Purpose:
            Main loop — dequeue and process flows until stop is signalled,
            then drain any remaining items before exiting.
        Side effects:
            - Calls _process() for each dequeued flow.
        """
        # Active phase: run until stop is requested.
        while not self._stop_event.is_set():
            flow = self._queue.get(timeout=0.2)
            if flow is None:
                # Timeout with no item — check stop_event and loop.
                self._maybe_log_stats()
                continue
            # Outer guard: never let _process crash the loop regardless of cause.
            try:
                self._process(flow)
            except Exception:
                logger.exception(
                    "Unexpected error in _process — worker loop continuing"
                )
            self._maybe_log_stats()

        # Drain phase: consume everything left in the queue before exiting.
        # Why: stop() is called after mitmdump exits; any flows captured in the
        # final seconds must not be silently discarded.
        while True:
            flow = self._queue.get(timeout=0)
            if flow is None:
                break
            try:
                self._process(flow)
            except Exception:
                logger.exception(
                    "Unexpected error in _process during drain — skipping"
                )

    def _process(self, flow: dict) -> None:
        """
        Purpose:
            Validate a raw flow dict, attach project context, and persist it.
        Input:
            flow — raw dict produced by the proxy addon.
        Side effects:
            - Mutates a copy of flow to add project_id.
            - Writes to DB and archive on success.
            - Logs WARNING and increments dropped_count on validation failure.
            - Retries DB write up to _DB_RETRY_ATTEMPTS times; logs ERROR and
              increments db_error_count if all attempts fail — flow is dropped.
            - Archive failure logs ERROR and continues; does not affect processed_count.
        """
        # Guard against queue corruption: entry must be a dict.
        if not isinstance(flow, dict):
            logger.warning(
                "Dropping corrupt queue entry — expected dict, got %s",
                type(flow).__name__,
            )
            self.dropped_count += 1
            return

        if not _validate_flow(flow):
            logger.warning(
                "Dropping invalid flow — flow_id=%s host=%s method=%s status=%s",
                flow.get("flow_id", "?"),
                flow.get("host", "?"),
                flow.get("method", "?"),
                flow.get("status_code", "?"),
            )
            self.dropped_count += 1
            return

        # Out-of-scope safety backstop — covers any flow that bypassed the proxy
        # addon's primary enforcement check (e.g. startup races, test injection).
        if is_out_of_scope(flow.get("host", ""), self._blocked_domains):
            logger.warning(
                "Dropping out-of-scope flow (worker backstop) — flow_id=%s host=%s",
                flow.get("flow_id", "?"),
                flow.get("host", "?"),
            )
            self.dropped_count += 1
            return

        # Attach project context. role_id and module_id arrive from the addon;
        # the worker never resolves or defaults them.
        enriched = {
            **flow,
            "project_id": self._project.id,
        }

        # DB write with retry — handles transient lock contention under WAL.
        # Does not retry sqlite3.IntegrityError (duplicate key) — those are bugs.
        persisted = False
        for attempt in range(1, _DB_RETRY_ATTEMPTS + 1):
            try:
                _persist_db(enriched, self._project.db_path)
                persisted = True
                break
            except sqlite3.IntegrityError:
                # Duplicate flow_id — not a transient failure; retrying won't help.
                logger.error(
                    "DB integrity error — duplicate flow_id=%s — dropping",
                    enriched.get("flow_id"),
                )
                self.db_error_count += 1
                return
            except sqlite3.Error as exc:
                if attempt < _DB_RETRY_ATTEMPTS:
                    logger.warning(
                        "DB write failed (attempt %d/%d) — flow_id=%s — %s — retrying",
                        attempt,
                        _DB_RETRY_ATTEMPTS,
                        enriched.get("flow_id"),
                        exc,
                    )
                    time.sleep(_DB_RETRY_DELAY)
                else:
                    logger.error(
                        "DB write failed after %d attempts — dropping flow_id=%s",
                        _DB_RETRY_ATTEMPTS,
                        enriched.get("flow_id"),
                        exc_info=True,
                    )
                    self.db_error_count += 1

        if not persisted:
            # Do not write archive for a flow with no DB record; stores must stay
            # consistent (archive is ground truth, not a retry queue).
            return

        # Archive failure is non-fatal: DB is the authoritative store.
        try:
            self._persist_archive(enriched)
        except Exception:
            logger.exception(
                "Archive write failed — flow_id=%s — continuing",
                enriched.get("flow_id"),
            )

        self.processed_count += 1

    # ------------------------------------------------------------------ #
    # Archive persistence                                                  #
    # ------------------------------------------------------------------ #

    def _persist_archive(self, flow: dict) -> None:
        """
        Purpose:
            Append the flow as a single JSON line to the current day's archive file.
            Rotates to a new file at UTC midnight.
        Input:
            flow — enriched flow dict with project_id attached.
        Side effects:
            - Creates archive directory if absent.
            - Opens a new file handle when the date rolls over.
            - Writes one JSON line per call, flushed immediately.
        """
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

        if today != self._archive_date:
            self._close_archive()
            archive_path = self._project.archive_dir / f"flows-{today}.jsonl"
            archive_path.parent.mkdir(parents=True, exist_ok=True)
            # Append mode — safe to restart the worker mid-day without losing data.
            self._archive_handle = open(  # noqa: WPS515
                archive_path, "a", encoding="utf-8"
            )
            self._archive_date = today

        self._archive_handle.write(_flow_to_jsonl(flow) + "\n")  # type: ignore[union-attr]
        self._archive_handle.flush()  # type: ignore[union-attr]

    def _close_archive(self) -> None:
        """
        Purpose: Close the open archive file handle if one is open.
        Side effects: Closes file, resets handle and date to None.
        """
        if self._archive_handle is not None:
            self._archive_handle.close()
            self._archive_handle = None
            self._archive_date = None

    def _maybe_log_stats(self) -> None:
        """
        Purpose:
            Emit a rolling stats log line if _STATS_LOG_INTERVAL seconds have
            elapsed since the last emission.  Called from the run loop so the
            interval is approximate (resolution ≈ queue timeout = 0.2 s).
        Side effects:
            - Logs at INFO when the interval has elapsed.
            - Updates _last_stats_at.
        """
        now = time.monotonic()
        if now - self._last_stats_at < _STATS_LOG_INTERVAL:
            return
        self._last_stats_at = now
        logger.info(
            "Worker stats — processed=%d dropped=%d db_errors=%d queue_drops=%d",
            self.processed_count,
            self.dropped_count,
            self.db_error_count,
            self._queue.dropped_flow_count,
        )


# ------------------------------------------------------------------ #
# Module-level helpers (pure functions — no side effects)             #
# ------------------------------------------------------------------ #

def _validate_flow(flow: dict) -> bool:
    """
    Purpose:
        Reject structurally malformed flows before they reach the database.
        Only checks fields the worker is required to write — does not enforce
        application-level invariants.
    Input:
        flow — raw dict from the proxy queue.
    Output:
        True if the flow passes all checks; False if it should be dropped.
    Rules:
        - method must be a non-empty string.
        - url must be a non-empty string.
        - status_code must be present (not None).
        - request_start must be a valid ISO-8601 string.
        - role_id must be a non-empty string (resolved by the addon).
        - module_id must be a non-empty string (resolved by the addon).
    """
    if not flow.get("method"):
        return False
    if not flow.get("url"):
        return False
    if flow.get("status_code") is None:
        return False

    ts = flow.get("request_start")
    if not ts:
        return False
    try:
        datetime.fromisoformat(ts)
    except (ValueError, TypeError):
        return False

    if not flow.get("role_id"):
        return False
    if not flow.get("module_id"):
        return False

    return True


def _persist_db(flow: dict, db_path: Path) -> Optional[str]:
    """
    Purpose:
        Insert a validated, project-tagged flow into the flows table and resolve
        its stable endpoint identity in the same transaction.
    Input:
        flow    — enriched flow dict with project_id attached.
        db_path — absolute path to the project SQLite file.
    Output:
        Endpoint ID linked to the persisted flow, or None when endpoint
        resolution failed (flow is still stored with NULL endpoint_id).
    Side effects:
        - Opens a new connection, upserts endpoint state, inserts one flow row,
          upserts endpoint_roles (only when endpoint_id resolved), commits the
          primary record, then extracts and upserts parameters in a second
          commit (also only when endpoint_id resolved), closes connection.
        - On normalization failure: logs ERROR, sets endpoint_id to NULL,
          continues with flow insert — does not raise.
        - On endpoint upsert failure: rolls back the failed endpoint work, logs
          ERROR, inserts the flow with NULL endpoint_id — does not raise.
        - On parameter extraction failure: rolls back incomplete param writes,
          logs ERROR, flow and endpoint remain committed — does not raise.
    Raises:
        sqlite3.Error on DB-level failure outside the endpoint upsert scope
        (caller logs and handles via retry logic).
    """
    response_content_type = _extract_response_content_type(
        flow.get("response_headers", {})
    )
    auth_required = _flow_has_auth_material(flow)

    # Normalize URL outside the database connection — it is a pure step.
    # Any unexpected failure degrades gracefully: flow is still stored with
    # NULL endpoint_id rather than being dropped.
    normalized_url: Optional[NormalizedFlowURL] = None
    try:
        normalized_url = normalize_flow_url(flow["path"], flow.get("query", ""))
    except Exception:
        logger.error(
            "URL normalization raised unexpectedly — flow_id=%s host=%s path=%s"
            " — endpoint_id will be NULL",
            flow.get("flow_id"),
            flow.get("host"),
            flow.get("path"),
            exc_info=True,
        )

    # Fall back to raw query when normalization was skipped due to failure.
    cleaned_query: str = (
        normalized_url.cleaned_query
        if normalized_url is not None
        else (flow.get("query") or "")
    )

    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row

        # Attempt endpoint upsert. On failure: roll back any partial endpoint
        # work, log, and continue with NULL endpoint_id — the flow must not be
        # dropped because endpoint resolution failed.
        endpoint_id: Optional[str] = None
        if normalized_url is not None:
            try:
                endpoint_id = _upsert_endpoint(
                    conn=conn,
                    flow=flow,
                    normalized_url=normalized_url,
                    content_type=response_content_type,
                    auth_required=auth_required,
                )
            except Exception:
                # Reset transaction state so the flow INSERT below can proceed
                # cleanly in a fresh implicit transaction.
                conn.rollback()
                logger.error(
                    "Endpoint upsert failed — flow_id=%s host=%s path=%s"
                    " — inserting flow with NULL endpoint_id",
                    flow.get("flow_id"),
                    flow.get("host"),
                    flow.get("path"),
                    exc_info=True,
                )

        conn.execute(
            """
            INSERT INTO flows (
                id,
                project_id,
                captured_at,
                response_end,
                method,
                url,
                host,
                path,
                query,
                request_headers,
                request_cookies,
                request_body,
                request_body_truncated,
                status_code,
                response_headers,
                response_body,
                response_body_truncated,
                content_type,
                endpoint_id,
                role_id,
                module_id
            ) VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
            """,
            (
                flow["flow_id"],
                flow["project_id"],
                flow["request_start"],          # captured_at
                flow.get("response_end"),        # nullable
                flow["method"],
                flow["url"],
                flow["host"],
                flow["path"],
                cleaned_query,
                json.dumps(flow.get("request_headers", {})),
                json.dumps(flow.get("request_cookies", {})),
                flow.get("request_body"),        # bytes | None → BLOB
                1 if flow.get("request_body_truncated") else 0,
                flow["status_code"],
                json.dumps(flow.get("response_headers", {})),
                flow.get("response_body"),       # bytes | None → BLOB
                1 if flow.get("response_body_truncated") else 0,
                response_content_type,
                endpoint_id,
                flow["role_id"],
                flow["module_id"],
            ),
        )

        # endpoint_roles requires a resolved endpoint_id; skip when NULL.
        if endpoint_id is not None:
            _upsert_endpoint_role(
                conn=conn,
                endpoint_id=endpoint_id,
                role_id=flow["role_id"],
                captured_at=flow["request_start"],
            )

        # Commit the primary record (flow + endpoint + endpoint_roles) before
        # attempting parameter extraction.  Parameters are supplementary:
        # a failure must not roll back a committed flow.
        conn.commit()

        # Parameter extraction runs in a second commit so any failure only
        # rolls back the uncommitted param writes, not the flow record.
        if endpoint_id is not None:
            try:
                params = extract_flow_params(
                    query=cleaned_query,
                    request_body=flow.get("request_body"),
                    request_headers=flow.get("request_headers", {}),
                )
                if params:
                    upsert_endpoint_params(conn, endpoint_id, params)
                    conn.commit()
            except Exception:
                conn.rollback()  # discard incomplete param writes only
                logger.error(
                    "Parameter extraction failed — flow_id=%s endpoint_id=%s"
                    " — parameters skipped, flow unaffected",
                    flow.get("flow_id"),
                    endpoint_id,
                    exc_info=True,
                )

        return endpoint_id


def _upsert_endpoint(
    conn: sqlite3.Connection,
    flow: dict,
    normalized_url: NormalizedFlowURL,
    content_type: str,
    auth_required: bool,
) -> str:
    """
    Purpose:
        Create or update the stable endpoint record for one captured flow.
    Input:
        conn           — open SQLite connection in the current write transaction.
        flow           — validated flow dict with project_id attached.
        normalized_url — canonical path/query derived from the flow URL.
        content_type   — response content type derived from response headers.
        auth_required  — True when the request carried auth material.
    Output:
        Endpoint ID for the matching stable endpoint.
    Side effects:
        Inserts or updates one row in endpoints.
    """
    row = conn.execute(
        """
        SELECT id, first_seen, last_seen, content_type, auth_required, roles_seen
        FROM endpoints
        WHERE project_id = ? AND method = ? AND host = ? AND normalized_path = ?
        """,
        (
            flow["project_id"],
            flow["method"],
            flow["host"],
            normalized_url.normalized_path,
        ),
    ).fetchone()

    observed_roles = _merge_roles_seen(
        row["roles_seen"] if row is not None else "[]",
        flow["role_id"],
    )
    captured_at = flow["request_start"]

    if row is None:
        endpoint_id = str(uuid.uuid4())
        conn.execute(
            """
            INSERT INTO endpoints (
                id,
                project_id,
                method,
                host,
                path,
                normalized_path,
                content_type,
                auth_required,
                roles_seen,
                first_seen,
                last_seen
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                endpoint_id,
                flow["project_id"],
                flow["method"],
                flow["host"],
                flow["path"],
                normalized_url.normalized_path,
                content_type,
                1 if auth_required else 0,
                observed_roles,
                captured_at,
                captured_at,
            ),
        )
        return endpoint_id

    first_seen = min(row["first_seen"], captured_at)
    last_seen = max(row["last_seen"], captured_at)
    conn.execute(
        """
        UPDATE endpoints
        SET content_type = ?,
            auth_required = ?,
            roles_seen = ?,
            first_seen = ?,
            last_seen = ?
        WHERE id = ?
        """,
        (
            row["content_type"] or content_type,
            1 if row["auth_required"] or auth_required else 0,
            observed_roles,
            first_seen,
            last_seen,
            row["id"],
        ),
    )
    return str(row["id"])


def _merge_roles_seen(raw_roles: str, role_id: str) -> str:
    """
    Purpose:
        Add the current role ID to an endpoint's observed-role list without
        duplicating prior observations.
    Input:
        raw_roles — JSON array string stored on the endpoint row.
        role_id   — role UUID to record.
    Output:
        JSON array string containing the merged role IDs.
    Side effects: None.
    """
    try:
        parsed_roles = json.loads(raw_roles)
    except (json.JSONDecodeError, TypeError):
        parsed_roles = []

    if not isinstance(parsed_roles, list):
        parsed_roles = []
    if role_id not in parsed_roles:
        parsed_roles.append(role_id)
    return json.dumps(parsed_roles)


def _extract_response_content_type(headers: dict) -> str:
    """
    Purpose:
        Read the response Content-Type header from captured response headers.
    Input:
        headers — response headers dict captured from the proxy.
    Output:
        Header value as a string, or an empty string when absent.
    Side effects: None.
    """
    return _get_header_value(headers, "content-type")


def _flow_has_auth_material(flow: dict) -> bool:
    """
    Purpose:
        Infer whether a flow was captured in an authenticated browser context.
    Input:
        flow — validated flow dict.
    Output:
        True when the request carried cookies or an Authorization header.
    Side effects: None.
    """
    if flow.get("request_cookies"):
        return True
    return bool(_get_header_value(flow.get("request_headers", {}), "authorization"))


def _get_header_value(headers: dict, name: str) -> str:
    """
    Purpose:
        Read one header from a case-insensitive headers dict.
    Input:
        headers — captured headers dict.
        name    — target header name in lowercase.
    Output:
        Header value as a string, or an empty string if missing.
    Side effects: None.
    """
    lowered = name.lower()
    for key, value in headers.items():
        if str(key).lower() != lowered:
            continue
        if isinstance(value, list):
            return str(value[0]) if value else ""
        return str(value)
    return ""


def _flow_to_jsonl(flow: dict) -> str:
    """
    Purpose:
        Serialize a flow dict to a single JSON string for archive storage.
        bytes values (request_body, response_body) are base64-encoded so the
        line is valid JSON and can be decoded deterministically.
    Input:
        flow — enriched flow dict; may contain bytes values.
    Output:
        Single-line JSON string (no trailing newline).
    Side effects: None.
    """
    def _encode(obj: object) -> object:
        # Only bytes fields require special handling; everything else is JSON-native.
        if isinstance(obj, bytes):
            return {"_b64": base64.b64encode(obj).decode("ascii")}
        raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")

    return json.dumps(flow, default=_encode)


def _upsert_endpoint_role(
    conn: sqlite3.Connection,
    endpoint_id: str,
    role_id: str,
    captured_at: str,
) -> None:
    """
    Purpose:
        Record that a role accessed an endpoint.
        Inserts a new (endpoint_id, role_id) row on first observation;
        updates last_seen on subsequent observations.
    Input:
        conn        — open SQLite connection in the current write transaction.
        endpoint_id — UUID of the resolved endpoint.
        role_id     — UUID of the role that produced the flow.
        captured_at — UTC ISO-8601 timestamp of the flow (used as first_seen /
                      candidate for last_seen).
    Side effects:
        Upserts one row into endpoint_roles.
    """
    conn.execute(
        """
        INSERT INTO endpoint_roles (endpoint_id, role_id, first_seen, last_seen)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(endpoint_id, role_id)
        DO UPDATE SET last_seen = excluded.last_seen
            WHERE excluded.last_seen > endpoint_roles.last_seen
        """,
        (endpoint_id, role_id, captured_at, captured_at),
    )

