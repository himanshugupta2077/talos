"""
Module: talos.error_intel.worker

Purpose:
    ErrorIntelWorker — daemon that drains ErrorIntelQueue and runs the
    Error Intelligence pipeline (Phases 3–6):

        1. Load response_body from flows by flow_id
        2. Defense-in-depth is_error_candidate()
        3. Merge job context + pending attach_error_context + flow_meta
        4. classify_error (detect → normalize → fingerprint → severity)
        5. store_classified_error (cluster upsert + observation)

    Never: outbound HTTP, archive JSONL, ReplayScheduler, auto Findings.

Architecture:
    ErrorIntelQueue → ErrorIntelWorker._run() → _process(job)
        → load body → candidate → classify → store

    Capture-safe hook:
        maybe_enqueue_error_scan(...) — cheap gate + put; never raises.

    Scheduler / replay path (no daemon worker):
        process_error_scan_sync(...) — full pipeline inline, non-fatal.

Dependencies:
    hashlib, json, logging, sqlite3, threading, time
    talos.error_intel.{candidate, classify, config via db, constants,
                       db, models, observe pending context, queue}
    talos.projects.model.Project
Data flow:
    TalosAddon starts worker after FlowWorker; FlowWorker enqueues jobs
    after flow commit; this worker writes error_clusters / observations.
Side effects:
    - Reads flows.response_body from project SQLite.
    - Writes error_clusters + error_observations.
    - Logs progress and errors; never raises into capture path.
"""

from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Optional, Union

from talos.error_intel.candidate import is_error_candidate
from talos.error_intel.classify import classify_from_detect
from talos.error_intel.config import ErrorIntelConfig, header_names_for_gate
from talos.error_intel.constants import (
    ATTACK_TYPE_BAC,
    ATTACK_TYPE_IV,
    ATTACK_TYPE_PROXY,
    ATTACK_TYPE_REPLAY,
    ATTACK_TYPE_UNAUTH,
    ATTACK_TYPE_UNKNOWN,
    DEFAULT_PAYLOAD_REDACTED_MAX,
    ERROR_INTEL_VERSION,
)
from talos.error_intel import db as error_db
from talos.error_intel.detectors.orchestrator import detect_errors
from talos.error_intel.models import ErrorIntelJob
from talos.error_intel.queue import ErrorIntelQueue
from talos.error_intel.redact import redact_payload as _redact_payload_secrets

# flow_meta key for multi-process attach context (BUG-13).
ERROR_INTEL_FLOW_META_KEY = "error_intel"

logger = logging.getLogger(__name__)

# Emit a rolling stats log line every N seconds while the worker is active.
_STATS_LOG_INTERVAL: float = 30.0

# Queue get timeout while running (seconds).
_POLL_TIMEOUT: float = 0.2

# Process-local pending context from attach_error_context (flow_id → fields).
# Used when attack engines enrich after / before the worker processes a flow.
_pending_context: dict[str, dict[str, Any]] = {}
_pending_lock = threading.Lock()


def set_pending_error_context(
    flow_id: str,
    *,
    parameter_uuid: Optional[str] = None,
    parameter_name: Optional[str] = None,
    attack_type: Optional[str] = None,
    payload: Optional[str] = None,
) -> None:
    """
    Purpose:
        Record observation context for a flow that may not yet have been
        scanned. Worker merges this when processing.
    Side effects:
        Mutates process-local _pending_context.
    """
    if not flow_id:
        return
    with _pending_lock:
        cur = dict(_pending_context.get(flow_id) or {})
        if parameter_uuid:
            cur["parameter_uuid"] = parameter_uuid
        if parameter_name:
            cur["parameter_name"] = parameter_name
        if attack_type:
            cur["attack_type"] = attack_type
        if payload is not None:
            cur["payload"] = payload
        _pending_context[flow_id] = cur


def pop_pending_error_context(flow_id: str) -> dict[str, Any]:
    """
    Purpose:
        Take and remove pending context for a flow (if any).
    Side effects:
        Removes key from process-local map.
    """
    if not flow_id:
        return {}
    with _pending_lock:
        return dict(_pending_context.pop(flow_id, {}) or {})


def peek_pending_error_context(flow_id: str) -> dict[str, Any]:
    """Read pending context without removing. Side effects: None."""
    if not flow_id:
        return {}
    with _pending_lock:
        return dict(_pending_context.get(flow_id) or {})


class ErrorIntelWorker:
    """
    Purpose:
        Consume ErrorIntelJob items: classify errors, persist clusters and
        observations. One instance per proxy session (recommended).

    Fields:
        _project         — Active project (db_path).
        _queue           — Shared ErrorIntelQueue drained by this worker.
        _stop_event      — Set to signal the run loop to exit cleanly.
        _thread          — Daemon thread running _run().
        processed_count  — Jobs that completed without unexpected error.
        stored_count     — Clusters/observations written this session.
        skipped_count    — Not candidate / disabled / empty body / no match.
        skipped_dup_count— Flows already observed (skip re-insert).
        error_count      — Jobs that failed with logged exception.
        _last_stats_at   — Monotonic timestamp of last stats log line.

    Invariant:
        start() should be called after FlowWorker so enqueued jobs land
        against committed flows. stop() drains remaining jobs.
    """

    def __init__(self, project: Any, queue: ErrorIntelQueue) -> None:
        self._project = project
        self._queue = queue
        self._stop_event = threading.Event()
        self._thread = threading.Thread(
            target=self._run,
            daemon=True,
            name="talos-error-intel",
        )
        self.processed_count: int = 0
        self.stored_count: int = 0
        self.skipped_count: int = 0
        self.skipped_dup_count: int = 0
        self.error_count: int = 0
        self._last_stats_at: float = time.monotonic()

    def start(self) -> None:
        """
        Purpose:
            Start the error intel daemon thread.
        Side effects:
            - Spawns a new thread.
            - Logs start at INFO.
        """
        self._thread.start()
        logger.info(
            "ErrorIntelWorker started — project=%s db=%s queue_max=%d "
            "version=%s",
            self._project.id,
            self._project.db_path,
            self._queue.maxsize(),
            ERROR_INTEL_VERSION,
        )

    def stop(self, timeout: float = 5.0) -> None:
        """
        Purpose:
            Signal the worker to stop, drain remaining jobs, join thread.
        Input:
            timeout — seconds to wait for the thread to join.
        Side effects:
            - Sets stop event; drains queue; joins thread; logs counters.
        """
        self._stop_event.set()
        self._thread.join(timeout=timeout)
        logger.info(
            "ErrorIntelWorker stopped — project=%s processed=%d stored=%d "
            "skipped_dup=%d skipped=%d errors=%d queue_drops=%d enqueued=%d",
            self._project.id,
            self.processed_count,
            self.stored_count,
            self.skipped_dup_count,
            self.skipped_count,
            self.error_count,
            self._queue.dropped_job_count,
            self._queue.enqueued_count,
        )

    # ------------------------------------------------------------------ #
    # Run loop                                                             #
    # ------------------------------------------------------------------ #

    def _run(self) -> None:
        """
        Purpose:
            Main loop — dequeue and process jobs until stop, then drain.
        Side effects:
            - Calls _process() for each dequeued job.
        """
        while not self._stop_event.is_set():
            job = self._queue.get(timeout=_POLL_TIMEOUT)
            if job is None:
                self._maybe_log_stats()
                continue
            try:
                self._process(job)
            except Exception:
                self.error_count += 1
                logger.exception(
                    "Unexpected error in ErrorIntelWorker._process — "
                    "flow_id=%s — loop continuing",
                    getattr(job, "flow_id", "?"),
                )
            self._maybe_log_stats()

        # Drain remaining jobs so stop does not silently discard work.
        while True:
            job = self._queue.get(timeout=0)
            if job is None:
                break
            try:
                self._process(job)
            except Exception:
                self.error_count += 1
                logger.exception(
                    "Unexpected error in ErrorIntelWorker drain — "
                    "flow_id=%s — skipping",
                    getattr(job, "flow_id", "?"),
                )

    def _process(self, job: ErrorIntelJob) -> None:
        """
        Purpose:
            Handle one ErrorIntelJob: classify + store pipeline.
        Input:
            job — minimal payload; body reloaded from DB.
        Side effects:
            - Reads flow body; may write cluster/observation rows.
            - Updates session counters.
        """
        if not isinstance(job, ErrorIntelJob):
            logger.warning(
                "Dropping corrupt error-intel job — expected ErrorIntelJob, "
                "got %s",
                type(job).__name__,
            )
            self.skipped_count += 1
            return

        result = process_error_scan_job(
            db_path=self._project.db_path,
            job=job,
            force=False,
        )
        if result is None:
            self.skipped_count += 1
            self.processed_count += 1
            return
        if result.get("duplicate"):
            self.skipped_dup_count += 1
            self.processed_count += 1
            return
        if result.get("stored"):
            self.stored_count += 1
        else:
            self.skipped_count += 1
        self.processed_count += 1

    def _maybe_log_stats(self) -> None:
        """
        Purpose:
            Emit a rolling stats log line on interval.
        Side effects:
            - Logs at INFO when interval elapsed; updates _last_stats_at.
        """
        now = time.monotonic()
        if now - self._last_stats_at < _STATS_LOG_INTERVAL:
            return
        self._last_stats_at = now
        logger.info(
            "Error intel stats — processed=%d stored=%d skipped_dup=%d "
            "skipped=%d errors=%d queue_depth=%d queue_drops=%d version=%s",
            self.processed_count,
            self.stored_count,
            self.skipped_dup_count,
            self.skipped_count,
            self.error_count,
            self._queue.size(),
            self._queue.dropped_job_count,
            ERROR_INTEL_VERSION,
        )


# ------------------------------------------------------------------ #
# Core pipeline (shared by worker + sync path)                         #
# ------------------------------------------------------------------ #

def process_error_scan_job(
    *,
    db_path: Path,
    job: ErrorIntelJob,
    force: bool = False,
    config: Optional[ErrorIntelConfig] = None,
) -> Optional[dict[str, Any]]:
    """
    Purpose:
        Run the full Error Intelligence pipeline for one job.

    Input:
        db_path — project talos.db
        job     — ErrorIntelJob (body loaded by flow_id)
        force   — when True, re-scan even if observations exist for flow_id
        config  — optional; None → load from DB

    Output:
        None when skipped (disabled / not candidate / empty / no match).
        dict with keys: stored, duplicate, cluster_id, observation_id,
        fingerprint, created.

    Side effects:
        May write error_clusters / error_observations.
        Never raises (logs and returns None on failure).
    """
    try:
        cfg = config if config is not None else error_db.get_config(db_path)
        if not cfg.enabled:
            return None

        # Already observed at current scanner version? Skip unless force.
        # Outdated scanner_version → reprocess (replace) so detector fixes
        # apply without manual --force (BUG-09).
        replace_flow = bool(force)
        if not force and error_db.has_current_observation_for_flow(
            db_path, job.flow_id, scanner_version=ERROR_INTEL_VERSION
        ):
            # Still apply pending / flow_meta context enrich if any.
            pending = pop_pending_error_context(job.flow_id)
            meta_ctx = _load_error_intel_meta(db_path, job.flow_id)
            merged_pending = {**meta_ctx, **pending}
            if merged_pending:
                error_db.update_observations_context(
                    db_path,
                    job.flow_id,
                    parameter_uuid=merged_pending.get("parameter_uuid"),
                    parameter_name=merged_pending.get("parameter_name"),
                    attack_type=merged_pending.get("attack_type"),
                    payload_redacted=_redact_payload(
                        merged_pending.get("payload")
                        or merged_pending.get("payload_redacted")
                    ),
                )
            return {"stored": False, "duplicate": True}
        if (
            not force
            and error_db.has_observation_for_flow(db_path, job.flow_id)
        ):
            # Observation exists but scanner_version is stale → replace.
            replace_flow = True

        body = _load_flow_body(db_path, job.flow_id)
        headers = _load_flow_headers(db_path, job.flow_id)

        # Defense in depth: re-check candidate with body.
        if not is_error_candidate(
            status_code=job.status_code,
            content_type=job.content_type,
            headers=headers,
            body=body,
            path=job.path,
            error_header_names=header_names_for_gate(cfg),
            gate_sniff_bytes=cfg.gate_sniff_bytes,
        ):
            pop_pending_error_context(job.flow_id)
            return None

        if body is None or len(body) == 0:
            # Status/header-only candidates with empty body: nothing to parse.
            pop_pending_error_context(job.flow_id)
            return None

        # Cap scan budget.
        scan_body = body
        if len(scan_body) > int(cfg.max_body_scan):
            scan_body = scan_body[: int(cfg.max_body_scan)]

        detect_result = detect_errors(
            scan_body,
            status_code=job.status_code,
            content_type=job.content_type or None,
            headers=headers,
            config=cfg,
        )
        classified = classify_from_detect(
            detect_result,
            status_code=job.status_code,
            evidence_snippet_max=cfg.evidence_snippet_max,
        )
        if classified is None:
            pop_pending_error_context(job.flow_id)
            logger.debug(
                "Error intel no match — flow_id=%s status=%s",
                job.flow_id,
                job.status_code,
            )
            return None

        # Merge context: job fields < flow_meta < pending attach.
        ctx = _merge_observation_context(db_path, job)
        pending = pop_pending_error_context(job.flow_id)
        if pending.get("parameter_uuid"):
            ctx["parameter_uuid"] = pending["parameter_uuid"]
        if pending.get("parameter_name"):
            ctx["parameter_name"] = pending["parameter_name"]
        if pending.get("attack_type"):
            ctx["attack_type"] = pending["attack_type"]
        if pending.get("payload") is not None:
            ctx["payload_redacted"] = _redact_payload(pending.get("payload"))

        response_hash = hashlib.sha256(body).hexdigest()
        response_length = len(body)

        cluster, obs, created = error_db.store_classified_error(
            db_path,
            job.project_id,
            classified,
            flow_id=job.flow_id,
            endpoint_id=job.endpoint_id or ctx.get("endpoint_id"),
            parameter_uuid=ctx.get("parameter_uuid") or job.parameter_uuid,
            parameter_name=ctx.get("parameter_name") or job.parameter_name,
            attack_type=ctx.get("attack_type") or job.attack_type or ATTACK_TYPE_UNKNOWN,
            payload_redacted=ctx.get("payload_redacted") or job.payload_redacted,
            response_status=job.status_code,
            response_length=response_length,
            duration_ms=job.duration_ms,
            response_hash=response_hash,
            artifacts=list(detect_result.artifacts or []),
            observed_at=job.observed_at or None,
            # --force or outdated scanner_version replaces the flow observation.
            replace_flow=replace_flow,
        )

        logger.debug(
            "Error intel stored — flow_id=%s error_id=%s category=%s "
            "severity=%s created=%s fingerprint=%s…",
            job.flow_id,
            cluster.id,
            cluster.category,
            cluster.severity,
            created,
            (cluster.fingerprint or "")[:12],
        )
        _record_burp_error(db_path, job, obs, cluster)
        return {
            "stored": True,
            "duplicate": False,
            "cluster_id": cluster.id,
            "observation_id": obs.id,
            "fingerprint": cluster.fingerprint,
            "created": created,
            "cluster": cluster,
            "observation": obs,
        }
    except Exception:
        logger.exception(
            "Error intel process failed — flow_id=%s",
            getattr(job, "flow_id", "?"),
        )
        return None


def _record_burp_error(db_path: Path, job: ErrorIntelJob, obs: Any, cluster: Any) -> None:
    """Best-effort Burp snapshot; never raises into the scan path."""
    try:
        from talos.burp.snapshot import record_module_hit
        from talos.burp.trace import ENGINE_ERROR_INTEL

        record_module_hit(
            project_id=job.project_id,
            engine=ENGINE_ERROR_INTEL,
            extras={
                "technique": getattr(cluster, "category", "") or "error",
                "detail": getattr(cluster, "exception_type", "")
                or getattr(obs, "id", "")
                or "error",
            },
            record_id=f"error:{getattr(obs, 'id', '') or job.flow_id}",
            status=int(job.status_code or 0),
            db_path=db_path,
            flow_id=job.flow_id,
            url=job.url,
            host=job.host,
            path=job.path,
            endpoint_id=job.endpoint_id or "",
        )
    except Exception:
        logger.debug("burp error-intel snapshot skipped", exc_info=True)


def process_error_scan_sync(
    *,
    db_path: Path,
    project_id: str,
    flow_id: str,
    flow: Optional[dict[str, Any]] = None,
    force: bool = False,
    config: Optional[ErrorIntelConfig] = None,
) -> Optional[dict[str, Any]]:
    """
    Purpose:
        Synchronous scan path for scheduler / replay / tests when no
        ErrorIntelQueue worker is running.

    Input:
        db_path / project_id / flow_id — required identity
        flow — optional enriched dict (status, path, content_type, meta)
        force — re-scan even if observations exist
        config — optional ErrorIntelConfig

    Output:
        Same as process_error_scan_job, or None.

    Side effects:
        May write error_clusters / error_observations. Never raises.
    """
    try:
        job = build_job_from_flow(
            project_id=project_id,
            flow_id=flow_id,
            flow=flow,
            db_path=db_path,
        )
        if job is None:
            return None
        return process_error_scan_job(
            db_path=db_path,
            job=job,
            force=force,
            config=config,
        )
    except Exception:
        logger.exception(
            "Error intel sync scan failed — flow_id=%s",
            flow_id,
        )
        return None


def maybe_enqueue_error_scan(
    *,
    error_queue: Optional[ErrorIntelQueue],
    db_path: Path,
    project_id: str,
    flow: dict,
    endpoint_id: Optional[str] = None,
    content_type: str = "",
    inline_if_no_queue: bool = True,
) -> bool:
    """
    Purpose:
        Cheap post-commit hook: if error intel is enabled and the response
        looks error-like, enqueue an ErrorIntelJob (or process inline when
        no queue is available — scheduler / replay path).

        Never raises. Never blocks on a full queue (drop-on-full).
        Safe to call on every persisted flow.

    Input:
        error_queue — ErrorIntelQueue or None
        db_path     — project DB (config read)
        project_id  — owning project
        flow        — enriched flow dict (must include flow_id or id)
        endpoint_id — resolved endpoint UUID or None
        content_type — response Content-Type already extracted by caller
        inline_if_no_queue — when True and queue is None, run sync pipeline

    Output:
        True if a job was enqueued or inline scan ran (including no-match
        skips after gate), False when disabled / not candidate / error.

    Side effects:
        - May read error_intel_config.
        - May put a job on error_queue (drop-on-full inside queue).
        - May write clusters/observations when processing inline.
        - Logs DEBUG/WARNING only; errors swallowed.
    """
    try:
        config = error_db.get_config(db_path)
        if not config.enabled:
            return False

        flow_id = str(flow.get("flow_id") or flow.get("id") or "")
        if not flow_id:
            return False

        path = flow.get("path") or ""
        status = flow.get("status_code")
        body = flow.get("response_body")
        headers = flow.get("response_headers")

        body_bytes = _coerce_body(body)
        status_code = _coerce_status(status)
        ct = content_type or flow.get("content_type") or ""

        if not is_error_candidate(
            status_code=status_code,
            content_type=ct,
            headers=headers,
            body=body_bytes,
            path=path,
            error_header_names=header_names_for_gate(config),
            gate_sniff_bytes=config.gate_sniff_bytes,
        ):
            return False

        job = build_job_from_flow(
            project_id=project_id,
            flow_id=flow_id,
            flow=flow,
            db_path=db_path,
            endpoint_id=endpoint_id,
            content_type=ct,
        )
        if job is None:
            return False

        if error_queue is not None:
            return error_queue.put(job)

        if inline_if_no_queue:
            process_error_scan_job(
                db_path=db_path,
                job=job,
                force=False,
                config=config,
            )
            return True
        return False
    except Exception:
        # Capture / replay path must never fail because of error intel.
        logger.exception(
            "Error intel enqueue failed — flow_id=%s — caller unaffected",
            flow.get("flow_id") or flow.get("id") or "?",
        )
        return False


# ------------------------------------------------------------------ #
# Job builders / attack context                                        #
# ------------------------------------------------------------------ #

def build_job_from_flow(
    *,
    project_id: str,
    flow_id: str,
    flow: Optional[dict[str, Any]] = None,
    db_path: Optional[Path] = None,
    endpoint_id: Optional[str] = None,
    content_type: str = "",
) -> Optional[ErrorIntelJob]:
    """
    Purpose:
        Build an ErrorIntelJob from a flow dict and/or DB row fields.
    Side effects:
        May read flow_meta / source from DB when flow is sparse.
    """
    if not project_id or not flow_id:
        return None

    data: dict[str, Any] = dict(flow or {})
    if db_path is not None and (
        not data.get("source")
        and not data.get("flow_meta")
        and data.get("status_code") is None
    ):
        row = _load_flow_row(db_path, flow_id)
        if row:
            data = {**row, **data}

    meta = _parse_flow_meta(data.get("flow_meta"))
    source = str(data.get("source") or "")
    replay_reason = data.get("replay_reason")
    attack_type = infer_attack_type(source, meta, replay_reason)
    param_uuid = (
        data.get("parameter_uuid")
        or meta.get("parameter_uuid")
        or meta.get("param_uuid")
    )
    param_name = (
        data.get("parameter_name")
        or meta.get("parameter_name")
        or meta.get("param_name")
    )
    payload = data.get("payload") or meta.get("payload")
    payload_redacted = _redact_payload(payload)

    status_code = _coerce_status(data.get("status_code"))
    ct = content_type or data.get("content_type") or ""
    ep = endpoint_id or data.get("endpoint_id")
    if isinstance(ep, str) and not ep:
        ep = None

    return ErrorIntelJob(
        project_id=project_id,
        flow_id=flow_id,
        endpoint_id=ep if isinstance(ep, str) else None,
        url=str(data.get("url") or ""),
        host=str(data.get("host") or ""),
        path=str(data.get("path") or ""),
        content_type=str(ct or ""),
        status_code=status_code,
        truncated=bool(
            data.get("response_body_truncated") or data.get("truncated")
        ),
        attack_type=attack_type,
        parameter_uuid=str(param_uuid) if param_uuid else None,
        parameter_name=str(param_name) if param_name else None,
        payload_redacted=payload_redacted,
        duration_ms=_coerce_float(data.get("duration_ms")),
        observed_at=str(
            data.get("request_start")
            or data.get("captured_at")
            or data.get("observed_at")
            or ""
        ),
        role_id=str(data.get("role_id") or ""),
        module_id=str(data.get("module_id") or ""),
    )


def infer_attack_type(
    source: Optional[str],
    flow_meta: Optional[dict[str, Any]],
    replay_reason: Optional[str] = None,
) -> str:
    """
    Purpose:
        Map flow source / flow_meta / replay_reason to error_observations
        attack_type vocabulary.
    Side effects: None.
    """
    meta = flow_meta if isinstance(flow_meta, dict) else {}
    generated_by = str(meta.get("generated_by") or "").lower()
    attack_module = str(meta.get("attack_module") or "").lower()
    reason = str(replay_reason or meta.get("attack_type") or "").lower()
    src = str(source or "").lower()

    if generated_by in ("input_validation", "iv") or src == "iv_scan":
        return ATTACK_TYPE_IV
    if "input_validation" in reason:
        return ATTACK_TYPE_IV
    if attack_module == "bac" or reason.startswith("bac") or "bac_" in reason:
        return ATTACK_TYPE_BAC
    if (
        attack_module == "unauth"
        or reason.startswith("unauth")
        or "unauth" in reason
    ):
        return ATTACK_TYPE_UNAUTH
    if src in ("auto_replay", "manual_replay", "manual_send", "ai_send"):
        return ATTACK_TYPE_REPLAY
    if src in ("proxy_capture", "proxy", ""):
        return ATTACK_TYPE_PROXY
    return ATTACK_TYPE_UNKNOWN


def _merge_observation_context(
    db_path: Path,
    job: ErrorIntelJob,
) -> dict[str, Any]:
    """
    Purpose:
        Load flow_meta from DB and merge with job fields for observation.
        Includes multi-process attach context under flow_meta.error_intel.
    Side effects:
        May open a short-lived SQLite connection.
    """
    meta = _load_flow_meta(db_path, job.flow_id)
    ei_meta = _error_intel_meta_from_flow_meta(meta)
    source_row = _load_flow_source(db_path, job.flow_id)
    attack_type = (
        job.attack_type
        or ei_meta.get("attack_type")
        or infer_attack_type(
            source_row.get("source"),
            meta,
            source_row.get("replay_reason"),
        )
    )
    param_uuid = (
        job.parameter_uuid
        or ei_meta.get("parameter_uuid")
        or meta.get("parameter_uuid")
        or meta.get("param_uuid")
    )
    param_name = (
        job.parameter_name
        or ei_meta.get("parameter_name")
        or meta.get("parameter_name")
        or meta.get("param_name")
    )
    payload = (
        job.payload_redacted
        or _redact_payload(ei_meta.get("payload") or ei_meta.get("payload_redacted"))
        or _redact_payload(meta.get("payload"))
    )
    return {
        "attack_type": attack_type,
        "parameter_uuid": param_uuid,
        "parameter_name": param_name,
        "payload_redacted": payload,
        "endpoint_id": job.endpoint_id or source_row.get("endpoint_id"),
    }


def _error_intel_meta_from_flow_meta(meta: dict[str, Any]) -> dict[str, Any]:
    raw = meta.get(ERROR_INTEL_FLOW_META_KEY) if isinstance(meta, dict) else None
    if not isinstance(raw, dict):
        return {}
    out: dict[str, Any] = {}
    for key in (
        "parameter_uuid",
        "parameter_name",
        "attack_type",
        "payload",
        "payload_redacted",
    ):
        if raw.get(key) is not None and raw.get(key) != "":
            out[key] = raw[key]
    return out


def _load_error_intel_meta(db_path: Path, flow_id: str) -> dict[str, Any]:
    return _error_intel_meta_from_flow_meta(_load_flow_meta(db_path, flow_id))


def persist_error_context_to_flow_meta(
    db_path: Path,
    flow_id: str,
    *,
    parameter_uuid: Optional[str] = None,
    parameter_name: Optional[str] = None,
    attack_type: Optional[str] = None,
    payload: Optional[str] = None,
) -> bool:
    """
    Purpose:
        Merge attach context into flows.flow_meta.error_intel so workers in
        other processes can still link parameters (BUG-13).

        Only fills empty fields inside the error_intel sub-object.

    Side effects:
        UPDATE flows.flow_meta; commits.
    """
    if not flow_id or not db_path:
        return False
    try:
        with sqlite3.connect(str(db_path)) as conn:
            row = conn.execute(
                "SELECT flow_meta FROM flows WHERE id = ?",
                (flow_id,),
            ).fetchone()
            if row is None:
                return False
            meta = _parse_flow_meta(row[0])
            ei = meta.get(ERROR_INTEL_FLOW_META_KEY)
            if not isinstance(ei, dict):
                ei = {}
            else:
                ei = dict(ei)

            def _fill(key: str, value: Optional[str]) -> None:
                if value is None or value == "":
                    return
                old = ei.get(key)
                if old is None or old == "" or (
                    key == "attack_type" and old == ATTACK_TYPE_UNKNOWN
                ):
                    ei[key] = value

            _fill("parameter_uuid", parameter_uuid)
            _fill("parameter_name", parameter_name)
            _fill("attack_type", attack_type)
            if payload is not None:
                _fill("payload", str(payload))

            meta[ERROR_INTEL_FLOW_META_KEY] = ei
            conn.execute(
                "UPDATE flows SET flow_meta = ? WHERE id = ?",
                (json.dumps(meta, separators=(",", ":"), ensure_ascii=False), flow_id),
            )
            conn.commit()
        return True
    except sqlite3.Error:
        logger.exception(
            "Failed to persist error_intel flow_meta — flow_id=%s",
            flow_id,
        )
        return False


# ------------------------------------------------------------------ #
# DB load helpers                                                      #
# ------------------------------------------------------------------ #

def _load_flow_body(db_path: Path, flow_id: str) -> Optional[bytes]:
    """
    Purpose:
        Load response_body BLOB for a flow from the project database.
    Output:
        Body bytes, empty bytes if present-but-empty, or None if missing.
    Side effects:
        Opens a short-lived SQLite connection.
    """
    if not flow_id:
        return None
    try:
        with sqlite3.connect(str(db_path)) as conn:
            row = conn.execute(
                "SELECT response_body FROM flows WHERE id = ?",
                (flow_id,),
            ).fetchone()
    except sqlite3.Error:
        logger.exception(
            "Failed to load flow body for error intel — flow_id=%s",
            flow_id,
        )
        return None
    if row is None:
        return None
    return _coerce_body(row[0])


def _load_flow_headers(db_path: Path, flow_id: str) -> Any:
    """Load response_headers JSON/text for a flow. Side effects: DB read."""
    if not flow_id:
        return None
    try:
        with sqlite3.connect(str(db_path)) as conn:
            row = conn.execute(
                "SELECT response_headers FROM flows WHERE id = ?",
                (flow_id,),
            ).fetchone()
    except sqlite3.Error:
        return None
    if row is None:
        return None
    raw = row[0]
    if raw is None:
        return None
    if isinstance(raw, (dict, list)):
        return raw
    if isinstance(raw, str):
        try:
            return json.loads(raw) if raw else {}
        except (json.JSONDecodeError, TypeError):
            return raw
    return raw


def _load_flow_meta(db_path: Path, flow_id: str) -> dict[str, Any]:
    """Load flow_meta as a dict. Side effects: DB read."""
    if not flow_id:
        return {}
    try:
        with sqlite3.connect(str(db_path)) as conn:
            row = conn.execute(
                "SELECT flow_meta FROM flows WHERE id = ?",
                (flow_id,),
            ).fetchone()
    except sqlite3.Error:
        return {}
    if row is None:
        return {}
    return _parse_flow_meta(row[0])


def _load_flow_source(db_path: Path, flow_id: str) -> dict[str, Any]:
    """Load source / replay_reason / endpoint_id. Side effects: DB read."""
    if not flow_id:
        return {}
    try:
        with sqlite3.connect(str(db_path)) as conn:
            row = conn.execute(
                """
                SELECT source, replay_reason, endpoint_id, content_type,
                       status_code, path, host, url, role_id, module_id,
                       captured_at
                FROM flows WHERE id = ?
                """,
                (flow_id,),
            ).fetchone()
    except sqlite3.Error:
        return {}
    if row is None:
        return {}
    keys = (
        "source",
        "replay_reason",
        "endpoint_id",
        "content_type",
        "status_code",
        "path",
        "host",
        "url",
        "role_id",
        "module_id",
        "captured_at",
    )
    return {k: row[i] for i, k in enumerate(keys)}


def _load_flow_row(db_path: Path, flow_id: str) -> Optional[dict[str, Any]]:
    """Load a subset of flow columns for job building. Side effects: DB read."""
    base = _load_flow_source(db_path, flow_id)
    if not base:
        return None
    base["flow_meta"] = _load_flow_meta(db_path, flow_id)
    return base


def _parse_flow_meta(raw: Any) -> dict[str, Any]:
    if raw is None:
        return {}
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            data = json.loads(raw) if raw else {}
            return data if isinstance(data, dict) else {}
        except (json.JSONDecodeError, TypeError):
            return {}
    return {}


def _coerce_body(body: Any) -> Optional[bytes]:
    if body is None:
        return None
    if isinstance(body, memoryview):
        return body.tobytes()
    if isinstance(body, bytes):
        return body
    if isinstance(body, str):
        return body.encode("utf-8", errors="replace")
    try:
        return bytes(body)
    except (TypeError, ValueError):
        return None


def _coerce_status(status: Any) -> Optional[int]:
    if status is None or status == "":
        return None
    try:
        return int(status)
    except (TypeError, ValueError):
        return None


def _coerce_float(value: Any) -> Optional[float]:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _redact_payload(payload: Any) -> Optional[str]:
    """Truncate + secret-redact payload for observation storage (BUG-12)."""
    return _redact_payload_secrets(payload, max_len=DEFAULT_PAYLOAD_REDACTED_MAX)
