"""
Module: talos.passive.worker

Purpose:
    SourceScanWorker — daemon that drains PassiveScanQueue and runs the
    Passive Source Intelligence pipeline (Phases 4–12).

    Pipeline:
        1. Load response_body from flows by flow_id
        2. Defense-in-depth is_source_candidate()
        3. classify_source → SourceKind
        4. Respect PassiveScanConfig scan_* toggles and max_document_size
        5. normalize_body → scan text (not persisted on document row)
        6. SHA-256 body_hash → upsert_document + insert_occurrence
        7. If already scanned at SCANNER_VERSION → skip re-scan
        8. Else run detector orchestrator → insert_detection
        9. Source map extractor → virtual documents → scan (Phase 10)
       10. HTML inline script / bootstrap extractor → virtual docs (Phase 11)
       11. Auto-create findings for eligible secret detections (Phase 8)
       12. mark scan_status=scanned

    Never: outbound HTTP, archive JSONL, ReplayScheduler.

Architecture:
    PassiveScanQueue → SourceScanWorker._run() → _process(job)
        → load body → candidate → classify → normalize → registry
        → orchestrator → detections → findings bridge → mark scanned

Dependencies:
    hashlib, logging, sqlite3, threading, time
    talos.passive.{candidate, classifier, config helpers via db, constants,
                   detectors.orchestrator, finding_bridge, extractors,
                   models, normalize, queue, db}
    talos.projects.model.Project
Data flow:
    TalosAddon starts worker after FlowWorker; FlowWorker enqueues jobs
    after flow commit; this worker writes source_documents / occurrences /
    passive_detections / findings links.
Side effects:
    - Reads flows.response_body from project SQLite.
    - Writes source_documents + source_occurrences + passive_detections.
    - May create findings via finding_bridge.
    - Logs progress and errors; never raises into capture path.
"""

from __future__ import annotations

import hashlib
import logging
import sqlite3
import threading
import time
from pathlib import Path
from typing import Optional

from talos.passive.candidate import is_source_candidate
from talos.passive.classifier import classify_source, is_scannable_kind
from talos.passive.config import PassiveScanConfig
from talos.passive.constants import (
    SCAN_STATUS_SCANNED,
    SCAN_STATUS_TOO_LARGE,
    SCANNER_VERSION,
    SourceKind,
)
from talos.passive import db as passive_db
from talos.passive.detectors.orchestrator import DetectorOrchestrator
from talos.passive.extractors.html import extract_html_virtual_docs
from talos.passive.extractors.sourcemap import extract_sourcemap_virtual_docs
from talos.passive.finding_bridge import maybe_create_findings_for_detections
from talos.passive.models import Detection, PassiveScanJob, SourceDocument
from talos.passive.normalize import normalize_body
from talos.passive.queue import PassiveScanQueue
from talos.projects.model import Project

logger = logging.getLogger(__name__)

# Emit a rolling stats log line every N seconds while the worker is active.
_STATS_LOG_INTERVAL: float = 30.0

# Queue get timeout while running (seconds).
_POLL_TIMEOUT: float = 0.2


class SourceScanWorker:
    """
    Purpose:
        Consume PassiveScanJob items: register documents, run detectors,
        persist detections. One instance per proxy session.

    Fields:
        _project         — Active project (db_path).
        _queue           — Shared PassiveScanQueue drained by this worker.
        _stop_event      — Set to signal the run loop to exit cleanly.
        _thread          — Daemon thread running _run().
        _orchestrator    — Lazy DetectorOrchestrator (rules loaded on first scan).
        processed_count  — Jobs that completed without unexpected error.
        scanned_count    — Documents newly marked scanned this session.
        detection_count  — Detections persisted this session.
        skipped_dup_count— Documents already scanned at SCANNER_VERSION.
        skipped_count    — Not candidate / kind disabled / empty body / etc.
        error_count      — Jobs that failed with logged exception.
        _last_stats_at   — Monotonic timestamp of last stats log line.

    Invariant:
        start() should be called after FlowWorker so enqueued jobs land
        against committed flows. stop() drains remaining jobs.
    """

    def __init__(self, project: Project, queue: PassiveScanQueue) -> None:
        self._project = project
        self._queue = queue
        self._stop_event = threading.Event()
        self._thread = threading.Thread(
            target=self._run,
            daemon=True,
            name="talos-passive-scan",
        )
        self._orchestrator: Optional[DetectorOrchestrator] = None
        self.processed_count: int = 0
        self.scanned_count: int = 0
        self.detection_count: int = 0
        self.finding_count: int = 0
        self.skipped_dup_count: int = 0
        self.skipped_count: int = 0
        self.error_count: int = 0
        self._last_stats_at: float = time.monotonic()

    def start(self) -> None:
        """
        Purpose:
            Start the passive scan daemon thread.
        Side effects:
            - Spawns a new thread.
            - Logs start at INFO.
        """
        self._thread.start()
        logger.info(
            "SourceScanWorker started — project=%s db=%s queue_max=%d",
            self._project.id,
            self._project.db_path,
            self._queue.maxsize(),
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
            "SourceScanWorker stopped — project=%s processed=%d scanned=%d "
            "detections=%d findings=%d skipped_dup=%d skipped=%d errors=%d "
            "queue_drops=%d enqueued=%d",
            self._project.id,
            self.processed_count,
            self.scanned_count,
            self.detection_count,
            self.finding_count,
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
                    "Unexpected error in SourceScanWorker._process — "
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
                    "Unexpected error in SourceScanWorker drain — "
                    "flow_id=%s — skipping",
                    getattr(job, "flow_id", "?"),
                )

    def _process(self, job: PassiveScanJob) -> None:
        """
        Purpose:
            Handle one PassiveScanJob: registry + detector pipeline.
        Input:
            job — minimal payload; body reloaded from DB.
        Side effects:
            - Reads flow body; may write document/occurrence/detection rows.
            - Updates session counters.
        """
        if not isinstance(job, PassiveScanJob):
            logger.warning(
                "Dropping corrupt passive job — expected PassiveScanJob, got %s",
                type(job).__name__,
            )
            self.skipped_count += 1
            return

        db_path = self._project.db_path
        config = passive_db.get_config(db_path)
        if not config.enabled:
            self.skipped_count += 1
            logger.debug(
                "Passive scan disabled — skip flow_id=%s",
                job.flow_id,
            )
            return

        body = _load_flow_body(db_path, job.flow_id)
        if body is None or len(body) == 0:
            self.skipped_count += 1
            logger.debug(
                "Passive scan skip — empty/missing body flow_id=%s",
                job.flow_id,
            )
            return

        # Defense in depth: FlowWorker already gated; re-check with body.
        if not is_source_candidate(
            content_type=job.content_type,
            path=job.path,
            body=body,
            truncated=job.truncated,
        ):
            self.skipped_count += 1
            logger.debug(
                "Passive scan skip — not a source candidate flow_id=%s path=%s",
                job.flow_id,
                job.path,
            )
            return

        kind = classify_source(
            content_type=job.content_type,
            path=job.path,
            body=body,
        )
        if not is_scannable_kind(kind) or not _kind_enabled(config, kind):
            self.skipped_count += 1
            logger.debug(
                "Passive scan skip — kind=%s not scannable/enabled flow_id=%s",
                kind.value,
                job.flow_id,
            )
            return

        body_size = len(body)
        body_hash = hashlib.sha256(body).hexdigest()

        # Too large: still register document + occurrence for UI inventory,
        # but do not run detectors.
        if body_size > int(config.max_document_size):
            doc, _created = passive_db.upsert_document(
                db_path,
                job.project_id,
                body_hash,
                kind,
                body_size,
                truncated=job.truncated,
                first_flow_id=job.flow_id,
                observed_at=job.observed_at,
            )
            _insert_job_occurrence(db_path, doc.id, job)
            if doc.scanner_version != SCANNER_VERSION or doc.scan_status != SCAN_STATUS_TOO_LARGE:
                passive_db.mark_document_status(
                    db_path,
                    doc.id,
                    SCAN_STATUS_TOO_LARGE,
                    error_message=f"body_size={body_size} > max_document_size={config.max_document_size}",
                )
            self.skipped_count += 1
            self.processed_count += 1
            return

        norm = normalize_body(
            body,
            content_type=job.content_type,
            truncated=job.truncated,
        )

        doc, _created = passive_db.upsert_document(
            db_path,
            job.project_id,
            body_hash,
            kind,
            body_size,
            truncated=job.truncated,
            first_flow_id=job.flow_id,
            observed_at=job.observed_at,
        )
        occurrence = _insert_job_occurrence(db_path, doc.id, job)

        # Already scanned at this SCANNER_VERSION → occurrence only.
        if (
            doc.scanner_version == SCANNER_VERSION
            and doc.scan_status == SCAN_STATUS_SCANNED
        ):
            self.skipped_dup_count += 1
            self.processed_count += 1
            logger.debug(
                "Passive scan skip dup — document_id=%s body_hash=%s…",
                doc.id,
                body_hash[:12],
            )
            return

        # Detector pipeline (Phases 5–10). Failures mark error, never crash loop.
        try:
            orch = self._get_orchestrator(config)
            scan_text = norm.text or ""
            stored_detections = self._scan_and_persist(
                db_path=db_path,
                orch=orch,
                text=scan_text,
                document_id=doc.id,
                occurrence_id=occurrence.id if occurrence else None,
            )

            # Phase 10: source map sourcesContent → virtual docs → scan.
            if config.scan_sourcemaps and (
                kind == SourceKind.SOURCEMAP
                or path_looks_like_sourcemap(job.path, job.content_type)
            ):
                virtual_dets = self._scan_sourcemap_virtuals(
                    db_path=db_path,
                    config=config,
                    orch=orch,
                    parent_doc=doc,
                    job=job,
                    map_text=scan_text,
                    parent_occurrence_id=occurrence.id if occurrence else None,
                )
                stored_detections.extend(virtual_dets)

            # Phase 11: HTML inline <script> / bootstrap JSON → virtual docs.
            if kind == SourceKind.HTML and config.scan_html:
                html_dets = self._scan_html_virtuals(
                    db_path=db_path,
                    config=config,
                    orch=orch,
                    parent_doc=doc,
                    job=job,
                    html_text=scan_text,
                    parent_occurrence_id=occurrence.id if occurrence else None,
                )
                stored_detections.extend(html_dets)

            # Phase 8: auto-findings for eligible detections.
            n_findings = maybe_create_findings_for_detections(
                db_path,
                job.project_id,
                stored_detections,
                config=config,
            )
            self.finding_count += n_findings

            passive_db.mark_document_scanned(
                db_path,
                doc.id,
                SCANNER_VERSION,
            )
            self.scanned_count += 1
            self.processed_count += 1
            logger.debug(
                "Passive scan complete — document_id=%s kind=%s size=%d "
                "detections=%d findings=%d flow_id=%s",
                doc.id,
                kind.value,
                body_size,
                len(stored_detections),
                n_findings,
                job.flow_id,
            )
        except Exception as exc:
            self.error_count += 1
            logger.exception(
                "Passive detector pipeline failed — document_id=%s flow_id=%s",
                doc.id,
                job.flow_id,
            )
            try:
                passive_db.mark_document_error(
                    db_path,
                    doc.id,
                    f"{type(exc).__name__}: {exc}",
                )
            except Exception:
                logger.exception(
                    "Failed to mark document error — document_id=%s",
                    doc.id,
                )
            self.processed_count += 1

    def _get_orchestrator(self, config: PassiveScanConfig) -> DetectorOrchestrator:
        """
        Purpose:
            Lazy-build DetectorOrchestrator with current project config.
        Input:
            config — PassiveScanConfig from DB
        Output:
            DetectorOrchestrator (rebuilt if config limits change)
        Side effects:
            May load YAML rules on first construction.
        """
        if self._orchestrator is None:
            self._orchestrator = DetectorOrchestrator(config=config)
            return self._orchestrator
        # Refresh caps if config changed mid-session
        self._orchestrator.config = config
        return self._orchestrator

    def _scan_and_persist(
        self,
        *,
        db_path: Path,
        orch: DetectorOrchestrator,
        text: str,
        document_id: str,
        occurrence_id: Optional[str],
    ) -> list[Detection]:
        """
        Purpose:
            Run detector orchestrator on text and persist non-duplicate rows.
        Output:
            list of Detection objects as stored (with ids; raw_value preserved
            from in-memory matches when present).
        Side effects:
            insert_detection; updates detection_count.
        """
        detections = orch.scan_text(
            text,
            document_id=document_id,
            occurrence_id=occurrence_id,
        )
        stored: list[Detection] = []
        for det in detections:
            raw = det.raw_value
            row = passive_db.insert_detection(db_path, det)
            if row is None:
                continue
            # Preserve raw_value for finding evidence (not in DB list path).
            if raw and not row.raw_value:
                row.raw_value = raw
            self.detection_count += 1
            stored.append(row)
        return stored

    def _scan_sourcemap_virtuals(
        self,
        *,
        db_path: Path,
        config: PassiveScanConfig,
        orch: DetectorOrchestrator,
        parent_doc: SourceDocument,
        job: PassiveScanJob,
        map_text: str,
        parent_occurrence_id: Optional[str],
    ) -> list[Detection]:
        """
        Purpose:
            Parse sourcesContent from a source map; register virtual
            documents under parent_document_id; scan each for secrets.
        Output:
            Combined Detection list from all virtual sources.
        Side effects:
            May upsert virtual documents + occurrences + detections.
        """
        all_dets: list[Detection] = []
        try:
            virtuals = extract_sourcemap_virtual_docs(
                map_text,
                parent_document_id=parent_doc.id,
                project_id=job.project_id,
            )
        except Exception:
            logger.exception(
                "Source map extract failed — document_id=%s",
                parent_doc.id,
            )
            return all_dets

        for virt in virtuals:
            try:
                body_bytes = (virt.text or "").encode("utf-8", errors="replace")
                if len(body_bytes) > int(config.max_document_size):
                    continue
                body_hash = hashlib.sha256(body_bytes).hexdigest()
                vdoc, _created = passive_db.upsert_document(
                    db_path,
                    job.project_id,
                    body_hash,
                    virt.source_kind,
                    len(body_bytes),
                    truncated=False,
                    first_flow_id=job.flow_id,
                    observed_at=job.observed_at,
                    parent_document_id=parent_doc.id,
                    logical_source_name=virt.logical_source_name,
                )
                # Already scanned virtual at this version → skip detectors.
                if (
                    vdoc.scanner_version == SCANNER_VERSION
                    and vdoc.scan_status == SCAN_STATUS_SCANNED
                ):
                    continue
                vocc = passive_db.insert_occurrence(
                    db_path,
                    document_id=vdoc.id,
                    flow_id=job.flow_id,
                    url=job.url,
                    host=job.host,
                    path=virt.logical_source_name or job.path,
                    content_type="application/javascript",
                    observed_at=job.observed_at,
                    role_id=job.role_id or "",
                    module_id=job.module_id or "",
                    endpoint_id=job.endpoint_id,
                    logical_source_name=virt.logical_source_name,
                )
                dets = self._scan_and_persist(
                    db_path=db_path,
                    orch=orch,
                    text=virt.text or "",
                    document_id=vdoc.id,
                    occurrence_id=vocc.id if vocc else parent_occurrence_id,
                )
                all_dets.extend(dets)
                passive_db.mark_document_scanned(
                    db_path, vdoc.id, SCANNER_VERSION
                )
            except Exception:
                logger.exception(
                    "Virtual source map scan failed — parent=%s virtual=%s",
                    parent_doc.id,
                    getattr(virt, "logical_source_name", "?"),
                )
        return all_dets

    def _scan_html_virtuals(
        self,
        *,
        db_path: Path,
        config: PassiveScanConfig,
        orch: DetectorOrchestrator,
        parent_doc: SourceDocument,
        job: PassiveScanJob,
        html_text: str,
        parent_occurrence_id: Optional[str],
    ) -> list[Detection]:
        """
        Purpose:
            Extract inline scripts / bootstrap JSON from HTML; register
            virtual documents; scan each for secrets. Never fetches src=.
        Output:
            Combined Detection list from all virtual sources.
        Side effects:
            May upsert virtual documents + occurrences + detections.
        """
        all_dets: list[Detection] = []
        try:
            virtuals = extract_html_virtual_docs(
                html_text,
                parent_document_id=parent_doc.id,
                project_id=job.project_id,
            )
        except Exception:
            logger.exception(
                "HTML extract failed — document_id=%s",
                parent_doc.id,
            )
            return all_dets

        for virt in virtuals:
            try:
                body_bytes = (virt.text or "").encode("utf-8", errors="replace")
                if len(body_bytes) > int(config.max_document_size):
                    continue
                # Skip kinds disabled in config
                if not _kind_enabled(config, virt.source_kind):
                    continue
                body_hash = hashlib.sha256(body_bytes).hexdigest()
                vdoc, _created = passive_db.upsert_document(
                    db_path,
                    job.project_id,
                    body_hash,
                    virt.source_kind,
                    len(body_bytes),
                    truncated=bool(virt.truncated),
                    first_flow_id=job.flow_id,
                    observed_at=job.observed_at,
                    parent_document_id=parent_doc.id,
                    logical_source_name=virt.logical_source_name,
                )
                if (
                    vdoc.scanner_version == SCANNER_VERSION
                    and vdoc.scan_status == SCAN_STATUS_SCANNED
                ):
                    continue
                ct = (
                    "application/javascript"
                    if virt.source_kind == SourceKind.JAVASCRIPT
                    else "application/json"
                    if virt.source_kind == SourceKind.JSON
                    else "text/plain"
                )
                vocc = passive_db.insert_occurrence(
                    db_path,
                    document_id=vdoc.id,
                    flow_id=job.flow_id,
                    url=job.url,
                    host=job.host,
                    path=virt.logical_source_name or job.path,
                    content_type=ct,
                    observed_at=job.observed_at,
                    role_id=job.role_id or "",
                    module_id=job.module_id or "",
                    endpoint_id=job.endpoint_id,
                    logical_source_name=virt.logical_source_name,
                )
                dets = self._scan_and_persist(
                    db_path=db_path,
                    orch=orch,
                    text=virt.text or "",
                    document_id=vdoc.id,
                    occurrence_id=vocc.id if vocc else parent_occurrence_id,
                )
                all_dets.extend(dets)
                passive_db.mark_document_scanned(
                    db_path, vdoc.id, SCANNER_VERSION
                )
            except Exception:
                logger.exception(
                    "Virtual HTML scan failed — parent=%s virtual=%s",
                    parent_doc.id,
                    getattr(virt, "logical_source_name", "?"),
                )
        return all_dets

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
            "Passive scan stats — processed=%d scanned=%d detections=%d "
            "findings=%d skipped_dup=%d skipped=%d errors=%d "
            "queue_depth=%d queue_drops=%d",
            self.processed_count,
            self.scanned_count,
            self.detection_count,
            self.finding_count,
            self.skipped_dup_count,
            self.skipped_count,
            self.error_count,
            self._queue.size(),
            self._queue.dropped_job_count,
        )


def path_looks_like_sourcemap(path: str, content_type: str = "") -> bool:
    """
    Purpose:
        Cheap check whether a response is a source map (.map path / CT).
    Side effects: None.
    """
    p = (path or "").split("?", 1)[0].lower()
    if p.endswith(".map"):
        return True
    ct = (content_type or "").split(";", 1)[0].strip().lower()
    if ct in (
        "application/json",
        "application/octet-stream",
    ) and p.endswith(".map"):
        return True
    return False


# ------------------------------------------------------------------ #
# Helpers                                                              #
# ------------------------------------------------------------------ #

def _kind_enabled(config: PassiveScanConfig, kind: SourceKind) -> bool:
    """
    Purpose:
        Map SourceKind to PassiveScanConfig scan_* toggle.
    Input:
        config — loaded PassiveScanConfig
        kind   — classified kind
    Output:
        True when scanning that kind is enabled.
    Side effects: None.
    """
    mapping = {
        SourceKind.HTML: config.scan_html,
        SourceKind.JAVASCRIPT: config.scan_javascript,
        SourceKind.JSON: config.scan_json,
        SourceKind.XML: config.scan_xml,
        SourceKind.TEXT: config.scan_text,
        SourceKind.CSS: config.scan_css,
        SourceKind.SOURCEMAP: config.scan_sourcemaps,
        SourceKind.WASM: config.scan_wasm,
    }
    return bool(mapping.get(kind, False))


def _load_flow_body(db_path: Path, flow_id: str) -> Optional[bytes]:
    """
    Purpose:
        Load response_body BLOB for a flow from the project database.
    Input:
        db_path — project talos.db
        flow_id — flows.id
    Output:
        Body bytes, empty bytes if present-but-empty, or None if missing.
    Side effects:
        Opens a short-lived SQLite connection (read-only intent).
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
            "Failed to load flow body for passive scan — flow_id=%s",
            flow_id,
        )
        return None
    if row is None:
        return None
    body = row[0]
    if body is None:
        return None
    if isinstance(body, memoryview):
        return body.tobytes()
    if isinstance(body, bytes):
        return body
    # Unexpected type (e.g. str from mis-store) — encode best-effort
    if isinstance(body, str):
        return body.encode("utf-8", errors="replace")
    return bytes(body)


def _insert_job_occurrence(
    db_path: Path,
    document_id: str,
    job: PassiveScanJob,
):
    """
    Purpose:
        Insert a source_occurrences row from PassiveScanJob fields.
    Input:
        db_path / document_id / job
    Output:
        SourceOccurrence as stored
    Side effects:
        INSERT via passive_db.insert_occurrence.
    """
    return passive_db.insert_occurrence(
        db_path,
        document_id=document_id,
        flow_id=job.flow_id,
        url=job.url,
        host=job.host,
        path=job.path,
        content_type=job.content_type,
        observed_at=job.observed_at,
        role_id=job.role_id or "",
        module_id=job.module_id or "",
        endpoint_id=job.endpoint_id,
    )


def maybe_enqueue_passive_scan(
    *,
    passive_queue: Optional[PassiveScanQueue],
    db_path: Path,
    project_id: str,
    flow: dict,
    endpoint_id: Optional[str],
    content_type: str,
) -> bool:
    """
    Purpose:
        Cheap FlowWorker post-commit hook: if passive scan is enabled and
        the response looks source-like, enqueue a PassiveScanJob.

        Never raises. Never blocks. Safe to call on every persisted flow.

    Input:
        passive_queue — PassiveScanQueue or None (no-op when None)
        db_path       — project DB (config read)
        project_id    — owning project
        flow          — enriched flow dict (must include flow_id, path, …)
        endpoint_id   — resolved endpoint UUID or None
        content_type  — response Content-Type already extracted by worker

    Output:
        True if a job was enqueued, False otherwise.

    Side effects:
        - May read passive_scan_config.
        - May put a job on passive_queue (drop-on-full inside queue).
        - Logs DEBUG/WARNING only; errors swallowed.
    """
    if passive_queue is None:
        return False
    try:
        config = passive_db.get_config(db_path)
        if not config.enabled:
            return False

        path = flow.get("path") or ""
        status = flow.get("status_code")
        body = flow.get("response_body")
        truncated = bool(flow.get("response_body_truncated"))

        # Prefer bytes body when present; None is OK (CT/path-only gate).
        body_bytes: Optional[bytes]
        if body is None:
            body_bytes = None
        elif isinstance(body, bytes):
            body_bytes = body
        elif isinstance(body, memoryview):
            body_bytes = body.tobytes()
        elif isinstance(body, str):
            body_bytes = body.encode("utf-8", errors="replace")
        else:
            body_bytes = None

        status_code: Optional[int] = None
        if status is not None and status != "":
            try:
                status_code = int(status)
            except (TypeError, ValueError):
                status_code = None

        if not is_source_candidate(
            content_type=content_type,
            path=path,
            status_code=status_code,
            body=body_bytes,
            truncated=truncated,
        ):
            return False

        flow_id = flow.get("flow_id") or ""
        if not flow_id:
            return False

        job = PassiveScanJob(
            project_id=project_id,
            flow_id=flow_id,
            endpoint_id=endpoint_id,
            url=flow.get("url") or "",
            host=flow.get("host") or "",
            path=path,
            content_type=content_type or "",
            truncated=truncated,
            role_id=flow.get("role_id") or "",
            module_id=flow.get("module_id") or "",
            observed_at=flow.get("request_start")
            or flow.get("captured_at")
            or "",
        )
        return passive_queue.put(job)
    except Exception:
        # Capture path must never fail because of passive scan.
        logger.exception(
            "Passive enqueue failed — flow_id=%s — capture unaffected",
            flow.get("flow_id", "?"),
        )
        return False
