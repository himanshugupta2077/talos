"""
Module: talos.intruder.session

Purpose:
    Session helpers: build config from baseline flow, status machine helpers,
    enqueue segment jobs, cooperative control flags.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

from talos.intruder import db as intruder_db
from talos.intruder.config_schema import (
    ValidationError,
    default_config,
    merge_defaults,
    validate_config,
)
from talos.intruder.models import (
    CONFIG_SCHEMA_VERSION,
    STATUS_CANCELLED,
    STATUS_COMPLETED,
    STATUS_CONFIGURED,
    STATUS_DRAFT,
    STATUS_FAILED,
    STATUS_PAUSED,
    STATUS_QUEUED,
    STATUS_RUNNING,
)
from talos.intruder.template import discover_vars_from_baseline
from talos.scheduler import db as sched_db
from talos.scheduler.job import (
    PRIORITY_AUTO,
    PRIORITY_MANUAL,
    STATUS_PENDING,
    STATUS_RUNNING as JOB_RUNNING,
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_headers(raw: Any) -> dict[str, str]:
    if raw is None:
        return {}
    if isinstance(raw, dict):
        return {str(k): str(v) for k, v in raw.items()}
    if isinstance(raw, str):
        try:
            data = json.loads(raw)
            if isinstance(data, dict):
                return {str(k): str(v) for k, v in data.items()}
        except json.JSONDecodeError:
            return {}
    return {}


def create_session_from_flow(
    db_path: Path,
    project_id: str,
    flow_id: str,
    *,
    name: str = "",
) -> dict[str, Any]:
    """
    Create draft session with baseline snapshot copied into config.
    """
    flow = intruder_db.load_flow(db_path, flow_id)
    if flow is None:
        raise LookupError(f"flow_not_found:{flow_id}")

    headers = _parse_headers(flow.get("request_headers"))
    body = flow.get("request_body")
    if isinstance(body, memoryview):
        body = bytes(body)
    method = flow.get("method") or "GET"
    url = flow.get("url") or ""
    endpoint_id = flow.get("endpoint_id")
    norm_path = intruder_db.load_endpoint_normalized_path(db_path, endpoint_id) or ""

    # Auto-discover raw placeholders if present in baseline.
    discovered = discover_vars_from_baseline(method, url, headers, body)
    variables = []
    for n in discovered:
        variables.append({
            "name": n,
            "location": "raw",
            "original_value": None,
        })

    cfg = default_config()
    cfg["session"] = {
        "base_flow_id": flow["id"],
        "endpoint_id": endpoint_id,
        "role_id": flow.get("role_id"),
        "module_id": flow.get("module_id"),
        "project_id": project_id,
        "name": name or "",
    }
    cfg["template"] = {
        "method": method,
        "url": url,
        "headers": headers,
        "body": body.decode("utf-8", errors="replace") if isinstance(body, (bytes, bytearray)) else body,
        "variables": variables,
        "normalized_path": norm_path,
        "host": flow.get("host") or urlparse(url).netloc,
        "path": flow.get("path") or urlparse(url).path,
    }

    session = intruder_db.create_session(
        db_path,
        project_id,
        name=name or "",
        base_flow_id=flow["id"],
        endpoint_id=endpoint_id,
        config=cfg,
        status=STATUS_DRAFT,
        schema_version=CONFIG_SCHEMA_VERSION,
    )
    return session


def mark_configured(db_path: Path, session_id: str, config: dict[str, Any]) -> dict[str, Any]:
    validated, _ = validate_config(config, open_generators=True)
    sess = intruder_db.update_session(
        db_path,
        session_id,
        config=validated,
        status=STATUS_CONFIGURED,
    )
    assert sess is not None
    return sess


def enqueue_segment(
    db_path: Path,
    project_id: str,
    session_id: str,
    *,
    segment: int,
    priority: int = PRIORITY_MANUAL,
    endpoint_id: Optional[str] = None,
    base_flow_id: Optional[str] = None,
) -> str:
    """
    Enqueue one intruder_session job segment. Returns job_id.
    """
    from talos.scheduler.job import INTRUDER_SESSION

    job_id = str(uuid.uuid4())
    meta = {
        "session_id": session_id,
        "engine": "intruder",
        "schema_version": CONFIG_SCHEMA_VERSION,
        "segment": segment,
    }
    sched_db.enqueue_job(
        db_path=db_path,
        job_id=job_id,
        endpoint_id=endpoint_id,
        flow_id=base_flow_id,
        job_type=INTRUDER_SESSION,
        priority=priority,
        project_id=project_id,
        meta=json.dumps(meta),
    )
    return job_id


def session_has_active_job(
    db_path: Path,
    job_id: Optional[str],
    *,
    project_id: str = "",
) -> bool:
    if not job_id:
        return False
    try:
        job = sched_db.get_job(db_path, project_id, job_id)
    except ValueError:
        return False
    if job is None:
        return False
    return job.status in (STATUS_PENDING, JOB_RUNNING)


def run_session(
    db_path: Path,
    project_id: str,
    session_id: str,
    *,
    force: bool = False,
    right_now: bool = False,
) -> dict[str, Any]:
    """
    Validate and either enqueue first segment or return handle for foreground run.
    """
    session = intruder_db.get_session(db_path, session_id)
    if session is None:
        raise LookupError("session_not_found")

    if session["status"] in (STATUS_RUNNING, STATUS_QUEUED):
        if not force:
            raise RuntimeError("session_busy")
        # force: request cancel then proceed after setting cancel
        intruder_db.set_control_flag(db_path, session_id, "cancel")
        # Wait not possible here; mark cancelled and reset for re-run.
        intruder_db.update_session(
            db_path,
            session_id,
            status=STATUS_CANCELLED,
            control_flag=None,
            job_id=None,
        )
        session = intruder_db.get_session(db_path, session_id)
        assert session is not None

    if right_now and session_has_active_job(
        db_path, session.get("job_id"), project_id=project_id
    ):
        raise RuntimeError("session_busy")

    cfg, estimate = validate_config(session["config"], open_generators=True, force=force)
    intruder_db.update_session(db_path, session_id, config=cfg, status=STATUS_CONFIGURED)

    progress = dict(session.get("progress") or {})
    progress.setdefault("sent", 0)
    progress.setdefault("matched", 0)
    progress.setdefault("errors", 0)
    progress.setdefault("active_duration_s", 0.0)
    progress["estimate_total"] = estimate
    progress["segment"] = progress.get("segment") or 0
    progress["updated_at"] = _now()

    if right_now:
        progress["execution_mode"] = "foreground"
        intruder_db.update_session(
            db_path,
            session_id,
            status=STATUS_RUNNING,
            progress=progress,
            job_id=None,
            started_at=session.get("started_at") or _now(),
            control_flag=None,
            checkpoint=session.get("checkpoint") or {},
        )
        return {
            "session_id": session_id,
            "job_id": None,
            "status": STATUS_RUNNING,
            "execution_mode": "foreground",
            "estimate_attempts": estimate,
            "slice": cfg.get("slice"),
        }

    segment = int(progress.get("segment") or 0) + 1
    progress["segment"] = segment
    progress["execution_mode"] = "scheduler"
    progress["continuation_priority"] = PRIORITY_MANUAL
    job_id = enqueue_segment(
        db_path,
        project_id,
        session_id,
        segment=segment,
        priority=PRIORITY_MANUAL,
        endpoint_id=session.get("endpoint_id"),
        base_flow_id=session.get("base_flow_id"),
    )
    intruder_db.update_session(
        db_path,
        session_id,
        status=STATUS_QUEUED,
        progress=progress,
        job_id=job_id,
        started_at=session.get("started_at") or _now(),
        control_flag=None,
        checkpoint=session.get("checkpoint") or {},
        finished_at=None,
    )
    return {
        "session_id": session_id,
        "job_id": job_id,
        "status": STATUS_QUEUED,
        "execution_mode": "scheduler",
        "estimate_attempts": estimate,
        "slice": cfg.get("slice"),
    }


def resume_session(
    db_path: Path,
    project_id: str,
    session_id: str,
) -> dict[str, Any]:
    session = intruder_db.get_session(db_path, session_id)
    if session is None:
        raise LookupError("session_not_found")
    if session["status"] != STATUS_PAUSED:
        raise RuntimeError(f"invalid_status:{session['status']}")

    progress = dict(session.get("progress") or {})
    segment = int(progress.get("segment") or 0) + 1
    progress["segment"] = segment
    progress["execution_mode"] = "scheduler"
    progress["continuation_priority"] = PRIORITY_MANUAL
    progress["updated_at"] = _now()

    job_id = enqueue_segment(
        db_path,
        project_id,
        session_id,
        segment=segment,
        priority=PRIORITY_MANUAL,
        endpoint_id=session.get("endpoint_id"),
        base_flow_id=session.get("base_flow_id"),
    )
    intruder_db.update_session(
        db_path,
        session_id,
        status=STATUS_QUEUED,
        progress=progress,
        job_id=job_id,
        control_flag=None,
        finished_at=None,
    )
    return {
        "session_id": session_id,
        "job_id": job_id,
        "status": STATUS_QUEUED,
        "execution_mode": "scheduler",
    }


def pause_session(db_path: Path, session_id: str) -> dict[str, Any]:
    session = intruder_db.get_session(db_path, session_id)
    if session is None:
        raise LookupError("session_not_found")
    if session["status"] not in (STATUS_RUNNING, STATUS_QUEUED):
        if session["status"] == STATUS_PAUSED:
            return {"session_id": session_id, "status": STATUS_PAUSED, "noop": True}
        raise RuntimeError(f"invalid_status:{session['status']}")
    # If job pending, cancel it and pause immediately.
    job_id = session.get("job_id")
    project_id = session.get("project_id") or ""
    if job_id:
        try:
            job = sched_db.get_job(db_path, project_id, job_id)
        except ValueError:
            job = None
        if job and job.status == STATUS_PENDING:
            sched_db.cancel_job(db_path, job_id)
            intruder_db.update_session(
                db_path,
                session_id,
                status=STATUS_PAUSED,
                control_flag=None,
                job_id=None,
            )
            return {"session_id": session_id, "status": STATUS_PAUSED}
    # Running: cooperative pause via control_flag
    intruder_db.set_control_flag(db_path, session_id, "pause")
    return {"session_id": session_id, "status": session["status"], "control_flag": "pause"}


def stop_session(db_path: Path, session_id: str) -> dict[str, Any]:
    session = intruder_db.get_session(db_path, session_id)
    if session is None:
        raise LookupError("session_not_found")
    if session["status"] == STATUS_CANCELLED:
        return {"session_id": session_id, "status": STATUS_CANCELLED, "noop": True}
    if session["status"] in (STATUS_COMPLETED, STATUS_FAILED):
        raise RuntimeError(f"invalid_status:{session['status']}")

    job_id = session.get("job_id")
    project_id = session.get("project_id") or ""
    if job_id:
        try:
            job = sched_db.get_job(db_path, project_id, job_id)
        except ValueError:
            job = None
        if job and job.status == STATUS_PENDING:
            sched_db.cancel_job(db_path, job_id)
            intruder_db.update_session(
                db_path,
                session_id,
                status=STATUS_CANCELLED,
                control_flag=None,
                job_id=None,
                finished_at=_now(),
            )
            return {"session_id": session_id, "status": STATUS_CANCELLED}

    if session["status"] in (STATUS_RUNNING, STATUS_QUEUED, STATUS_PAUSED):
        if session["status"] == STATUS_PAUSED:
            intruder_db.update_session(
                db_path,
                session_id,
                status=STATUS_CANCELLED,
                control_flag=None,
                finished_at=_now(),
            )
            return {"session_id": session_id, "status": STATUS_CANCELLED}
        intruder_db.set_control_flag(db_path, session_id, "cancel")
        return {
            "session_id": session_id,
            "status": session["status"],
            "control_flag": "cancel",
        }

    raise RuntimeError(f"invalid_status:{session['status']}")


def continue_segment_job(
    db_path: Path,
    project_id: str,
    session_id: str,
    *,
    segment: int,
    endpoint_id: Optional[str] = None,
    base_flow_id: Optional[str] = None,
) -> str:
    """Enqueue continuation at PRIORITY_AUTO (10)."""
    progress_sess = intruder_db.get_session(db_path, session_id)
    progress = dict((progress_sess or {}).get("progress") or {})
    progress["segment"] = segment
    progress["continuation_priority"] = PRIORITY_AUTO
    progress["updated_at"] = _now()
    job_id = enqueue_segment(
        db_path,
        project_id,
        session_id,
        segment=segment,
        priority=PRIORITY_AUTO,
        endpoint_id=endpoint_id,
        base_flow_id=base_flow_id,
    )
    intruder_db.update_session(
        db_path,
        session_id,
        status=STATUS_RUNNING,
        progress=progress,
        job_id=job_id,
    )
    return job_id
