"""
Control Panel Intruder API (`/api/intruder`).

Purpose:
    Thin FastAPI surface over the Intruder engine + CLI for the Control Panel
    workbench. Reads use ``talos.intruder.db`` in-process. Mutations CLI-wrap
    via ``run_scoped`` (never invent engine semantics).

Architecture (docs/design-control-panel-intruder.md):
    - Configure = bulk ``session configure --file`` after writing durable
      wordlist artifacts under project data dir (K5a).
    - Run never uses ``--right-now`` (K6).
    - Clone copies artifacts and rewrites path-backed options (K14).
    - Delete removes artifact dir after CLI success.

Data flow:
    UI draft → POST configure (artifacts + full config) → CLI configure
    UI validate/run/pause/… → CLI → poll GET status/results
"""

from __future__ import annotations

import json
import re
import shutil
import sys
from copy import deepcopy
from pathlib import Path
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from .. import cli, config, db

router = APIRouter(prefix="/api/intruder", tags=["intruder"])

_VAR_NAME_RE = re.compile(r"^[A-Za-z0-9_]+$")
_PATH_BACKED_GENERATORS = frozenset({"wordlist", "csv", "json"})


# ------------------------------------------------------------------ #
# Helpers                                                              #
# ------------------------------------------------------------------ #


def _ensure_talos_on_path() -> None:
    root = str(config.TALOS_ROOT)
    if root not in sys.path:
        sys.path.insert(0, root)


def _project_record(project_id: str) -> dict:
    record = db.get_project_record(project_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"Project '{project_id}' not found")
    return record


def _db_path(project_id: str) -> Path:
    record = _project_record(project_id)
    return config.project_db_path(project_id, record)


def _parse_json_stdout(stdout: str) -> Any:
    text = (stdout or "").strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # CLI may print human lines before/after JSON in edge cases
        for line in reversed(text.splitlines()):
            line = line.strip()
            if line.startswith("{") or line.startswith("["):
                try:
                    return json.loads(line)
                except json.JSONDecodeError:
                    continue
    return None


def _last_step_payload(steps: list) -> Any:
    if not steps:
        return None
    last = steps[-1]
    stdout = getattr(last, "stdout", None)
    if stdout is None and isinstance(last, dict):
        stdout = last.get("stdout")
    return _parse_json_stdout(stdout or "")


def _require_ok(steps: list, *, label: str = "Intruder command") -> None:
    if not steps:
        raise HTTPException(status_code=500, detail=f"{label}: no steps returned")
    last = steps[-1]
    ok = getattr(last, "ok", None)
    if ok is None and isinstance(last, dict):
        ok = last.get("ok")
    if not ok:
        stderr = getattr(last, "stderr", None) or ""
        stdout = getattr(last, "stdout", None) or ""
        if isinstance(last, dict):
            stderr = last.get("stderr") or stderr
            stdout = last.get("stdout") or stdout
        detail = (stderr or stdout or f"{label} failed").strip()
        # Map CLI precondition / usage to 400
        raise HTTPException(status_code=400, detail=detail[:2000])


def _steps_dicts(steps: list) -> list[dict]:
    out = []
    for r in steps:
        if hasattr(r, "to_dict"):
            out.append(r.to_dict())
        elif isinstance(r, dict):
            out.append(r)
        else:
            out.append({"ok": False, "stdout": "", "stderr": str(r)})
    return out


def intruder_artifact_dir(project_id: str, session_id: str, record: dict | None = None) -> Path:
    rec = record if record is not None else _project_record(project_id)
    return config.project_data_dir(project_id, rec) / "intruder" / "artifacts" / session_id


def _sanitize_var(var: str) -> str:
    name = (var or "").strip()
    if not _VAR_NAME_RE.match(name):
        raise HTTPException(
            status_code=400,
            detail=f"Invalid variable name '{var}': use letters, digits, underscore only",
        )
    return name


def write_wordlist(
    project_id: str,
    session_id: str,
    var: str,
    text: str,
    record: dict | None = None,
) -> Path:
    """Write durable wordlist under project artifacts; enforce engine size caps."""
    _ensure_talos_on_path()
    from talos.intruder.models import (
        DEFAULT_WORDLIST_MAX_BYTES,
        DEFAULT_WORDLIST_MAX_LINES,
    )

    var = _sanitize_var(var)
    content = text if text is not None else ""
    # Normalize newlines
    if content and not content.endswith("\n") and content.strip():
        # keep as-is; generators tolerate missing trailing newline
        pass
    line_count = len(content.splitlines()) if content else 0
    byte_len = len(content.encode("utf-8"))
    if line_count > DEFAULT_WORDLIST_MAX_LINES:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Wordlist for '{var}' has {line_count} lines "
                f"(max {DEFAULT_WORDLIST_MAX_LINES})"
            ),
        )
    if byte_len > DEFAULT_WORDLIST_MAX_BYTES:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Wordlist for '{var}' is {byte_len} bytes "
                f"(max {DEFAULT_WORDLIST_MAX_BYTES})"
            ),
        )
    d = intruder_artifact_dir(project_id, session_id, record)
    d.mkdir(parents=True, exist_ok=True)
    path = d / f"{var}.txt"
    path.write_text(content, encoding="utf-8")
    return path.resolve()


def write_artifact_file(
    project_id: str,
    session_id: str,
    var: str,
    kind: str,
    text: str,
    record: dict | None = None,
) -> Path:
    """Write path-backed generator artifact (wordlist/csv/json)."""
    var = _sanitize_var(var)
    kind = (kind or "wordlist").lower()
    if kind not in _PATH_BACKED_GENERATORS:
        raise HTTPException(status_code=400, detail=f"Unsupported artifact kind '{kind}'")
    if kind == "wordlist":
        return write_wordlist(project_id, session_id, var, text, record)
    d = intruder_artifact_dir(project_id, session_id, record)
    d.mkdir(parents=True, exist_ok=True)
    ext = ".csv" if kind == "csv" else ".json"
    path = d / f"{var}{ext}"
    path.write_text(text if text is not None else "", encoding="utf-8")
    return path.resolve()


def remove_artifact_dir(project_id: str, session_id: str, record: dict | None = None) -> None:
    d = intruder_artifact_dir(project_id, session_id, record)
    if d.is_dir():
        shutil.rmtree(d, ignore_errors=True)


def _baseline_label(sess: dict[str, Any]) -> str | None:
    """Compact method + path/url for session list chips."""
    cfg = sess.get("config") or {}
    if not isinstance(cfg, dict):
        return None
    template = cfg.get("template") or {}
    if not isinstance(template, dict):
        return None
    method = (template.get("method") or "GET").upper()
    path = template.get("normalized_path")
    url = template.get("url") or ""
    if path:
        target = str(path)
    elif url:
        # Prefer path portion of URL for density
        try:
            from urllib.parse import urlparse

            p = urlparse(str(url))
            target = p.path or str(url)
            if p.query:
                target = f"{target}?{p.query}"
        except Exception:
            target = str(url)
    else:
        return None
    if len(target) > 64:
        target = target[:61] + "…"
    return f"{method} {target}"


def _session_public(sess: dict[str, Any]) -> dict[str, Any]:
    progress = sess.get("progress") or {}
    if not isinstance(progress, dict):
        progress = {}
    return {
        "id": sess["id"],
        "name": sess.get("name") or "",
        "status": sess["status"],
        "base_flow_id": sess.get("base_flow_id"),
        "endpoint_id": sess.get("endpoint_id"),
        "job_id": sess.get("job_id"),
        "control_flag": sess.get("control_flag"),
        "progress": progress,
        "config": sess.get("config") or {},
        "checkpoint": sess.get("checkpoint") or {},
        "created_at": sess.get("created_at"),
        "updated_at": sess.get("updated_at"),
        "started_at": sess.get("started_at"),
        "finished_at": sess.get("finished_at"),
        "failure_reason": sess.get("failure_reason"),
        "schema_version": sess.get("schema_version"),
        "estimate_attempts": progress.get("estimate_total"),
        "baseline_label": _baseline_label(sess),
    }


def _session_summary(sess: dict[str, Any]) -> dict[str, Any]:
    progress = sess.get("progress") or {}
    if not isinstance(progress, dict):
        progress = {}
    return {
        "id": sess["id"],
        "name": sess.get("name") or "",
        "status": sess["status"],
        "base_flow_id": sess.get("base_flow_id"),
        "endpoint_id": sess.get("endpoint_id"),
        "job_id": sess.get("job_id"),
        "progress": {
            "sent": progress.get("sent"),
            "matched": progress.get("matched"),
            "interesting": progress.get("interesting"),
            "estimate_total": progress.get("estimate_total"),
            "active_duration_s": progress.get("active_duration_s"),
            "stopped_reason": progress.get("stopped_reason"),
        },
        "estimate_attempts": progress.get("estimate_total"),
        "updated_at": sess.get("updated_at"),
        "created_at": sess.get("created_at"),
        "failure_reason": sess.get("failure_reason"),
        "baseline_label": _baseline_label(sess),
    }


def _count_results_filtered(
    db_path: Path,
    session_id: str,
    *,
    interesting_only: bool = False,
    status_code: int | None = None,
) -> int:
    """Router-local count that honors status_code (engine count_results does not)."""
    clauses = ["session_id = ?"]
    params: list[Any] = [session_id]
    if interesting_only:
        clauses.append("interesting = 1")
    if status_code is not None:
        clauses.append("status_code = ?")
        params.append(status_code)
    sql = f"SELECT COUNT(*) AS n FROM intruder_results WHERE {' AND '.join(clauses)}"
    try:
        row = db.query_one(db_path, sql, tuple(params))
        return int(row["n"]) if row else 0
    except Exception:
        return 0


def _load_session(project_id: str, session_id: str) -> dict[str, Any]:
    _ensure_talos_on_path()
    from talos.intruder import db as intruder_db

    db_path = _db_path(project_id)
    sess = intruder_db.get_session(db_path, session_id)
    if sess is None:
        raise HTTPException(status_code=404, detail=f"Session '{session_id}' not found")
    if sess.get("project_id") and sess["project_id"] != project_id:
        raise HTTPException(status_code=404, detail=f"Session '{session_id}' not found")
    return sess


def _apply_artifacts_to_config(
    project_id: str,
    session_id: str,
    config_doc: dict[str, Any],
    artifacts: dict[str, Any] | None,
    record: dict,
) -> dict[str, Any]:
    """Write artifact files and stamp absolute paths into payload_sets."""
    cfg = deepcopy(config_doc) if config_doc else {}
    payload_sets = cfg.setdefault("payload_sets", {})
    if not isinstance(payload_sets, dict):
        payload_sets = {}
        cfg["payload_sets"] = payload_sets

    if not artifacts:
        return cfg

    for var, art in artifacts.items():
        if not isinstance(art, dict):
            continue
        kind = (art.get("kind") or "wordlist").lower()
        text = art.get("text")
        if text is None:
            continue
        path = write_artifact_file(project_id, session_id, var, kind, str(text), record)
        entry = payload_sets.get(var) if isinstance(payload_sets.get(var), dict) else {}
        entry = dict(entry)
        entry["generator"] = kind
        opts = dict(entry.get("options") or {})
        opts["path"] = str(path)
        entry["options"] = opts
        entry.setdefault("processors", [])
        payload_sets[var] = entry

    return cfg


def _copy_clone_artifacts(
    project_id: str,
    src_id: str,
    dst_id: str,
    config_doc: dict[str, Any],
    record: dict,
) -> dict[str, Any]:
    """
    K14: copy path-backed artifacts into the new session dir and rewrite paths.
    """
    cfg = deepcopy(config_doc) if config_doc else {}
    payload_sets = cfg.get("payload_sets") or {}
    if not isinstance(payload_sets, dict):
        return cfg

    src_dir = intruder_artifact_dir(project_id, src_id, record)
    dst_dir = intruder_artifact_dir(project_id, dst_id, record)
    dst_dir.mkdir(parents=True, exist_ok=True)

    new_sets: dict[str, Any] = {}
    for var, entry in payload_sets.items():
        if not isinstance(entry, dict):
            new_sets[var] = entry
            continue
        gen = (entry.get("generator") or "").lower()
        opts = dict(entry.get("options") or {})
        path_str = opts.get("path")
        if gen in _PATH_BACKED_GENERATORS and path_str:
            src_path = Path(str(path_str))
            # Prefer file under src_dir; else copy absolute path if readable
            if not src_path.is_file():
                candidate = src_dir / src_path.name
                if candidate.is_file():
                    src_path = candidate
            if src_path.is_file():
                ext = src_path.suffix or (
                    ".txt" if gen == "wordlist" else (".csv" if gen == "csv" else ".json")
                )
                safe = _sanitize_var(var) if _VAR_NAME_RE.match(var or "") else re.sub(
                    r"[^A-Za-z0-9_]", "_", var or "payload"
                )
                dst_path = dst_dir / f"{safe}{ext}"
                shutil.copy2(src_path, dst_path)
                opts["path"] = str(dst_path.resolve())
                entry = dict(entry)
                entry["options"] = opts
        new_sets[var] = entry

    cfg["payload_sets"] = new_sets
    return cfg


# ------------------------------------------------------------------ #
# Request bodies                                                       #
# ------------------------------------------------------------------ #


class CreateSessionBody(BaseModel):
    flow_id: str = Field(..., min_length=1)
    name: str = ""


class ConfigureBody(BaseModel):
    expected_updated_at: str = Field(..., min_length=1)
    force: bool = False
    config: dict[str, Any]
    artifacts: Optional[dict[str, Any]] = None


class ForceBody(BaseModel):
    force: bool = False


class CloneBody(BaseModel):
    name: str = ""


# ------------------------------------------------------------------ #
# Reads                                                                #
# ------------------------------------------------------------------ #


@router.get("/summary")
def summary(project_id: str):
    """Hub KPIs: running, paused, interesting_total."""
    _ensure_talos_on_path()
    from talos.intruder import db as intruder_db

    db_path = _db_path(project_id)
    sessions = intruder_db.list_sessions(db_path, project_id, limit=500)
    running = sum(1 for s in sessions if s.get("status") == "running")
    paused = sum(1 for s in sessions if s.get("status") == "paused")
    queued = sum(1 for s in sessions if s.get("status") == "queued")

    interesting_total = 0
    last_activity_at = None
    try:
        row = db.query_one(
            db_path,
            """
            SELECT COUNT(*) AS n FROM intruder_results
            WHERE interesting = 1
              AND session_id IN (
                SELECT id FROM intruder_sessions WHERE project_id = ?
              )
            """,
            (project_id,),
        )
        interesting_total = int(row["n"]) if row else 0
    except Exception:
        interesting_total = 0

    for s in sessions:
        ua = s.get("updated_at")
        if ua and (last_activity_at is None or str(ua) > str(last_activity_at)):
            last_activity_at = ua

    return {
        "running": running,
        "paused": paused,
        "queued": queued,
        "interesting_total": interesting_total,
        "session_total": len(sessions),
        "last_activity_at": last_activity_at,
    }


@router.get("/generators")
def generators():
    """Known generators / strategies / processors from engine models."""
    _ensure_talos_on_path()
    from talos.intruder.models import (
        KNOWN_GENERATORS,
        KNOWN_PROCESSORS,
        KNOWN_STORAGE_MODES,
        KNOWN_STRATEGIES,
        KNOWN_TIMING_MODES,
        PHASE1_GENERATORS,
        PHASE1_STRATEGIES,
    )

    return {
        "generators": sorted(KNOWN_GENERATORS),
        "mvp_generators": sorted(PHASE1_GENERATORS),
        "strategies": sorted(KNOWN_STRATEGIES),
        "mvp_strategies": sorted(PHASE1_STRATEGIES),
        "processors": sorted(KNOWN_PROCESSORS),
        "storage_modes": sorted(KNOWN_STORAGE_MODES),
        "timing_modes": sorted(KNOWN_TIMING_MODES),
    }


@router.get("/sessions")
def list_sessions(
    project_id: str,
    status: Optional[str] = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    _ensure_talos_on_path()
    from talos.intruder import db as intruder_db

    db_path = _db_path(project_id)
    # list_sessions has limit only — fetch + slice for offset
    fetch_limit = min(limit + offset, 500)
    rows = intruder_db.list_sessions(
        db_path, project_id, status=status, limit=fetch_limit
    )
    if offset:
        rows = rows[offset : offset + limit]
    else:
        rows = rows[:limit]
    return {"sessions": [_session_summary(s) for s in rows]}


@router.get("/sessions/{session_id}")
def get_session(project_id: str, session_id: str):
    sess = _load_session(project_id, session_id)
    return _session_public(sess)


@router.get("/sessions/{session_id}/status")
def session_status(project_id: str, session_id: str):
    sess = _load_session(project_id, session_id)
    progress = sess.get("progress") or {}
    if not isinstance(progress, dict):
        progress = {}
    return {
        "id": sess["id"],
        "status": sess["status"],
        "job_id": sess.get("job_id"),
        "control_flag": sess.get("control_flag"),
        "progress": progress,
        "updated_at": sess.get("updated_at"),
        "started_at": sess.get("started_at"),
        "finished_at": sess.get("finished_at"),
        "failure_reason": sess.get("failure_reason"),
        "estimate_attempts": progress.get("estimate_total"),
    }


@router.get("/sessions/{session_id}/results")
def session_results(
    project_id: str,
    session_id: str,
    interesting: Optional[bool] = None,
    status_code: Optional[int] = None,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    _ensure_talos_on_path()
    from talos.intruder import db as intruder_db

    _load_session(project_id, session_id)  # 404 if missing
    db_path = _db_path(project_id)

    interesting_only = bool(interesting) if interesting is not None else False
    # Smart default: if client omits interesting, leave as False (UI sets smart default)

    rows = intruder_db.list_results(
        db_path,
        session_id,
        interesting_only=interesting_only,
        limit=limit,
        offset=offset,
        status_code=status_code,
    )
    # Filtered total (interesting + status_code) for correct pagination
    total = _count_results_filtered(
        db_path,
        session_id,
        interesting_only=interesting_only,
        status_code=status_code,
    )
    total_all = intruder_db.count_results(db_path, session_id, interesting_only=False)
    total_interesting = intruder_db.count_results(
        db_path, session_id, interesting_only=True
    )

    return {
        "results": rows,
        "total": total,
        "total_all": total_all,
        "total_interesting": total_interesting,
        "limit": limit,
        "offset": offset,
    }


@router.get("/sessions/{session_id}/results/summary")
def results_summary(project_id: str, session_id: str):
    """Status-code histogram for the results strip."""
    _load_session(project_id, session_id)
    db_path = _db_path(project_id)
    try:
        rows = db.query_all(
            db_path,
            """
            SELECT status_code, COUNT(*) AS n
            FROM intruder_results
            WHERE session_id = ?
            GROUP BY status_code
            ORDER BY n DESC
            """,
            (session_id,),
        )
        by_status = {
            (str(r["status_code"]) if r["status_code"] is not None else "null"): int(
                r["n"]
            )
            for r in rows
        }
    except Exception:
        by_status = {}

    _ensure_talos_on_path()
    from talos.intruder import db as intruder_db

    return {
        "by_status": by_status,
        "total": intruder_db.count_results(db_path, session_id),
        "interesting": intruder_db.count_results(
            db_path, session_id, interesting_only=True
        ),
    }


@router.get("/sessions/{session_id}/results/export")
def export_results(
    project_id: str,
    session_id: str,
    format: str = Query("jsonl", pattern="^(jsonl|csv)$"),
    interesting: Optional[bool] = None,
    limit: int = Query(100_000, ge=1, le=1_000_000),
):
    """
    Download results as JSONL or CSV (in-process; no temp project files).

    Registered before ``results/{attempt}`` so ``export`` is not parsed as an int.
    """
    import csv
    import io

    from fastapi.responses import Response

    _ensure_talos_on_path()
    from talos.intruder import db as intruder_db

    _load_session(project_id, session_id)
    db_path = _db_path(project_id)
    rows = intruder_db.list_results(
        db_path,
        session_id,
        interesting_only=bool(interesting) if interesting is not None else False,
        limit=limit,
        offset=0,
    )

    short = session_id[:8]
    if format == "csv":
        buf = io.StringIO()
        fieldnames = [
            "attempt_index",
            "status_code",
            "success",
            "failure_reason",
            "duration_ms",
            "body_length",
            "interesting",
            "match_tags",
            "grepped",
            "variables",
            "flow_id",
            "finding_id",
        ]
        writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(
                {
                    "attempt_index": row.get("attempt_index"),
                    "status_code": row.get("status_code"),
                    "success": row.get("success"),
                    "failure_reason": row.get("failure_reason"),
                    "duration_ms": row.get("duration_ms"),
                    "body_length": row.get("body_length"),
                    "interesting": row.get("interesting"),
                    "match_tags": json.dumps(row.get("match_tags") or []),
                    "grepped": json.dumps(row.get("grepped") or {}),
                    "variables": json.dumps(row.get("variables") or {}),
                    "flow_id": row.get("flow_id"),
                    "finding_id": row.get("finding_id"),
                }
            )
        body = buf.getvalue()
        return Response(
            content=body,
            media_type="text/csv; charset=utf-8",
            headers={
                "Content-Disposition": f'attachment; filename="intruder-{short}.csv"'
            },
        )

    lines = [json.dumps(r, default=str) for r in rows]
    body = "\n".join(lines) + ("\n" if lines else "")
    return Response(
        content=body,
        media_type="application/x-ndjson; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="intruder-{short}.jsonl"'
        },
    )


@router.get("/sessions/{session_id}/results/{attempt}")
def get_result(project_id: str, session_id: str, attempt: int):
    _ensure_talos_on_path()
    from talos.intruder import db as intruder_db

    _load_session(project_id, session_id)
    db_path = _db_path(project_id)
    row = intruder_db.get_result(db_path, session_id, attempt)
    if row is None:
        raise HTTPException(
            status_code=404,
            detail=f"Result attempt {attempt} not found for session '{session_id}'",
        )
    return row


# ------------------------------------------------------------------ #
# Mutations                                                            #
# ------------------------------------------------------------------ #


@router.post("/sessions")
def create_session(project_id: str, body: CreateSessionBody):
    flow_id = body.flow_id.strip()
    if not flow_id:
        raise HTTPException(status_code=400, detail="flow_id is required")
    args = [
        "intruder",
        "session",
        "create",
        "--from",
        flow_id,
        "--format",
        "json",
    ]
    if body.name and body.name.strip():
        args.extend(["--name", body.name.strip()])
    steps = cli.run_scoped(project_id, args)
    _require_ok(steps, label="intruder session create")
    payload = _last_step_payload(steps) or {}
    session_id = payload.get("session_id")
    if not session_id:
        # Fallback: newest draft for this base_flow
        _ensure_talos_on_path()
        from talos.intruder import db as intruder_db

        rows = intruder_db.list_sessions(_db_path(project_id), project_id, limit=20)
        for r in rows:
            if r.get("base_flow_id") == flow_id:
                session_id = r["id"]
                break
    if not session_id:
        raise HTTPException(
            status_code=500, detail="Create succeeded but no session_id in CLI output"
        )
    sess = _load_session(project_id, session_id)
    return {
        "session": _session_public(sess),
        "steps": _steps_dicts(steps),
    }


@router.post("/sessions/{session_id}/configure")
def configure_session(project_id: str, session_id: str, body: ConfigureBody):
    record = _project_record(project_id)
    sess = _load_session(project_id, session_id)

    expected = (body.expected_updated_at or "").strip()
    actual = str(sess.get("updated_at") or "")
    if expected != actual:
        raise HTTPException(
            status_code=409,
            detail={
                "message": "Session was modified elsewhere — reload and try again",
                "expected_updated_at": expected,
                "actual_updated_at": actual,
            },
        )

    if not isinstance(body.config, dict):
        raise HTTPException(status_code=400, detail="config must be an object")

    cfg = _apply_artifacts_to_config(
        project_id, session_id, body.config, body.artifacts, record
    )

    # Ensure session identity block present (CLI also re-stamps)
    cfg.setdefault("session", {})
    if isinstance(cfg["session"], dict):
        cfg["session"] = {
            **cfg["session"],
            "base_flow_id": sess.get("base_flow_id"),
            "endpoint_id": sess.get("endpoint_id"),
            "project_id": project_id,
        }

    content = json.dumps(cfg, indent=2, default=str)

    # Temp JSON for CLI only — durable wordlist paths stay under project data dir
    open_result = cli.run(["project", "open", project_id])
    if not open_result.ok:
        return {"steps": _steps_dicts([open_result]), "session": None}

    import tempfile

    with tempfile.NamedTemporaryFile(
        mode="w",
        suffix=".json",
        prefix="talos-cp-intruder-",
        delete=False,
        encoding="utf-8",
    ) as fh:
        fh.write(content)
        tmp_path = fh.name
    try:
        argv = [
            "intruder",
            "session",
            "configure",
            session_id,
            "--file",
            tmp_path,
            "--format",
            "json",
        ]
        if body.force:
            argv.append("--force")
        result = cli.run(argv)
    finally:
        try:
            Path(tmp_path).unlink(missing_ok=True)
        except OSError:
            pass

    steps = [open_result, result]
    _require_ok(steps, label="intruder session configure")
    payload = _last_step_payload(steps) or {}
    fresh = _load_session(project_id, session_id)
    return {
        "session": _session_public(fresh),
        "estimate_attempts": payload.get("estimate_attempts"),
        "steps": _steps_dicts(steps),
    }


@router.post("/sessions/{session_id}/validate")
def validate_session(project_id: str, session_id: str, body: ForceBody = ForceBody()):
    args = [
        "intruder",
        "session",
        "validate",
        session_id,
        "--format",
        "json",
    ]
    if body.force:
        args.append("--force")
    steps = cli.run_scoped(project_id, args)
    _require_ok(steps, label="intruder session validate")
    payload = _last_step_payload(steps) or {}
    fresh = _load_session(project_id, session_id)
    return {
        "session": _session_public(fresh),
        "valid": payload.get("valid", True),
        "estimate_attempts": payload.get("estimate_attempts"),
        "steps": _steps_dicts(steps),
    }


@router.post("/sessions/{session_id}/run")
def run_session(project_id: str, session_id: str, body: ForceBody = ForceBody()):
    """Enqueue scheduler job — never --right-now (K6)."""
    args = [
        "intruder",
        "session",
        "run",
        session_id,
        "--format",
        "json",
    ]
    if body.force:
        args.append("--force")
    steps = cli.run_scoped(project_id, args)
    _require_ok(steps, label="intruder session run")
    payload = _last_step_payload(steps) or {}
    fresh = _load_session(project_id, session_id)
    return {
        "session": _session_public(fresh),
        "job_id": payload.get("job_id") or fresh.get("job_id"),
        "estimate_attempts": payload.get("estimate_attempts"),
        "steps": _steps_dicts(steps),
    }


@router.post("/sessions/{session_id}/pause")
def pause_session(project_id: str, session_id: str):
    steps = cli.run_scoped(
        project_id,
        ["intruder", "session", "pause", session_id, "--format", "json"],
    )
    _require_ok(steps, label="intruder session pause")
    fresh = _load_session(project_id, session_id)
    return {"session": _session_public(fresh), "steps": _steps_dicts(steps)}


@router.post("/sessions/{session_id}/resume")
def resume_session(project_id: str, session_id: str):
    steps = cli.run_scoped(
        project_id,
        ["intruder", "session", "resume", session_id, "--format", "json"],
    )
    _require_ok(steps, label="intruder session resume")
    fresh = _load_session(project_id, session_id)
    return {"session": _session_public(fresh), "steps": _steps_dicts(steps)}


@router.post("/sessions/{session_id}/stop")
def stop_session(project_id: str, session_id: str):
    steps = cli.run_scoped(
        project_id,
        ["intruder", "session", "stop", session_id, "--format", "json"],
    )
    _require_ok(steps, label="intruder session stop")
    fresh = _load_session(project_id, session_id)
    return {"session": _session_public(fresh), "steps": _steps_dicts(steps)}


@router.delete("/sessions/{session_id}")
def delete_session(
    project_id: str,
    session_id: str,
    force: bool = Query(False),
):
    record = _project_record(project_id)
    # Ensure exists (friendly 404)
    _load_session(project_id, session_id)
    args = [
        "intruder",
        "session",
        "delete",
        session_id,
        "--format",
        "json",
    ]
    if force:
        args.append("--force")
    steps = cli.run_scoped(project_id, args)
    _require_ok(steps, label="intruder session delete")
    remove_artifact_dir(project_id, session_id, record)
    return {"deleted": True, "session_id": session_id, "steps": _steps_dicts(steps)}


@router.post("/sessions/{session_id}/clone")
def clone_session(project_id: str, session_id: str, body: CloneBody = CloneBody()):
    """
    CLI clone + K14 artifact copy/path rewrite + configure new session.
    """
    record = _project_record(project_id)
    src = _load_session(project_id, session_id)

    args = [
        "intruder",
        "session",
        "clone",
        session_id,
        "--format",
        "json",
    ]
    if body.name and body.name.strip():
        args.extend(["--name", body.name.strip()])
    steps = cli.run_scoped(project_id, args)
    _require_ok(steps, label="intruder session clone")
    payload = _last_step_payload(steps) or {}
    new_id = payload.get("session_id") or payload.get("id")
    if not new_id:
        # Fallback: list drafts with matching base_flow
        _ensure_talos_on_path()
        from talos.intruder import db as intruder_db

        rows = intruder_db.list_sessions(_db_path(project_id), project_id, limit=30)
        for r in rows:
            if r["id"] != session_id and r.get("base_flow_id") == src.get(
                "base_flow_id"
            ):
                if r.get("status") == "draft":
                    new_id = r["id"]
                    break
    if not new_id:
        raise HTTPException(
            status_code=500, detail="Clone succeeded but no new session_id in CLI output"
        )

    new_sess = _load_session(project_id, new_id)
    rewritten = _copy_clone_artifacts(
        project_id,
        session_id,
        new_id,
        new_sess.get("config") or {},
        record,
    )

    # Persist rewritten paths via configure (CLI)
    content = json.dumps(rewritten, indent=2, default=str)
    import tempfile

    open_result = cli.run(["project", "open", project_id])
    all_steps = list(steps)
    if open_result.ok:
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".json",
            prefix="talos-cp-intruder-clone-",
            delete=False,
            encoding="utf-8",
        ) as fh:
            fh.write(content)
            tmp_path = fh.name
        try:
            cfg_result = cli.run(
                [
                    "intruder",
                    "session",
                    "configure",
                    new_id,
                    "--file",
                    tmp_path,
                    "--format",
                    "json",
                    "--force",
                ]
            )
            all_steps.extend([open_result, cfg_result])
            if not cfg_result.ok:
                # Non-fatal if no path-backed gens; still return clone
                pass
        finally:
            try:
                Path(tmp_path).unlink(missing_ok=True)
            except OSError:
                pass

    fresh = _load_session(project_id, new_id)
    return {
        "session": _session_public(fresh),
        "source_session_id": session_id,
        "steps": _steps_dicts(all_steps),
    }


# ------------------------------------------------------------------ #
# Pools / export / from-params / suggest / findings promote          #
# ------------------------------------------------------------------ #


@router.get("/pools")
def list_pools(project_id: str):
    """Project-wide extracted value pools (in-process)."""
    _ensure_talos_on_path()
    from talos.intruder import db as intruder_db

    db_path = _db_path(project_id)
    pools = intruder_db.list_pools(db_path, project_id)
    # Compact list: omit full values for hub density
    compact = []
    for p in pools:
        compact.append(
            {
                "name": p.get("name"),
                "count": p.get("count") or len(p.get("values") or []),
                "session_id": p.get("session_id"),
                "source_rule": p.get("source_rule"),
                "updated_at": p.get("updated_at"),
                "created_at": p.get("created_at"),
            }
        )
    return {"pools": compact}


@router.get("/pools/{name}")
def get_pool(
    project_id: str,
    name: str,
    limit: int = Query(200, ge=1, le=5000),
):
    _ensure_talos_on_path()
    from talos.intruder import db as intruder_db

    db_path = _db_path(project_id)
    pool = intruder_db.get_pool(db_path, project_id, name)
    if pool is None:
        raise HTTPException(status_code=404, detail=f"Pool '{name}' not found")
    values = list(pool.get("values") or [])
    return {
        "name": pool.get("name"),
        "count": pool.get("count") or len(values),
        "session_id": pool.get("session_id"),
        "source_rule": pool.get("source_rule"),
        "updated_at": pool.get("updated_at"),
        "created_at": pool.get("created_at"),
        "values": values[:limit],
        "truncated": len(values) > limit,
    }


@router.post("/pools/{name}/clear")
def clear_pool(project_id: str, name: str):
    """Empty pool values (keep row) via CLI."""
    steps = cli.run_scoped(
        project_id,
        ["intruder", "pool", "clear", name, "--format", "json"],
    )
    _require_ok(steps, label="intruder pool clear")
    return {"cleared": True, "name": name, "steps": _steps_dicts(steps)}


@router.delete("/pools/{name}")
def delete_pool(project_id: str, name: str):
    steps = cli.run_scoped(
        project_id,
        ["intruder", "pool", "delete", name, "--format", "json"],
    )
    _require_ok(steps, label="intruder pool delete")
    return {"deleted": True, "name": name, "steps": _steps_dicts(steps)}


class FromParamsBody(BaseModel):
    set_payloads: bool = False
    replace: bool = False
    locations: str = ""


@router.post("/sessions/{session_id}/from-params")
def from_params(project_id: str, session_id: str, body: FromParamsBody = FromParamsBody()):
    """CLI: template from-params — rewrites session variables (not draft-local)."""
    _load_session(project_id, session_id)
    args = [
        "intruder",
        "template",
        "from-params",
        session_id,
        "--format",
        "json",
    ]
    if body.set_payloads:
        args.append("--set-payloads")
    if body.replace:
        args.append("--replace")
    if body.locations and body.locations.strip():
        args.extend(["--locations", body.locations.strip()])
    steps = cli.run_scoped(project_id, args)
    _require_ok(steps, label="intruder template from-params")
    payload = _last_step_payload(steps) or {}
    fresh = _load_session(project_id, session_id)
    return {
        "session": _session_public(fresh),
        "added": payload.get("added"),
        "payloads_set": payload.get("payloads_set"),
        "steps": _steps_dicts(steps),
    }


class SuggestBody(BaseModel):
    apply: bool = False
    replace_payloads: bool = False
    no_match: bool = False
    no_grep: bool = False


@router.post("/sessions/{session_id}/suggest")
def suggest_session(
    project_id: str,
    session_id: str,
    body: SuggestBody = SuggestBody(),
):
    """CLI: intruder suggest [--apply]."""
    _load_session(project_id, session_id)
    args = ["intruder", "suggest", session_id, "--format", "json"]
    if body.apply:
        args.append("--apply")
    if body.replace_payloads:
        args.append("--replace-payloads")
    if body.no_match:
        args.append("--no-match")
    if body.no_grep:
        args.append("--no-grep")
    steps = cli.run_scoped(project_id, args)
    _require_ok(steps, label="intruder suggest")
    payload = _last_step_payload(steps) or {}
    fresh = _load_session(project_id, session_id)
    return {
        "session": _session_public(fresh),
        "suggestions": payload,
        "steps": _steps_dicts(steps),
    }


class FindingsPromoteBody(BaseModel):
    enable: bool = False
    force: bool = False


@router.post("/sessions/{session_id}/findings/promote")
def findings_promote(
    project_id: str,
    session_id: str,
    body: FindingsPromoteBody = FindingsPromoteBody(),
):
    """CLI: findings promote (offline)."""
    _load_session(project_id, session_id)
    args = [
        "intruder",
        "findings",
        "promote",
        session_id,
        "--format",
        "json",
    ]
    if body.enable:
        args.append("--enable")
    if body.force:
        args.append("--force")
    steps = cli.run_scoped(project_id, args)
    _require_ok(steps, label="intruder findings promote")
    payload = _last_step_payload(steps) or {}
    fresh = _load_session(project_id, session_id)
    return {
        "session": _session_public(fresh),
        "result": payload,
        "steps": _steps_dicts(steps),
    }
