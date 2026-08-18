"""
Scheduler control and observability API.

Ownership boundary:
    Talos core owns the daemon lifecycle (SchedulerRuntimeManager), queue
    execution state (scheduler_state), and job mutations (CLI). This router
    reads process status + SQLite inventory and shells mutations through
    `talos scheduler …`.
"""

from __future__ import annotations

import sys
from typing import Any, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from .. import cli, config, db

router = APIRouter(prefix="/api/scheduler", tags=["scheduler"])


def _ensure_talos_on_path() -> None:
    """
    Control panel backend runs in its own venv; Talos package lives at
    TALOS_ROOT. Same pattern as endpoint_reads / input_validation routers.
    """
    root = str(config.TALOS_ROOT)
    if root not in sys.path:
        sys.path.insert(0, root)

# Process start/stop may settle for several seconds.
_SCHEDULER_LIFECYCLE_TIMEOUT_S = 60

# Mirror core list_jobs caps (talos.scheduler.cli).
_DEFAULT_JOBS_LIMIT = 200
_MAX_JOBS_LIMIT = 1000

_ALL_JOB_STATUSES = (
    "pending",
    "running",
    "paused",
    "done",
    "failed",
    "skipped",
    "cancelled",
)

_ACTIVE_STATUSES = ("pending", "running", "paused")

_PRUNEABLE_STATUSES = frozenset({"done", "failed", "skipped", "cancelled"})

# Known families for empty-queue filters (CLI list_jobs family semantics).
_KNOWN_FAMILIES = (
    "replay",
    "bac",
    "iv",
    "unauth",
    "cors",
    "sqli",
    "smuggle",
    "auth_session",
    "auth_test",
    "intruder",
)


def _job_family(job_type: str | None) -> str:
    """Roll exact job_type up to the operator family (iv, cors, bac, …)."""
    raw = (job_type or "").strip().lower()
    if not raw:
        return "other"
    if raw == "auth_test":
        return "auth_test"
    if raw.startswith("replay"):
        return "replay"
    if raw.startswith("bac"):
        return "bac"
    if raw.startswith("iv"):
        return "iv"
    if raw.startswith("unauth"):
        return "unauth"
    if raw.startswith("cors"):
        return "cors"
    if raw.startswith("sqli"):
        return "sqli"
    if raw.startswith("smuggle"):
        return "smuggle"
    if raw.startswith("auth_session"):
        return "auth_session"
    if raw.startswith("intruder"):
        return "intruder"
    if "_" not in raw:
        return raw
    return raw.split("_", 1)[0] or "other"

_JOB_SELECT = """
    SELECT sj.*,
        COALESCE(sj.endpoint_id, f.endpoint_id) AS resolved_endpoint_id,
        COALESCE(r.name, rf.name) AS role_name,
        COALESCE(m.name, mf.name) AS module_name
    FROM scheduler_jobs sj
    LEFT JOIN flows f ON f.id = sj.flow_id
    LEFT JOIN roles r ON r.id = json_extract(sj.meta, '$.attacker_role_id')
    LEFT JOIN roles rf ON rf.id = f.role_id
    LEFT JOIN modules m ON m.id = json_extract(sj.meta, '$.module_id')
    LEFT JOIN modules mf ON mf.id = f.module_id
"""


def _process_status() -> dict[str, Any]:
    """
    Observational snapshot from SchedulerRuntimeManager (no CLI scrape).
    """
    try:
        _ensure_talos_on_path()
        from talos.scheduler.runtime import SchedulerRuntimeManager

        info = SchedulerRuntimeManager(data_dir=config.TALOS_HOME).status()
        return info.to_dict()
    except Exception as exc:  # pragma: no cover — defensive for missing runtime
        return {
            "state": "stopped",
            "pid": None,
            "create_time": None,
            "project_id": None,
            "startup_time": None,
            "runtime_version": 1,
            "last_error": str(exc),
            "validation_deferred": False,
            "transitional": False,
            "log_path": str(config.TALOS_HOME / "runtime" / "scheduler.log"),
        }


def _full_counts(raw: dict[str, int]) -> dict[str, int]:
    return {s: int(raw.get(s) or 0) for s in _ALL_JOB_STATUSES}


def _queue_metrics(db_path) -> dict[str, Any]:
    """Read-only metrics matching core get_queue_metrics (no migrate writes)."""
    if not db.db_exists(db_path):
        return {
            "total_jobs": 0,
            "avg_execution_delay_s": None,
            "last_executed_at": None,
        }
    try:
        row = db.query_one(
            db_path,
            """
            SELECT
                COUNT(*) AS total_jobs,
                AVG(
                    (julianday(finished_at) - julianday(scheduled_at)) * 86400.0
                ) AS avg_delay,
                MAX(finished_at) AS last_executed_at
            FROM scheduler_jobs
            WHERE status = 'done'
              AND scheduled_at IS NOT NULL
              AND finished_at  IS NOT NULL
            """,
        )
    except Exception:
        return {
            "total_jobs": 0,
            "avg_execution_delay_s": None,
            "last_executed_at": None,
        }
    if not row:
        return {
            "total_jobs": 0,
            "avg_execution_delay_s": None,
            "last_executed_at": None,
        }
    return {
        "total_jobs": int(row.get("total_jobs") or 0),
        "avg_execution_delay_s": row.get("avg_delay"),
        "last_executed_at": row.get("last_executed_at"),
    }


def _enrich_job(row: dict[str, Any]) -> dict[str, Any]:
    row["meta"] = db.safe_json(row.get("meta"), {})
    return row


def _job_type_clause(job_type: str) -> tuple[str, list[Any]]:
    """
    Family filter aligned with talos.scheduler.db.list_jobs:
    no underscore → exact OR type_% ; otherwise exact match.
    """
    if "_" not in job_type:
        return "(sj.job_type = ? OR sj.job_type LIKE ?)", [job_type, f"{job_type}_%"]
    return "sj.job_type = ?", [job_type]


def _status_clause(status: str | None) -> tuple[Optional[str], list[Any]]:
    """
    Exact status, or synthetic 'active' → pending|running|paused.
    """
    if not status:
        return None, []
    if status == "active":
        placeholders = ", ".join("?" for _ in _ACTIVE_STATUSES)
        return f"sj.status IN ({placeholders})", list(_ACTIVE_STATUSES)
    return "sj.status = ?", [status]


@router.get("/status")
def status(project_id: str):
    """
    Process runtime + DB queue state + counts + metrics + config.
    Keeps legacy keys (counts, config, state) for Header/StatusContext.
    """
    record = db.get_project_record(project_id)
    db_path = config.project_db_path(project_id, record)

    counts_rows = db.query_all(
        db_path, "SELECT status, COUNT(*) AS n FROM scheduler_jobs GROUP BY status"
    )
    raw_counts = {row["status"]: int(row["n"] or 0) for row in counts_rows}
    counts = _full_counts(raw_counts)

    type_rows = db.query_all(
        db_path,
        "SELECT job_type, COUNT(*) AS n FROM scheduler_jobs GROUP BY job_type",
    )
    by_job_type: list[dict[str, Any]] = []
    family_totals: dict[str, int] = {}
    for row in type_rows:
        job_type = row.get("job_type") or "unknown"
        n = int(row.get("n") or 0)
        family = _job_family(job_type)
        by_job_type.append({"job_type": job_type, "family": family, "n": n})
        family_totals[family] = family_totals.get(family, 0) + n
    by_job_type.sort(key=lambda r: (-int(r["n"]), str(r["job_type"])))
    by_family = [
        {"family": fam, "n": n}
        for fam, n in sorted(family_totals.items(), key=lambda kv: (-kv[1], kv[0]))
    ]

    cfg = db.query_one(db_path, "SELECT * FROM scheduler_config")
    state = db.query_one(db_path, "SELECT * FROM scheduler_state")

    layered: dict = {}
    tw_state: dict | None = None
    try:
        _ensure_talos_on_path()
        from talos.scheduler.db import get_scheduler_config
        from talos.scheduler.testing_windows import evaluate

        layered = get_scheduler_config(db_path)
        tw_state = evaluate(
            bool(layered.get("testing_windows_enabled", False)),
            layered.get("testing_windows") or [],
        ).to_dict()
    except Exception:  # noqa: BLE001
        layered = {}
        tw_state = None

    min_delay = layered.get("min_delay", (cfg or {}).get("min_delay", 2))
    max_delay = layered.get("max_delay", (cfg or {}).get("max_delay", 6))
    max_queue_size = layered.get(
        "max_queue_size", (cfg or {}).get("max_queue_size", 200)
    )
    try:
        max_q = int(max_queue_size) if max_queue_size is not None else 200
    except (TypeError, ValueError):
        max_q = 200
    if max_q <= 0:
        max_q = 200

    active_queue = (
        counts["pending"] + counts["running"] + counts["paused"]
    )
    fill = int(round(100 * active_queue / max_q)) if max_q > 0 else 0
    fill = min(max(fill, 0), 100)

    process = _process_status()
    metrics = _queue_metrics(db_path)

    return {
        # Legacy keys (compat)
        "counts": counts,
        "config": {
            "min_delay": min_delay if (cfg or layered) else 2,
            "max_delay": max_delay if (cfg or layered) else 6,
            "max_queue_size": max_q,
            "testing_windows_enabled": bool(
                layered.get("testing_windows_enabled", False)
            ),
            "testing_windows": list(layered.get("testing_windows") or []),
        },
        "testing_windows": tw_state,
        "state": state,
        # Enriched
        "process": process,
        "metrics": metrics,
        "active_queue": active_queue,
        "queue_fill_pct": fill,
        "by_job_type": by_job_type,
        "by_family": by_family,
    }


@router.get("/filters")
def job_filters(project_id: str):
    """
    Distinct filter values. Always includes known statuses and families so
    controls remain usable on an empty queue.
    """
    record = db.get_project_record(project_id)
    db_path = config.project_db_path(project_id, record)

    discovered_types: list[str] = []
    roles: list[str] = []
    modules: list[str] = []
    if db.db_exists(db_path):
        discovered_types = [
            r["job_type"]
            for r in db.query_all(
                db_path,
                "SELECT DISTINCT job_type FROM scheduler_jobs ORDER BY job_type",
            )
            if r.get("job_type")
        ]
        roles = [
            r["name"]
            for r in db.query_all(db_path, "SELECT name FROM roles ORDER BY name")
            if r.get("name")
        ]
        modules = [
            r["name"]
            for r in db.query_all(db_path, "SELECT name FROM modules ORDER BY name")
            if r.get("name")
        ]

    # Families first, then discovered exact types not covered by family labels.
    families = list(_KNOWN_FAMILIES)
    exact_extra = [t for t in discovered_types if t not in families]
    job_types = families + exact_extra

    return {
        "job_types": job_types,
        "statuses": list(_ALL_JOB_STATUSES),
        "families": list(_KNOWN_FAMILIES),
        "roles": roles,
        "modules": modules,
        "pruneable_statuses": sorted(_PRUNEABLE_STATUSES),
    }


@router.get("/jobs")
def list_jobs(
    project_id: str,
    status: str | None = None,
    job_type: str | None = None,
    role: str | None = None,
    module: str | None = None,
    limit: int = _DEFAULT_JOBS_LIMIT,
    offset: int = 0,
):
    """
    Filtered job inventory with family type filter, total count, and paging.
    """
    record = db.get_project_record(project_id)
    db_path = config.project_db_path(project_id, record)

    limit = max(1, min(int(limit), _MAX_JOBS_LIMIT))
    offset = max(0, int(offset))

    conditions: list[str] = []
    params: list[Any] = []

    status_sql, status_params = _status_clause(status)
    if status_sql:
        conditions.append(status_sql)
        params.extend(status_params)

    if job_type:
        type_sql, type_params = _job_type_clause(job_type)
        conditions.append(type_sql)
        params.extend(type_params)

    if role:
        conditions.append("COALESCE(r.name, rf.name) = ?")
        params.append(role)
    if module:
        conditions.append("COALESCE(m.name, mf.name) = ?")
        params.append(module)

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""

    # Total matching rows (honest paging).
    total = 0
    if db.db_exists(db_path):
        try:
            total_row = db.query_one(
                db_path,
                f"""
                SELECT COUNT(*) AS n
                FROM scheduler_jobs sj
                LEFT JOIN flows f ON f.id = sj.flow_id
                LEFT JOIN roles r ON r.id = json_extract(sj.meta, '$.attacker_role_id')
                LEFT JOIN roles rf ON rf.id = f.role_id
                LEFT JOIN modules m ON m.id = json_extract(sj.meta, '$.module_id')
                LEFT JOIN modules mf ON mf.id = f.module_id
                {where}
                """,
                tuple(params),
            )
            total = int((total_row or {}).get("n") or 0)
        except Exception:
            total = 0

    # Order: active-first when browsing mixed; finished_at for terminal filter.
    if status in _PRUNEABLE_STATUSES:
        order = "COALESCE(sj.finished_at, sj.created_at) DESC"
    else:
        order = (
            "CASE sj.status WHEN 'running' THEN 0 WHEN 'pending' THEN 1 "
            "WHEN 'paused' THEN 2 ELSE 3 END, "
            "sj.priority DESC, sj.created_at DESC"
        )

    rows = db.query_all(
        db_path,
        f"{_JOB_SELECT} {where} ORDER BY {order} LIMIT ? OFFSET ?",
        (*params, limit, offset),
    )
    for r in rows:
        _enrich_job(r)

    return {
        "jobs": rows,
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/jobs/{job_id}")
def get_job(job_id: str, project_id: str):
    """
    Job detail by full UUID or unique prefix (mirror sched_db.get_job).
    """
    record = db.get_project_record(project_id)
    db_path = config.project_db_path(project_id, record)
    needle = (job_id or "").strip()
    if not needle:
        raise HTTPException(status_code=400, detail="job_id is required")

    if not db.db_exists(db_path):
        raise HTTPException(status_code=404, detail=f"Job '{needle}' not found")

    # Exact match first.
    rows = db.query_all(
        db_path,
        f"{_JOB_SELECT} WHERE sj.job_id = ?",
        (needle,),
    )
    if not rows:
        # Unique prefix (case-insensitive), same as core get_job.
        rows = db.query_all(
            db_path,
            f"{_JOB_SELECT} WHERE lower(sj.job_id) LIKE lower(?) || '%'",
            (needle,),
        )
        if len(rows) > 1:
            raise HTTPException(
                status_code=400,
                detail=f"Ambiguous job prefix '{needle}' matches {len(rows)} jobs",
            )
        if not rows:
            raise HTTPException(status_code=404, detail=f"Job '{needle}' not found")

    return {"job": _enrich_job(rows[0])}


@router.post("/start")
def process_start(project_id: str):
    """Start the managed scheduler daemon for the project."""
    results = cli.run_scoped(
        project_id, ["scheduler", "start"], timeout=_SCHEDULER_LIFECYCLE_TIMEOUT_S
    )
    return {"steps": [r.to_dict() for r in results]}


@router.post("/stop")
def process_stop(project_id: str | None = None):
    """
    Stop the managed scheduler daemon.
    CLI stop does not require a project; project_id is optional for audit/
    open consistency when the UI has a selection.
    """
    if project_id:
        results = cli.run_scoped(
            project_id,
            ["scheduler", "stop"],
            timeout=_SCHEDULER_LIFECYCLE_TIMEOUT_S,
        )
        return {"steps": [r.to_dict() for r in results]}
    result = cli.run(["scheduler", "stop"], timeout=_SCHEDULER_LIFECYCLE_TIMEOUT_S)
    return {"steps": [result.to_dict()]}


class CancelBody(BaseModel):
    job_id: str


@router.post("/cancel")
def cancel_job(project_id: str, body: CancelBody):
    """Cancel one pending/paused job (CLI has no multi-id)."""
    results = cli.run_scoped(
        project_id, ["scheduler", "cancel", body.job_id.strip()]
    )
    return {"steps": [r.to_dict() for r in results]}


class PruneBody(BaseModel):
    status: str
    force: bool = True


@router.post("/prune")
def prune_jobs(project_id: str, body: PruneBody):
    """Delete terminal job history for one status."""
    status = (body.status or "").strip().lower()
    if status not in _PRUNEABLE_STATUSES:
        allowed = ", ".join(sorted(_PRUNEABLE_STATUSES))
        raise HTTPException(
            status_code=400,
            detail=f"status must be one of: {allowed}",
        )
    args = ["scheduler", "prune", "--status", status]
    if body.force:
        args.append("--force")
    results = cli.run_scoped(project_id, args)
    return {"steps": [r.to_dict() for r in results]}


class ConfigBody(BaseModel):
    min_delay: float | None = None
    max_delay: float | None = None
    max_queue_size: int | None = None
    testing_windows: str | None = None
    windows: list[str] | None = None
    clear_windows: bool = False


@router.post("/config")
def set_config(project_id: str, body: ConfigBody):
    args = ["scheduler", "config"]
    if body.min_delay is not None:
        args += ["--min-delay", str(body.min_delay)]
    if body.max_delay is not None:
        args += ["--max-delay", str(body.max_delay)]
    if body.max_queue_size is not None:
        args += ["--max-queue-size", str(body.max_queue_size)]
    if body.testing_windows is not None:
        switch = str(body.testing_windows).strip().lower()
        if switch not in ("on", "off"):
            raise HTTPException(
                status_code=400,
                detail="testing_windows must be 'on' or 'off'",
            )
        args += ["--testing-windows", switch]
    if body.clear_windows:
        args.append("--clear-windows")
    for window in body.windows or []:
        args += ["--window", str(window)]
    results = cli.run_scoped(project_id, args)
    return {"steps": [r.to_dict() for r in results]}


class EnqueueFlowBody(BaseModel):
    flow_id: str
    priority: int | None = None
    force: bool = False


@router.post("/enqueue/flow")
def enqueue_flow(project_id: str, body: EnqueueFlowBody):
    args = ["scheduler", "enqueue", "flow", body.flow_id]
    if body.priority is not None:
        args += ["--priority", str(body.priority)]
    if body.force:
        args.append("--force")
    results = cli.run_scoped(project_id, args)
    return {"steps": [r.to_dict() for r in results]}


class EnqueueEndpointBody(BaseModel):
    endpoint_id: str
    type: str | None = None  # replay | auth-test
    priority: int | None = None
    force: bool = False


@router.post("/enqueue/endpoint")
def enqueue_endpoint(project_id: str, body: EnqueueEndpointBody):
    args = ["scheduler", "enqueue", "endpoint", body.endpoint_id]
    if body.type:
        args += ["--type", body.type]
    if body.priority is not None:
        args += ["--priority", str(body.priority)]
    if body.force:
        args.append("--force")
    results = cli.run_scoped(project_id, args)
    return {"steps": [r.to_dict() for r in results]}


@router.post("/clear")
def clear(project_id: str, force: bool = False):
    args = ["scheduler", "clear"]
    if force:
        args.append("--force")
    results = cli.run_scoped(project_id, args)
    return {"steps": [r.to_dict() for r in results]}


@router.post("/pause")
def pause(project_id: str):
    results = cli.run_scoped(project_id, ["scheduler", "pause"])
    return {"steps": [r.to_dict() for r in results]}


@router.post("/resume")
def resume(project_id: str):
    results = cli.run_scoped(project_id, ["scheduler", "resume"])
    return {"steps": [r.to_dict() for r in results]}
