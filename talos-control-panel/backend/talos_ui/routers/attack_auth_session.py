"""
Auth-Session Testing Control Panel routes under ``/api/attack/auth-session/*``.

Phase 1: summary / overview / bindings (read-only SQL).
Phase 2: bind / unbind / generate mutations (CLI argv) + candidates list/detail.

Mutations always go through ``cli.run_scoped``; reads prefer read-only SQLite.
Included from ``attack.py`` so the public URL prefix stays ``/api/attack``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from .. import cli, config, db

router = APIRouter(tags=["attack-auth-session"])

DISCLAIMER = (
    "Active attack · medium risk. "
    "Auth-Session Testing mutates a presented credential (JWT structure, "
    "algorithm, signature, claims, kid) and replays one HTTP request per "
    "approved testcase against the live target. Use only on authorized "
    "bug bounty / client-approved scope. "
    "Distinct from Unauth (auth removed), BAC (other-role session), and "
    "classic Authentication Bypass (auth test / BYPASS). "
    "Operator must approve candidates before run — pending tests never auto-fire. "
    "WEAK_VALIDATION is evidence of weak token validation, not a freeform exploit."
)

FILTER_FILENAME = "auth-session-decision-filter.yaml"
JOB_TYPE = "auth_session_attack"

KNOWN_FAMILIES = frozenset({
    "signature",
    "algorithm",
    "algorithm_degrade",
    "structure",
    "claims",
    "kid",
})


# ------------------------------------------------------------------ #
# Helpers                                                              #
# ------------------------------------------------------------------ #


def _db_path(project_id: str) -> Path:
    record = db.get_project_record(project_id)
    return config.project_db_path(project_id, record)


def _data_dir(project_id: str) -> Path:
    record = db.get_project_record(project_id)
    return config.project_data_dir(project_id, record)


def _filter_meta(project_id: str) -> dict[str, Any]:
    data_dir = _data_dir(project_id)
    path = data_dir / FILTER_FILENAME
    return {
        "filter_filename": FILTER_FILENAME,
        "filter_path": str(path),
        "filter_exists": path.is_file(),
    }


def _safe_group_count(db_path: Path, sql: str, params: tuple = ()) -> dict[str, int]:
    try:
        rows = db.query_all(db_path, sql, params)
        return {str(r.get("k") or r.get("verdict") or r.get("status") or ""): int(r["n"]) for r in rows}
    except Exception:
        return {}


def _auth_config_artifacts(db_path: Path) -> list[dict]:
    try:
        return db.query_all(
            db_path,
            "SELECT type, name FROM auth_config ORDER BY type, name",
        )
    except Exception:
        return []


def _auth_config_ready(artifacts: list[dict]) -> bool:
    return len(artifacts) > 0


def _field_in_auth_config(artifacts: list[dict], location: str, name: str) -> bool:
    loc = (location or "").strip().lower()
    field = (name or "").strip()
    if not field:
        return False
    for a in artifacts:
        a_type = str(a.get("type") or "").strip().lower()
        a_name = str(a.get("name") or "").strip()
        if a_type != loc:
            continue
        if loc == "header" and a_name.lower() == field.lower():
            return True
        if loc == "cookie" and a_name == field:
            return True
    return False


def _job_counts(db_path: Path) -> dict[str, int]:
    try:
        rows = db.query_all(
            db_path,
            """
            SELECT status, COUNT(*) AS n
            FROM scheduler_jobs
            WHERE job_type = ?
            GROUP BY status
            """,
            (JOB_TYPE,),
        )
        return {str(r["status"]): int(r["n"]) for r in rows}
    except Exception:
        return {}


def _binding_rows(db_path: Path) -> list[dict]:
    try:
        return db.query_all(
            db_path,
            """
            SELECT id, location, name, auth_type, role_id, config_json,
                   created_at, updated_at
            FROM auth_session_bindings
            ORDER BY location, name
            """,
        )
    except Exception:
        return []


def _candidate_counts_for_binding(db_path: Path, binding_id: str) -> dict[str, int]:
    try:
        rows = db.query_all(
            db_path,
            """
            SELECT status, COUNT(*) AS n
            FROM auth_session_candidates
            WHERE binding_id = ?
            GROUP BY status
            """,
            (binding_id,),
        )
        out = {str(r["status"]): int(r["n"]) for r in rows}
        out["total"] = sum(out.values())
        return out
    except Exception:
        return {"total": 0}


def _candidate_status_counts(db_path: Path) -> dict[str, int]:
    try:
        rows = db.query_all(
            db_path,
            """
            SELECT status, COUNT(*) AS n
            FROM auth_session_candidates
            GROUP BY status
            """,
        )
        return {str(r["status"]): int(r["n"]) for r in rows}
    except Exception:
        return {}


def _result_verdict_counts(db_path: Path) -> dict[str, int]:
    try:
        rows = db.query_all(
            db_path,
            """
            SELECT verdict, COUNT(*) AS n
            FROM auth_session_results
            GROUP BY verdict
            """,
        )
        return {str(r["verdict"]): int(r["n"]) for r in rows}
    except Exception:
        return {}


def _recent_weak(db_path: Path, top_n: int) -> list[dict]:
    try:
        return db.query_all(
            db_path,
            """
            SELECT r.replay_flow_id, r.original_flow_id, r.candidate_id,
                   r.binding_id, r.auth_type, r.test_id, r.verdict,
                   r.endpoint_id, r.test_family, r.mutation_summary,
                   r.original_status, r.replay_status, r.failure_reason,
                   r.created_at,
                   f.method, f.path, f.host, f.status_code, f.captured_at
            FROM auth_session_results r
            LEFT JOIN flows f ON f.id = r.replay_flow_id
            WHERE r.verdict = 'WEAK_VALIDATION'
            ORDER BY r.created_at DESC
            LIMIT ?
            """,
            (top_n,),
        )
    except Exception:
        return []


def _approved_count(
    db_path: Path,
    *,
    endpoint_id: Optional[str] = None,
) -> int:
    try:
        if endpoint_id:
            row = db.query_one(
                db_path,
                """
                SELECT COUNT(*) AS n FROM auth_session_candidates
                WHERE status = 'approved' AND endpoint_id = ?
                """,
                (endpoint_id,),
            )
        else:
            row = db.query_one(
                db_path,
                """
                SELECT COUNT(*) AS n FROM auth_session_candidates
                WHERE status = 'approved'
                """,
            )
        return int(row["n"]) if row else 0
    except Exception:
        return 0


def _parse_csv_or_list(value: Optional[list[str] | str]) -> list[str]:
    """Accept repeated query params or a single comma-separated string."""
    if value is None:
        return []
    if isinstance(value, str):
        parts = [p.strip() for p in value.split(",") if p.strip()]
        return parts
    out: list[str] = []
    for item in value:
        if not item:
            continue
        if "," in item:
            out.extend(p.strip() for p in item.split(",") if p.strip())
        else:
            out.append(item.strip())
    return out


def _validate_families(families: list[str] | None) -> None:
    if not families:
        return
    unknown = sorted({f for f in families if f not in KNOWN_FAMILIES})
    if unknown:
        raise HTTPException(
            400,
            f"unknown family {unknown}; known: {sorted(KNOWN_FAMILIES)}",
        )


# ------------------------------------------------------------------ #
# Read: summary / overview / bindings                                  #
# ------------------------------------------------------------------ #


@router.get("/auth-session/summary")
def auth_session_summary(project_id: str):
    """Lightweight hub KPI payload (K7 chips)."""
    db_path = _db_path(project_id)
    counts = _result_verdict_counts(db_path)
    by_status = _candidate_status_counts(db_path)
    bindings = _binding_rows(db_path)
    return {
        "counts": counts,
        "candidates_by_status": by_status,
        "bindings": len(bindings),
    }


@router.get("/auth-session/overview")
def auth_session_overview(
    project_id: str,
    endpoint_id: Optional[str] = None,
    top_n: int = 8,
):
    """
    Aggregate for Overview tab: readiness, KPIs, recent WEAK_VALIDATION,
    job pressure, filter path meta.
    """
    db_path = _db_path(project_id)
    top_n = min(max(int(top_n or 8), 1), 50)

    artifacts = _auth_config_artifacts(db_path)
    auth_ready = _auth_config_ready(artifacts)
    bindings_raw = _binding_rows(db_path)
    binding_details = []
    bindings_valid = True
    for b in bindings_raw:
        in_cfg = _field_in_auth_config(
            artifacts, str(b.get("location") or ""), str(b.get("name") or "")
        )
        if not in_cfg:
            bindings_valid = False
        binding_details.append(
            {
                "id": b.get("id"),
                "location": b.get("location"),
                "name": b.get("name"),
                "auth_type": b.get("auth_type"),
                "role_id": b.get("role_id"),
                "in_auth_config": in_cfg,
            }
        )
    if not bindings_raw:
        bindings_valid = True

    by_status = _candidate_status_counts(db_path)
    candidates_total = sum(by_status.values())
    by_verdict = _result_verdict_counts(db_path)
    results_total = sum(by_verdict.values())
    jobs = _job_counts(db_path)
    pending = int(jobs.get("pending") or 0)
    running = int(jobs.get("running") or 0)
    estimated = _approved_count(db_path, endpoint_id=endpoint_id)
    recent = _recent_weak(db_path, top_n)
    fmeta = _filter_meta(project_id)

    empty_state = {
        "no_bindings": len(bindings_raw) == 0,
        "no_candidates": candidates_total == 0,
        "no_results": results_total == 0,
        "jobs_in_flight": (pending + running) > 0,
        "no_auth_config": not auth_ready,
    }

    return {
        "bindings": len(bindings_raw),
        "binding_details": binding_details,
        "candidates_total": candidates_total,
        "candidates_by_status": by_status,
        "results_total": results_total,
        "results_by_verdict": by_verdict,
        # Alias used by FE hub-style chips / Unauth parity
        "counts": by_verdict,
        "jobs": jobs,
        "jobs_pending": pending,
        "jobs_running": running,
        "estimated_jobs_approved": estimated,
        "auth_config_ready": auth_ready,
        "bindings_valid": bindings_valid,
        "filter_filename": fmeta["filter_filename"],
        "filter_path": fmeta["filter_path"],
        "filter_exists": fmeta["filter_exists"],
        "recent_weak": recent,
        "empty_state": empty_state,
        "disclaimer": DISCLAIMER,
        "endpoint_id": endpoint_id,
    }


@router.get("/auth-session/bindings")
def auth_session_bindings(project_id: str):
    """List bindings + per-status candidate counts + in_auth_config flag."""
    db_path = _db_path(project_id)
    artifacts = _auth_config_artifacts(db_path)
    rows = _binding_rows(db_path)
    items = []
    for b in rows:
        bid = str(b.get("id") or "")
        loc = str(b.get("location") or "")
        name = str(b.get("name") or "")
        items.append(
            {
                **dict(b),
                "in_auth_config": _field_in_auth_config(artifacts, loc, name),
                "candidate_counts": _candidate_counts_for_binding(db_path, bid),
            }
        )
    return {
        "items": items,
        "count": len(items),
        "auth_config_ready": _auth_config_ready(artifacts),
        "auth_artifacts": artifacts,
    }


# ------------------------------------------------------------------ #
# Read: candidates                                                     #
# ------------------------------------------------------------------ #


@router.get("/auth-session/candidates")
def auth_session_candidates(
    project_id: str,
    status: Optional[str] = None,
    endpoint_id: Optional[str] = None,
    binding_id: Optional[str] = None,
    test_id: Optional[list[str]] = Query(default=None),
    family: Optional[list[str]] = Query(default=None),
    limit: int = 200,
):
    """
    List candidates with CLI-aligned filters. No offset (K21).
    Default limit 200, max 1000.
    """
    db_path = _db_path(project_id)
    limit = min(max(int(limit or 200), 1), 1000)
    test_ids = _parse_csv_or_list(test_id)
    families = _parse_csv_or_list(family)
    _validate_families(families)

    clauses: list[str] = []
    params: list[Any] = []
    if status:
        clauses.append("c.status = ?")
        params.append(status.strip())
    if endpoint_id:
        clauses.append("c.endpoint_id = ?")
        params.append(endpoint_id.strip())
    if binding_id:
        clauses.append("c.binding_id = ?")
        params.append(binding_id.strip())
    if test_ids:
        placeholders = ",".join("?" for _ in test_ids)
        clauses.append(f"c.test_id IN ({placeholders})")
        params.extend(test_ids)
    if families:
        placeholders = ",".join("?" for _ in families)
        clauses.append(f"c.test_family IN ({placeholders})")
        params.extend(families)

    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    sql = f"""
        SELECT c.id, c.binding_id, c.baseline_flow_id, c.auth_type, c.test_id,
               c.test_family, c.title, c.mutation_summary, c.status,
               c.endpoint_id, c.token_fingerprint, c.risk_hint,
               c.reject_reason, c.skip_reason, c.meta_json,
               c.created_at, c.updated_at,
               e.method AS endpoint_method, e.path AS endpoint_path
        FROM auth_session_candidates c
        LEFT JOIN endpoints e ON e.id = c.endpoint_id
        {where}
        ORDER BY c.created_at ASC, c.test_id ASC
        LIMIT ?
    """
    params.append(limit)
    try:
        items = db.query_all(db_path, sql, tuple(params))
    except Exception:
        items = []

    return {
        "items": items,
        "count": len(items),
        "filters_applied": {
            "status": status,
            "endpoint_id": endpoint_id,
            "binding_id": binding_id,
            "test_ids": test_ids or None,
            "families": families or None,
            "limit": limit,
        },
    }


@router.get("/auth-session/candidates/{candidate_id}")
def auth_session_candidate_detail(project_id: str, candidate_id: str):
    """Single candidate for detail drawer."""
    db_path = _db_path(project_id)
    try:
        row = db.query_one(
            db_path,
            """
            SELECT c.*, e.method AS endpoint_method, e.path AS endpoint_path
            FROM auth_session_candidates c
            LEFT JOIN endpoints e ON e.id = c.endpoint_id
            WHERE c.id = ?
            """,
            (candidate_id,),
        )
    except Exception:
        row = None
    if not row:
        raise HTTPException(404, f"candidate not found: {candidate_id}")
    return {"item": dict(row)}


# ------------------------------------------------------------------ #
# Mutations: bind / unbind / generate                                  #
# ------------------------------------------------------------------ #


class AuthSessionBindBody(BaseModel):
    auth_type: str = "jwt"
    header: Optional[str] = None
    cookie: Optional[str] = None
    role: Optional[str] = None
    config_json: Optional[str] = None


class AuthSessionUnbindBody(BaseModel):
    header: Optional[str] = None
    cookie: Optional[str] = None
    binding_id: Optional[str] = None
    force: bool = False


class AuthSessionGenerateBody(BaseModel):
    binding_id: Optional[str] = None
    flow_id: Optional[str] = None
    endpoint_id: Optional[str] = None
    module: Optional[str] = None
    role: Optional[str] = None
    test_ids: Optional[list[str]] = None
    families: Optional[list[str]] = None
    force_refresh: bool = False
    include_unsafe_methods: bool = False


def _bind_args(body: AuthSessionBindBody) -> list[str]:
    auth_type = (body.auth_type or "jwt").strip() or "jwt"
    args = ["attack", "auth-session", "bind", "--type", auth_type]
    header = (body.header or "").strip() or None
    cookie = (body.cookie or "").strip() or None
    if header and cookie:
        raise HTTPException(400, "provide only one of header or cookie")
    if header:
        args += ["--header", header]
    elif cookie:
        args += ["--cookie", cookie]
    else:
        raise HTTPException(400, "header or cookie required")
    if body.role and body.role.strip():
        args += ["--role", body.role.strip()]
    if body.config_json and body.config_json.strip():
        args += ["--config-json", body.config_json.strip()]
    return args


def _unbind_args(body: AuthSessionUnbindBody) -> list[str]:
    args = ["attack", "auth-session", "unbind"]
    header = (body.header or "").strip() or None
    cookie = (body.cookie or "").strip() or None
    binding_id = (body.binding_id or "").strip() or None
    provided = [x for x in (header, cookie, binding_id) if x]
    if len(provided) != 1:
        raise HTTPException(
            400,
            "provide exactly one of header, cookie, or binding_id",
        )
    if header:
        args += ["--header", header]
    elif cookie:
        args += ["--cookie", cookie]
    else:
        args += ["--id", binding_id]  # type: ignore[arg-type]
    if body.force:
        args.append("--force")
    return args


def _generate_args(body: AuthSessionGenerateBody) -> list[str]:
    endpoint = (body.endpoint_id or "").strip() or None
    module = (body.module or "").strip() or None
    if endpoint and module:
        raise HTTPException(
            400,
            "endpoint and module are mutually exclusive (CLI mutex)",
        )
    families = body.families or []
    _validate_families(families)

    args = ["attack", "auth-session", "generate"]
    if body.binding_id and body.binding_id.strip():
        args += ["--binding", body.binding_id.strip()]
    if body.flow_id and body.flow_id.strip():
        args += ["--flow", body.flow_id.strip()]
    if endpoint:
        args += ["--endpoint", endpoint]
    if module:
        args += ["--module", module]
    if body.role and body.role.strip():
        args += ["--role", body.role.strip()]
    for tid in body.test_ids or []:
        t = tid.strip()
        if t:
            args += ["--test-id", t]
    for fam in families:
        f = fam.strip()
        if f:
            args += ["--family", f]
    if body.force_refresh:
        args.append("--force-refresh")
    if body.include_unsafe_methods:
        args.append("--include-unsafe-methods")
    return args


@router.post("/auth-session/bindings")
def auth_session_bind(project_id: str, body: AuthSessionBindBody):
    args = _bind_args(body)
    results = cli.run_scoped(project_id, args)
    return {"steps": [r.to_dict() for r in results]}


@router.post("/auth-session/unbind")
def auth_session_unbind(project_id: str, body: AuthSessionUnbindBody):
    args = _unbind_args(body)
    results = cli.run_scoped(project_id, args)
    return {"steps": [r.to_dict() for r in results]}


@router.post("/auth-session/generate")
def auth_session_generate(project_id: str, body: AuthSessionGenerateBody):
    args = _generate_args(body)
    results = cli.run_scoped(project_id, args)
    return {"steps": [r.to_dict() for r in results]}
