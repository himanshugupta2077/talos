"""
Flows API — list, detail, filters, export, related intelligence.

Reads are SQL-only against the project SQLite DB. Mutations (export) go through
CLI. Derived fields are presentation helpers only — never re-compute Core
verdicts or session health scores.
"""

from __future__ import annotations

from datetime import datetime
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
import base64

from .. import cli, config, db

router = APIRouter(prefix="/api/flows", tags=["flows"])


def _decode_body(value) -> tuple[str | None, str]:
    """SQLite BLOB columns come back as Python bytes; make them JSON-safe.
    Returns (text, encoding) where encoding is 'utf-8' or 'base64'."""
    if value is None:
        return None, "utf-8"
    if isinstance(value, str):
        return value, "utf-8"
    try:
        return value.decode("utf-8"), "utf-8"
    except UnicodeDecodeError:
        return base64.b64encode(value).decode("ascii"), "base64"


def _body_size(value) -> int:
    if value is None:
        return 0
    if isinstance(value, (bytes, bytearray)):
        return len(value)
    if isinstance(value, str):
        return len(value.encode("utf-8", errors="replace"))
    return 0


def _parse_iso(ts: str | None) -> datetime | None:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None


def _duration_ms(captured_at, response_end) -> int | None:
    start = _parse_iso(captured_at)
    end = _parse_iso(response_end)
    if start is None or end is None:
        return None
    return max(0, int((end - start).total_seconds() * 1000))


def _header_map(headers) -> dict:
    if isinstance(headers, dict):
        return headers
    if isinstance(headers, str):
        return db.safe_json(headers, {}) or {}
    return {}


def _has_auth_material(headers: dict, cookies: dict) -> bool:
    for k, v in (headers or {}).items():
        if str(k).lower() == "authorization" and v:
            return True
    if cookies and any(v for v in cookies.values()):
        return True
    for k, v in (headers or {}).items():
        if str(k).lower() == "cookie" and v:
            return True
    return False


def _filters(source, method, host, status_code, role, module, search, endpoint_id=None):
    conditions, params = [], []
    if source:
        conditions.append("f.source = ?")
        params.append(source)
    if method:
        conditions.append("f.method = ?")
        params.append(method)
    if host:
        conditions.append("f.host = ?")
        params.append(host)
    if status_code is not None:
        conditions.append("f.status_code = ?")
        params.append(status_code)
    if role:
        conditions.append("COALESCE(r.name, '—') = ?")
        params.append(role)
    if module:
        conditions.append("COALESCE(m.name, '—') = ?")
        params.append(module)
    if endpoint_id:
        conditions.append("f.endpoint_id = ?")
        params.append(endpoint_id)
    if search:
        conditions.append("(f.host LIKE ? OR f.path LIKE ? OR f.query LIKE ?)")
        like = f"%{search}%"
        params += [like, like, like]
    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    return where, params


def _enrich_flow_row(row: dict) -> dict:
    """Parse JSON columns and decode bodies on a flows detail row."""
    row["request_headers"] = db.safe_json(row.get("request_headers"), {})
    row["request_cookies"] = db.safe_json(row.get("request_cookies"), {})
    row["response_headers"] = db.safe_json(row.get("response_headers"), {})
    row["tags"] = db.safe_json(row.get("tags"), [])
    row["flow_meta"] = db.safe_json(row.get("flow_meta"), {})
    raw_req = row.get("request_body")
    raw_resp = row.get("response_body")
    req_size = _body_size(raw_req)
    resp_size = _body_size(raw_resp)
    row["request_body"], row["request_body_encoding"] = _decode_body(raw_req)
    row["response_body"], row["response_body_encoding"] = _decode_body(raw_resp)
    # Expose truncation as booleans for the UI
    row["request_body_truncated"] = bool(row.get("request_body_truncated"))
    row["response_body_truncated"] = bool(row.get("response_body_truncated"))
    return row, req_size, resp_size


def _derived_for_flow(row: dict, req_size: int, resp_size: int) -> dict:
    headers = row.get("request_headers") or {}
    cookies = row.get("request_cookies") or {}
    return {
        "duration_ms": _duration_ms(row.get("captured_at"), row.get("response_end")),
        "request_body_size": req_size,
        "response_body_size": resp_size,
        "has_auth_material": _has_auth_material(headers, cookies),
        "request_body_truncated": bool(row.get("request_body_truncated")),
        "response_body_truncated": bool(row.get("response_body_truncated")),
        "is_replay": bool(row.get("original_flow_id")),
        "has_request_body": req_size > 0 or bool(row.get("request_body")),
        "has_response_body": resp_size > 0 or bool(row.get("response_body")),
    }


@router.get("")
def list_flows(
    project_id: str,
    offset: int = 0,
    limit: int = 100,
    source: str | None = None,
    method: str | None = None,
    host: str | None = None,
    status_code: int | None = None,
    role: str | None = None,
    module: str | None = None,
    search: str | None = None,
    endpoint: str | None = None,
    endpoint_id: str | None = None,
    include: str | None = None,
):
    """
    List flows with optional lightweight intelligence flags.

    Pass include=flags (or include=flags,anything) to attach has_diff / has_bac /
    has_unauth / has_finding_evidence / is_replay / body_truncated columns.
    Flags use LEFT JOINs / EXISTS so list stays fast for typical project sizes.
    """
    record = db.get_project_record(project_id)
    db_path = config.project_db_path(project_id, record)
    ep = endpoint_id or endpoint
    where, params = _filters(source, method, host, status_code, role, module, search, ep)
    joins = "LEFT JOIN roles r ON r.id = f.role_id LEFT JOIN modules m ON m.id = f.module_id"
    want_flags = include and "flags" in {p.strip() for p in include.split(",")}

    flag_select = ""
    flag_joins = ""
    if want_flags:
        flag_select = """
               , CASE WHEN f.original_flow_id IS NOT NULL THEN 1 ELSE 0 END AS is_replay
               , CASE WHEN (f.request_body_truncated = 1 OR f.response_body_truncated = 1)
                      THEN 1 ELSE 0 END AS body_truncated
               , CASE WHEN rd.replay_flow_id IS NOT NULL OR child_diff.cnt > 0
                      THEN 1 ELSE 0 END AS has_diff
               , CASE WHEN bac.replay_flow_id IS NOT NULL THEN 1 ELSE 0 END AS has_bac
               , CASE WHEN unauth.replay_flow_id IS NOT NULL THEN 1 ELSE 0 END AS has_unauth
               , CASE WHEN fe.cnt > 0 THEN 1 ELSE 0 END AS has_finding_evidence
        """
        flag_joins = """
            LEFT JOIN replay_diffs rd ON rd.replay_flow_id = f.id
            LEFT JOIN bac_results bac ON bac.replay_flow_id = f.id
            LEFT JOIN unauth_results unauth ON unauth.replay_flow_id = f.id
            LEFT JOIN (
                SELECT child.original_flow_id AS oid, COUNT(*) AS cnt
                FROM flows child
                JOIN replay_diffs rd2 ON rd2.replay_flow_id = child.id
                WHERE child.original_flow_id IS NOT NULL
                GROUP BY child.original_flow_id
            ) child_diff ON child_diff.oid = f.id
            LEFT JOIN (
                SELECT reference_id AS rid, COUNT(*) AS cnt
                FROM finding_evidence
                WHERE reference_id IS NOT NULL
                GROUP BY reference_id
            ) fe ON fe.rid = f.id
        """

    rows = db.query_all(
        db_path,
        f"""
        SELECT f.id, f.method, f.host, f.path, f.query, f.status_code, f.source,
               f.captured_at, f.endpoint_id, f.original_flow_id, f.replay_reason,
               COALESCE(r.name, '—') AS role_name, COALESCE(m.name, '—') AS module_name
               {flag_select}
        FROM flows f
        {joins}
        {flag_joins}
        {where}
        ORDER BY f.captured_at DESC LIMIT ? OFFSET ?
        """,
        (*params, limit, offset),
    )
    total = db.scalar(
        db_path, f"SELECT COUNT(*) FROM flows f {joins} {where}", tuple(params)
    )
    if want_flags:
        for r in rows:
            for key in (
                "is_replay",
                "body_truncated",
                "has_diff",
                "has_bac",
                "has_unauth",
                "has_finding_evidence",
            ):
                if key in r:
                    r[key] = bool(r[key])
    return {"flows": rows, "total": total}


@router.get("/filters")
def flow_filters(project_id: str):
    record = db.get_project_record(project_id)
    db_path = config.project_db_path(project_id, record)
    if not db.db_exists(db_path):
        return {
            "sources": [],
            "methods": [],
            "hosts": [],
            "statuses": [],
            "roles": [],
            "modules": [],
        }
    return {
        "sources": [
            r["source"]
            for r in db.query_all(
                db_path,
                "SELECT DISTINCT source FROM flows WHERE source IS NOT NULL ORDER BY source",
            )
        ],
        "methods": [
            r["method"]
            for r in db.query_all(db_path, "SELECT DISTINCT method FROM flows ORDER BY method")
        ],
        "hosts": [
            r["host"]
            for r in db.query_all(db_path, "SELECT DISTINCT host FROM flows ORDER BY host")
        ],
        "statuses": [
            r["status_code"]
            for r in db.query_all(
                db_path,
                "SELECT DISTINCT status_code FROM flows WHERE status_code IS NOT NULL ORDER BY status_code",
            )
        ],
        "roles": [
            r["name"]
            for r in db.query_all(
                db_path,
                "SELECT DISTINCT r.name FROM flows f JOIN roles r ON r.id=f.role_id ORDER BY r.name",
            )
        ],
        "modules": [
            r["name"]
            for r in db.query_all(
                db_path,
                "SELECT DISTINCT m.name FROM flows f JOIN modules m ON m.id=f.module_id ORDER BY m.name",
            )
        ],
    }


@router.get("/{flow_id}")
def flow_detail(project_id: str, flow_id: str):
    """
    Full flow row + attack/replay side data + derived presentation fields.

    Backward-compatible keys (diff, bac_result, …) remain; nested `results`
    and `derived` are preferred by the inspection workspace UI.
    """
    record = db.get_project_record(project_id)
    db_path = config.project_db_path(project_id, record)
    row = db.query_one(
        db_path,
        """
        SELECT f.*, COALESCE(r.name,'—') AS role_name, COALESCE(m.name,'—') AS module_name
        FROM flows f
        LEFT JOIN roles r ON r.id = f.role_id
        LEFT JOIN modules m ON m.id = f.module_id
        WHERE f.id = ?
        """,
        (flow_id,),
    )
    if row is None:
        raise HTTPException(404, "flow not found")
    row, req_size, resp_size = _enrich_flow_row(row)
    derived = _derived_for_flow(row, req_size, resp_size)

    # Diff on this flow as a replay, or any child replay with a diff
    diff = db.query_one(
        db_path, "SELECT * FROM replay_diffs WHERE replay_flow_id=?", (flow_id,)
    )
    if diff is None:
        # original may have child diffs — surface first for chip purposes
        child_diff = db.query_one(
            db_path,
            """
            SELECT rd.* FROM replay_diffs rd
            JOIN flows c ON c.id = rd.replay_flow_id
            WHERE c.original_flow_id = ?
            ORDER BY c.captured_at DESC LIMIT 1
            """,
            (flow_id,),
        )
        if child_diff is not None:
            child_diff = dict(child_diff)
            child_diff["_from_child"] = True
            diff = child_diff

    bac = db.query_one(db_path, "SELECT * FROM bac_results WHERE replay_flow_id=?", (flow_id,))
    unauth = db.query_one(
        db_path, "SELECT * FROM unauth_results WHERE replay_flow_id=?", (flow_id,)
    )
    auth_test = db.query_one(
        db_path, "SELECT * FROM auth_test_results WHERE replay_flow_id=?", (flow_id,)
    )

    # Endpoint policy snippet when linked (qualified / baseline / logout)
    endpoint_policy = None
    if row.get("endpoint_id"):
        endpoint_policy = db.query_one(
            db_path,
            """
            SELECT ep.qualified, ep.qualification_reason, ep.baseline_flow_id,
                   ep.baseline_status, ep.excluded, ep.dangerous, ep.logout,
                   ep.manual_priority, ep.auto_priority, ep.notes, ep.tags
            FROM endpoint_policy ep
            WHERE ep.endpoint_id = ?
            """,
            (row["endpoint_id"],),
        )
        if endpoint_policy and endpoint_policy.get("tags"):
            endpoint_policy["tags"] = db.safe_json(endpoint_policy.get("tags"), [])

    results = {
        "diff": diff,
        "bac": bac,
        "unauth": unauth,
        "auth_test": auth_test,
    }
    return {
        "flow": row,
        "derived": derived,
        "results": results,
        "endpoint_policy": endpoint_policy,
        # Backward-compatible aliases
        "diff": diff,
        "bac_result": bac,
        "unauth_result": unauth,
        "auth_test_result": auth_test,
    }


@router.get("/{flow_id}/related")
def flow_related(project_id: str, flow_id: str):
    """
    Related objects for the inspection workspace right rail / timeline.

    Returns only rows that exist in Core tables — never invents events.
    """
    record = db.get_project_record(project_id)
    db_path = config.project_db_path(project_id, record)
    exists = db.query_one(db_path, "SELECT id, original_flow_id, endpoint_id, role_id, module_id FROM flows WHERE id=?", (flow_id,))
    if exists is None:
        raise HTTPException(404, "flow not found")

    original = None
    if exists.get("original_flow_id"):
        original = db.query_one(
            db_path,
            """
            SELECT f.id, f.method, f.host, f.path, f.status_code, f.source,
                   f.captured_at, f.replay_reason
            FROM flows f WHERE f.id = ?
            """,
            (exists["original_flow_id"],),
        )

    children = db.query_all(
        db_path,
        """
        SELECT f.id, f.method, f.host, f.path, f.status_code, f.source,
               f.captured_at, f.replay_reason, f.replay_error,
               rd.verdict AS diff_verdict, rd.status_diff, rd.length_diff
        FROM flows f
        LEFT JOIN replay_diffs rd ON rd.replay_flow_id = f.id
        WHERE f.original_flow_id = ?
        ORDER BY f.captured_at DESC
        LIMIT 50
        """,
        (flow_id,),
    )

    findings = db.query_all(
        db_path,
        """
        SELECT fe.id AS evidence_id, fe.evidence_type, fe.label, fe.created_at,
               fnd.id AS finding_id, fnd.title, fnd.status, fnd.attack_type, fnd.verdict
        FROM finding_evidence fe
        JOIN findings fnd ON fnd.id = fe.finding_id
        WHERE fe.reference_id = ?
        ORDER BY fe.created_at DESC
        LIMIT 30
        """,
        (flow_id,),
    )

    jobs = db.query_all(
        db_path,
        """
        SELECT job_id, job_type, status, priority, created_at, finished_at,
               verdict, flow_id, replayed_flow_id, endpoint_id, failure_reason
        FROM scheduler_jobs
        WHERE flow_id = ? OR replayed_flow_id = ?
        ORDER BY created_at DESC
        LIMIT 30
        """,
        (flow_id, flow_id),
    )

    param_count = 0
    if exists.get("endpoint_id"):
        cnt = db.scalar(
            db_path,
            "SELECT COUNT(*) FROM parameters WHERE endpoint_id = ?",
            (exists["endpoint_id"],),
        )
        param_count = int(cnt or 0)

    return {
        "original": original,
        "children": children,
        "findings": findings,
        "jobs": jobs,
        "param_count": param_count,
    }


@router.get("/{flow_id}/intelligence")
def flow_intelligence(project_id: str, flow_id: str):
    """
    Endpoint policy snippet + role session snapshot for the flow's role.

    Session fields are a thin read of the same tables Auth uses — no client-side
    health scoring. Returns null sections when role/endpoint absent.
    """
    record = db.get_project_record(project_id)
    db_path = config.project_db_path(project_id, record)
    flow = db.query_one(
        db_path,
        "SELECT id, role_id, endpoint_id, module_id FROM flows WHERE id = ?",
        (flow_id,),
    )
    if flow is None:
        raise HTTPException(404, "flow not found")

    endpoint = None
    if flow.get("endpoint_id"):
        endpoint = db.query_one(
            db_path,
            """
            SELECT e.id, e.method, e.host, e.normalized_path, e.path,
                   ep.qualified, ep.qualification_reason, ep.baseline_flow_id,
                   ep.baseline_status, ep.excluded, ep.dangerous, ep.logout,
                   ep.manual_priority, ep.auto_priority
            FROM endpoints e
            LEFT JOIN endpoint_policy ep ON ep.endpoint_id = e.id
            WHERE e.id = ?
            """,
            (flow["endpoint_id"],),
        )

    session = None
    role_id = flow.get("role_id")
    if role_id:
        provider = db.query_one(
            db_path,
            "SELECT provider, updated_at FROM role_auth_provider WHERE role_id=?",
            (role_id,),
        )
        artifacts = db.query_all(
            db_path,
            "SELECT key, value, collected_at FROM role_auth_state WHERE role_id=?",
            (role_id,),
        )
        health_row = db.query_one(
            db_path,
            "SELECT ttl_seconds, refresh_before_seconds FROM session_health_config WHERE role_id=?",
            (role_id,),
        )
        suspicion = db.query_one(
            db_path,
            "SELECT suspicion_count, last_checked_at FROM session_suspicion_state WHERE role_id=?",
            (role_id,),
        )
        role_name_row = db.query_one(
            db_path, "SELECT name FROM roles WHERE id=?", (role_id,)
        )
        suspicion_count = (suspicion or {}).get("suspicion_count") or 0
        # Match auth_config threshold used for degraded display
        health_degraded = suspicion_count >= 3
        session = {
            "role_id": role_id,
            "role_name": (role_name_row or {}).get("name"),
            "provider": (provider or {}).get("provider") if provider else None,
            "artifact_keys": [a.get("key") for a in artifacts if a.get("key")],
            "artifact_count": len(artifacts),
            "collected_at": next(
                (a.get("collected_at") for a in artifacts if a.get("collected_at")), None
            ),
            "ttl_seconds": (health_row or {}).get("ttl_seconds") if health_row else None,
            "suspicion_count": suspicion_count,
            "last_checked_at": (suspicion or {}).get("last_checked_at") if suspicion else None,
            "health_degraded": health_degraded,
            "has_artifacts": len(artifacts) > 0,
        }

    return {
        "endpoint": endpoint,
        "session": session,
    }


@router.get("/{flow_id}/adjacent")
def adjacent(
    project_id: str,
    flow_id: str,
    source: str | None = None,
    method: str | None = None,
    host: str | None = None,
    status_code: int | None = None,
    role: str | None = None,
    module: str | None = None,
    search: str | None = None,
    endpoint: str | None = None,
    endpoint_id: str | None = None,
):
    """
    Prev/next neighbors by captured_at DESC.

    When filter query params are provided, neighbors respect the same filters
    as the list page so keyboard navigation stays in-context.
    """
    record = db.get_project_record(project_id)
    db_path = config.project_db_path(project_id, record)
    ep = endpoint_id or endpoint
    where, params = _filters(source, method, host, status_code, role, module, search, ep)
    joins = "LEFT JOIN roles r ON r.id = f.role_id LEFT JOIN modules m ON m.id = f.module_id"

    # When no filters, keep the simple global window (fast path).
    if not where:
        row = db.query_one(
            db_path,
            """
            WITH ordered AS (
                SELECT id,
                       LAG(id) OVER (ORDER BY captured_at DESC) AS prev_id,
                       LEAD(id) OVER (ORDER BY captured_at DESC) AS next_id
                FROM flows
            )
            SELECT prev_id, next_id FROM ordered WHERE id = ?
            """,
            (flow_id,),
        )
        return row or {"prev_id": None, "next_id": None}

    row = db.query_one(
        db_path,
        f"""
        WITH ordered AS (
            SELECT f.id,
                   LAG(f.id) OVER (ORDER BY f.captured_at DESC) AS prev_id,
                   LEAD(f.id) OVER (ORDER BY f.captured_at DESC) AS next_id
            FROM flows f
            {joins}
            {where}
        )
        SELECT prev_id, next_id FROM ordered WHERE id = ?
        """,
        (*params, flow_id),
    )
    return row or {"prev_id": None, "next_id": None}


class ExportBody(BaseModel):
    module: str | None = None
    parameter: str | None = None
    endpoint: str | None = None
    flows: list[str] = []


@router.post("/{flow_id}/export")
def export_flow(project_id: str, flow_id: str):
    results = cli.run_scoped(project_id, ["flow", "export", flow_id])
    return {"steps": [r.to_dict() for r in results]}


@router.post("/export")
def export_flows(project_id: str, body: ExportBody):
    args = ["flow", "export"]
    if body.module:
        args += ["--module", body.module]
    if body.parameter:
        args += ["--parameter", body.parameter]
    if body.endpoint:
        args += ["--endpoint", body.endpoint]
    for f in body.flows:
        args += ["--flows", f]
    results = cli.run_scoped(project_id, args)
    return {"steps": [r.to_dict() for r in results]}
