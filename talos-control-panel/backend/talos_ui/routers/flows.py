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


def _filters(source, method, host, status_code, role, module, search, endpoint_id=None):
    conditions, params = [], []
    if source:
        conditions.append("f.source = ?"); params.append(source)
    if method:
        conditions.append("f.method = ?"); params.append(method)
    if host:
        conditions.append("f.host = ?"); params.append(host)
    if status_code is not None:
        conditions.append("f.status_code = ?"); params.append(status_code)
    if role:
        conditions.append("COALESCE(r.name, '—') = ?"); params.append(role)
    if module:
        conditions.append("COALESCE(m.name, '—') = ?"); params.append(module)
    if endpoint_id:
        conditions.append("f.endpoint_id = ?"); params.append(endpoint_id)
    if search:
        conditions.append("(f.host LIKE ? OR f.path LIKE ? OR f.query LIKE ?)")
        like = f"%{search}%"
        params += [like, like, like]
    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    return where, params


@router.get("")
def list_flows(
    project_id: str, offset: int = 0, limit: int = 100,
    source: str | None = None, method: str | None = None, host: str | None = None,
    status_code: int | None = None, role: str | None = None, module: str | None = None,
    search: str | None = None, endpoint: str | None = None, endpoint_id: str | None = None,
):
    record = db.get_project_record(project_id)
    db_path = config.project_db_path(project_id, record)
    ep = endpoint_id or endpoint
    where, params = _filters(source, method, host, status_code, role, module, search, ep)
    joins = "LEFT JOIN roles r ON r.id = f.role_id LEFT JOIN modules m ON m.id = f.module_id"
    rows = db.query_all(
        db_path,
        f"""
        SELECT f.id, f.method, f.host, f.path, f.query, f.status_code, f.source,
               f.captured_at, f.endpoint_id, f.original_flow_id, f.replay_reason,
               COALESCE(r.name, '—') AS role_name, COALESCE(m.name, '—') AS module_name
        FROM flows f {joins} {where}
        ORDER BY f.captured_at DESC LIMIT ? OFFSET ?
        """,
        (*params, limit, offset),
    )
    total = db.scalar(
        db_path, f"SELECT COUNT(*) FROM flows f {joins} {where}", tuple(params)
    )
    return {"flows": rows, "total": total}


@router.get("/filters")
def flow_filters(project_id: str):
    record = db.get_project_record(project_id)
    db_path = config.project_db_path(project_id, record)
    if not db.db_exists(db_path):
        return {"sources": [], "methods": [], "hosts": [], "statuses": [], "roles": [], "modules": []}
    return {
        "sources": [r["source"] for r in db.query_all(
            db_path, "SELECT DISTINCT source FROM flows WHERE source IS NOT NULL ORDER BY source")],
        "methods": [r["method"] for r in db.query_all(
            db_path, "SELECT DISTINCT method FROM flows ORDER BY method")],
        "hosts": [r["host"] for r in db.query_all(
            db_path, "SELECT DISTINCT host FROM flows ORDER BY host")],
        "statuses": [r["status_code"] for r in db.query_all(
            db_path, "SELECT DISTINCT status_code FROM flows WHERE status_code IS NOT NULL ORDER BY status_code")],
        "roles": [r["name"] for r in db.query_all(
            db_path, "SELECT DISTINCT r.name FROM flows f JOIN roles r ON r.id=f.role_id ORDER BY r.name")],
        "modules": [r["name"] for r in db.query_all(
            db_path, "SELECT DISTINCT m.name FROM flows f JOIN modules m ON m.id=f.module_id ORDER BY m.name")],
    }


@router.get("/{flow_id}")
def flow_detail(project_id: str, flow_id: str):
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
    row["request_headers"] = db.safe_json(row.get("request_headers"), {})
    row["request_cookies"] = db.safe_json(row.get("request_cookies"), {})
    row["response_headers"] = db.safe_json(row.get("response_headers"), {})
    row["tags"] = db.safe_json(row.get("tags"), [])
    row["flow_meta"] = db.safe_json(row.get("flow_meta"), {})
    row["request_body"], row["request_body_encoding"] = _decode_body(row.get("request_body"))
    row["response_body"], row["response_body_encoding"] = _decode_body(row.get("response_body"))
    diff = db.query_one(db_path, "SELECT * FROM replay_diffs WHERE replay_flow_id=?", (flow_id,))
    bac = db.query_one(db_path, "SELECT * FROM bac_results WHERE replay_flow_id=?", (flow_id,))
    unauth = db.query_one(db_path, "SELECT * FROM unauth_results WHERE replay_flow_id=?", (flow_id,))
    auth_test = db.query_one(db_path, "SELECT * FROM auth_test_results WHERE replay_flow_id=?", (flow_id,))
    return {"flow": row, "diff": diff, "bac_result": bac, "unauth_result": unauth, "auth_test_result": auth_test}


@router.get("/{flow_id}/adjacent")
def adjacent(project_id: str, flow_id: str):
    record = db.get_project_record(project_id)
    db_path = config.project_db_path(project_id, record)
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
