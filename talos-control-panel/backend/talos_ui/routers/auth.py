from fastapi import APIRouter
from pydantic import BaseModel

from .. import cli, config, db

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.get("")
def show_auth(project_id: str):
    record = db.get_project_record(project_id)
    db_path = config.project_db_path(project_id, record)
    rows = db.query_all(db_path, "SELECT type, name FROM auth_config ORDER BY type, name")
    return {"artifacts": rows}


class AuthSetBody(BaseModel):
    cookies: list[str] = []
    headers: list[str] = []


@router.post("/set")
def set_auth(project_id: str, body: AuthSetBody):
    args = ["auth", "set"]
    for c in body.cookies:
        args += ["--cookie", c]
    for h in body.headers:
        args += ["--header", h]
    results = cli.run_scoped(project_id, args)
    return {"steps": [r.to_dict() for r in results]}


@router.post("/unset")
def unset_auth(project_id: str, body: AuthSetBody):
    args = ["auth", "unset"]
    for c in body.cookies:
        args += ["--cookie", c]
    for h in body.headers:
        args += ["--header", h]
    results = cli.run_scoped(project_id, args)
    return {"steps": [r.to_dict() for r in results]}


@router.post("/clear")
def clear_auth(project_id: str):
    # Non-interactive CLI requires --force (UI confirmation already happened).
    results = cli.run_scoped(project_id, ["auth", "clear", "--force"])
    return {"steps": [r.to_dict() for r in results]}


class AuthTestBody(BaseModel):
    endpoint_id: str
    right_now: bool = False


@router.post("/test")
def test_auth(project_id: str, body: AuthTestBody):
    """Authentication-bypass test against an endpoint (not role session setup)."""
    args = ["auth", "test", body.endpoint_id]
    if body.right_now:
        args.append("--right-now")
    results = cli.run_scoped(project_id, args)
    return {"steps": [r.to_dict() for r in results]}


@router.get("/test-results")
def auth_test_results(project_id: str, limit: int = 100):
    record = db.get_project_record(project_id)
    db_path = config.project_db_path(project_id, record)
    rows = db.query_all(
        db_path,
        """
        SELECT atr.replay_flow_id, atr.original_flow_id, atr.verdict,
               f.captured_at, f.method, f.path, f.status_code, f.endpoint_id
        FROM auth_test_results atr
        JOIN flows f ON f.id = atr.replay_flow_id
        ORDER BY f.captured_at DESC
        LIMIT ?
        """,
        (limit,),
    )
    return {"results": rows}
