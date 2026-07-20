from fastapi import APIRouter
from pydantic import BaseModel

from .. import cli, config, db

router = APIRouter(prefix="/api/attack", tags=["attack"])

BAC_TECHNIQUES = [
    "session-swap", "method-fuzz", "content-type", "url-fuzz",
    "header-inject", "host-fuzz", "role-inject", "parser-confuse",
]


# ------------------------------------------------------------------ #
# Unauth                                                               #
# ------------------------------------------------------------------ #

@router.get("/unauth/results")
def unauth_results(project_id: str, verdict: str | None = None, limit: int = 200):
    record = db.get_project_record(project_id)
    db_path = config.project_db_path(project_id, record)
    where = "WHERE ur.verdict = ?" if verdict else ""
    params = (verdict, limit) if verdict else (limit,)
    rows = db.query_all(
        db_path,
        f"""
        SELECT ur.*, f.method, f.path, f.status_code, f.host, f.captured_at
        FROM unauth_results ur
        JOIN flows f ON f.id = ur.replay_flow_id
        {where}
        ORDER BY f.captured_at DESC LIMIT ?
        """,
        params,
    )
    return {"results": rows}


@router.get("/unauth/summary")
def unauth_summary(project_id: str):
    record = db.get_project_record(project_id)
    db_path = config.project_db_path(project_id, record)
    rows = db.query_all(db_path, "SELECT verdict, COUNT(*) AS n FROM unauth_results GROUP BY verdict")
    return {"counts": {r["verdict"]: r["n"] for r in rows}}


class UnauthRunBody(BaseModel):
    max_priority: int | None = None
    auth_mutation: str | None = None


@router.post("/unauth/run")
def run_unauth(project_id: str, body: UnauthRunBody):
    args = ["attack", "unauth", "run"]
    if body.max_priority is not None:
        args += ["--max-priority", str(body.max_priority)]
    if body.auth_mutation:
        args += ["--auth-mutation", body.auth_mutation]
    results = cli.run_scoped(project_id, args)
    return {"steps": [r.to_dict() for r in results]}


@router.post("/unauth/filter/init")
def unauth_filter_init(project_id: str):
    results = cli.run_scoped(project_id, ["attack", "unauth", "filter", "init"])
    return {"steps": [r.to_dict() for r in results]}


@router.post("/unauth/filter/show")
def unauth_filter_show(project_id: str):
    results = cli.run_scoped(project_id, ["attack", "unauth", "filter", "show"])
    return {"steps": [r.to_dict() for r in results]}


@router.post("/unauth/filter/validate")
def unauth_filter_validate(project_id: str):
    results = cli.run_scoped(project_id, ["attack", "unauth", "filter", "validate"])
    return {"steps": [r.to_dict() for r in results]}


# ------------------------------------------------------------------ #
# BAC                                                                  #
# ------------------------------------------------------------------ #

@router.get("/bac/results")
def bac_results(project_id: str, verdict: str | None = None, limit: int = 200):
    record = db.get_project_record(project_id)
    db_path = config.project_db_path(project_id, record)
    where = "WHERE br.verdict = ?" if verdict else ""
    params = (verdict, limit) if verdict else (limit,)
    rows = db.query_all(
        db_path,
        f"""
        SELECT br.*, f.method, f.path, f.status_code, f.host, f.captured_at,
               ar.name AS attacker_role_name, tr.name AS target_role_name, mo.name AS module_name
        FROM bac_results br
        JOIN flows f ON f.id = br.replay_flow_id
        LEFT JOIN roles ar ON ar.id = br.attacker_role_id
        LEFT JOIN roles tr ON tr.id = br.target_role_id
        LEFT JOIN modules mo ON mo.id = br.module_id
        {where}
        ORDER BY f.captured_at DESC LIMIT ?
        """,
        params,
    )
    return {"results": rows}


@router.get("/bac/summary")
def bac_summary(project_id: str):
    record = db.get_project_record(project_id)
    db_path = config.project_db_path(project_id, record)
    rows = db.query_all(db_path, "SELECT verdict, COUNT(*) AS n FROM bac_results GROUP BY verdict")
    return {"counts": {r["verdict"]: r["n"] for r in rows}}


class BacRunBody(BaseModel):
    role: str | None = None
    auto_generate: bool = False


@router.post("/bac/{technique}")
def run_bac(project_id: str, technique: str, body: BacRunBody):
    if technique not in BAC_TECHNIQUES:
        return {"error": f"unknown technique '{technique}'"}
    args = ["attack", "bac", technique]
    if body.role:
        args += ["--role", body.role]
    if body.auto_generate:
        args.append("--auto-generate")
    results = cli.run_scoped(project_id, args)
    return {"steps": [r.to_dict() for r in results]}


@router.post("/bac/filter/init")
def bac_filter_init(project_id: str):
    results = cli.run_scoped(project_id, ["attack", "bac", "filter", "init"])
    return {"steps": [r.to_dict() for r in results]}


@router.post("/bac/filter/show")
def bac_filter_show(project_id: str):
    results = cli.run_scoped(project_id, ["attack", "bac", "filter", "show"])
    return {"steps": [r.to_dict() for r in results]}


@router.post("/bac/filter/validate")
def bac_filter_validate(project_id: str):
    results = cli.run_scoped(project_id, ["attack", "bac", "filter", "validate"])
    return {"steps": [r.to_dict() for r in results]}
