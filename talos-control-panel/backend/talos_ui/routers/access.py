from fastapi import APIRouter
from pydantic import BaseModel

from .. import cli, config, db

router = APIRouter(prefix="/api/access", tags=["access"])


@router.get("/matrix")
def access_matrix(project_id: str):
    record = db.get_project_record(project_id)
    db_path = config.project_db_path(project_id, record)
    rows = db.query_all(
        db_path,
        """
        SELECT r.id AS role_id, r.name AS role_name,
               m.id AS module_id, m.name AS module_name,
               am.client_allowed, am.server_expected
        FROM roles r
        CROSS JOIN modules m
        LEFT JOIN access_map am ON am.role_id = r.id AND am.module_id = m.id
        ORDER BY r.name, m.name
        """,
    )
    return {"cells": rows}


class AccessSetBody(BaseModel):
    role: str
    module: str
    value: str  # ALLOW | DENY | UNKNOWN


@router.post("/client")
def set_client(project_id: str, body: AccessSetBody):
    results = cli.run_scoped(
        project_id, ["access", "client", "set", body.role, body.module, body.value.lower()]
    )
    return {"steps": [r.to_dict() for r in results]}


@router.post("/server")
def set_server(project_id: str, body: AccessSetBody):
    results = cli.run_scoped(
        project_id, ["access", "server", "set", body.role, body.module, body.value.lower()]
    )
    return {"steps": [r.to_dict() for r in results]}


class AccessPairBody(BaseModel):
    role: str
    module: str


@router.post("/client/unset")
def unset_client(project_id: str, body: AccessPairBody):
    results = cli.run_scoped(project_id, ["access", "client", "unset", body.role, body.module])
    return {"steps": [r.to_dict() for r in results]}


@router.post("/server/unset")
def unset_server(project_id: str, body: AccessPairBody):
    results = cli.run_scoped(project_id, ["access", "server", "unset", body.role, body.module])
    return {"steps": [r.to_dict() for r in results]}


@router.post("/delete")
def delete_mapping(project_id: str, body: AccessPairBody):
    results = cli.run_scoped(project_id, ["access", "delete", body.role, body.module])
    return {"steps": [r.to_dict() for r in results]}


@router.post("/coverage")
def run_coverage(project_id: str):
    results = cli.run_scoped(project_id, ["access", "coverage"])
    return {"steps": [r.to_dict() for r in results]}


@router.post("/signals")
def run_signals(project_id: str):
    results = cli.run_scoped(project_id, ["access", "signals"])
    return {"steps": [r.to_dict() for r in results]}
