"""
Access Model API — role×module matrix, bulk edits, structured coverage/signals.

Mutations always go through `talos access …` (CLI). Reads use project SQLite
and the same analysis helpers as `talos access coverage|signals`.
"""

from __future__ import annotations

from typing import Literal, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from .. import cli, config, db

router = APIRouter(prefix="/api/access", tags=["access"])

BULK_OP_LIMIT = 200
VALID_VALUES = frozenset({"ALLOW", "DENY", "UNKNOWN"})
BulkOpName = Literal[
    "client_set",
    "server_set",
    "client_unset",
    "server_unset",
    "delete",
]


def _db_path(project_id: str):
    record = db.get_project_record(project_id)
    return config.project_db_path(project_id, record)


@router.get("/matrix")
def access_matrix(project_id: str):
    """
    Full role×module grid with access_map values and observed traffic counts.
    CROSS JOIN so unset pairs appear as null client/server.
    """
    db_path = _db_path(project_id)
    if not db_path.exists():
        return {"cells": []}

    # Observation counts only when flows table exists.
    with db.connect(db_path) as conn:
        has_flows = db.table_exists(conn, "flows")

    if has_flows:
        rows = db.query_all(
            db_path,
            """
            SELECT r.id AS role_id, r.name AS role_name,
                   m.id AS module_id, m.name AS module_name,
                   am.client_allowed, am.server_expected,
                   COALESCE(obs.flow_count, 0) AS flow_count,
                   COALESCE(obs.endpoint_count, 0) AS endpoint_count
            FROM roles r
            CROSS JOIN modules m
            LEFT JOIN access_map am
              ON am.role_id = r.id AND am.module_id = m.id
            LEFT JOIN (
                SELECT role_id, module_id,
                       COUNT(DISTINCT id) AS flow_count,
                       COUNT(DISTINCT endpoint_id) AS endpoint_count
                FROM flows
                GROUP BY role_id, module_id
            ) obs ON obs.role_id = r.id AND obs.module_id = m.id
            ORDER BY r.name, m.name
            """,
        )
    else:
        rows = db.query_all(
            db_path,
            """
            SELECT r.id AS role_id, r.name AS role_name,
                   m.id AS module_id, m.name AS module_name,
                   am.client_allowed, am.server_expected,
                   0 AS flow_count,
                   0 AS endpoint_count
            FROM roles r
            CROSS JOIN modules m
            LEFT JOIN access_map am
              ON am.role_id = r.id AND am.module_id = m.id
            ORDER BY r.name, m.name
            """,
        )
    return {"cells": rows}


class AccessSetBody(BaseModel):
    role: str
    module: str
    value: str  # ALLOW | DENY | UNKNOWN


def _normalize_value(value: str) -> str:
    upper = (value or "").strip().upper()
    if upper not in VALID_VALUES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid value '{value}'. Must be one of: allow, deny, unknown.",
        )
    return upper


@router.post("/client")
def set_client(project_id: str, body: AccessSetBody):
    value = _normalize_value(body.value)
    results = cli.run_scoped(
        project_id,
        ["access", "client", "set", body.role, body.module, value.lower()],
    )
    return {"steps": [r.to_dict() for r in results]}


@router.post("/server")
def set_server(project_id: str, body: AccessSetBody):
    value = _normalize_value(body.value)
    results = cli.run_scoped(
        project_id,
        ["access", "server", "set", body.role, body.module, value.lower()],
    )
    return {"steps": [r.to_dict() for r in results]}


class AccessPairBody(BaseModel):
    role: str
    module: str


@router.post("/client/unset")
def unset_client(project_id: str, body: AccessPairBody):
    results = cli.run_scoped(
        project_id, ["access", "client", "unset", body.role, body.module]
    )
    return {"steps": [r.to_dict() for r in results]}


@router.post("/server/unset")
def unset_server(project_id: str, body: AccessPairBody):
    results = cli.run_scoped(
        project_id, ["access", "server", "unset", body.role, body.module]
    )
    return {"steps": [r.to_dict() for r in results]}


@router.post("/delete")
def delete_mapping(project_id: str, body: AccessPairBody):
    # Non-interactive CLI requires --force; UI confirmation already happened.
    results = cli.run_scoped(
        project_id, ["access", "delete", body.role, body.module, "--force"]
    )
    return {"steps": [r.to_dict() for r in results]}


class BulkOp(BaseModel):
    op: BulkOpName
    role: str
    module: str
    value: Optional[str] = None


class BulkBody(BaseModel):
    operations: list[BulkOp] = Field(default_factory=list)


def _bulk_argv(op: BulkOp) -> list[str]:
    if op.op == "client_set":
        if not op.value:
            raise HTTPException(status_code=400, detail="client_set requires value")
        return [
            "access",
            "client",
            "set",
            op.role,
            op.module,
            _normalize_value(op.value).lower(),
        ]
    if op.op == "server_set":
        if not op.value:
            raise HTTPException(status_code=400, detail="server_set requires value")
        return [
            "access",
            "server",
            "set",
            op.role,
            op.module,
            _normalize_value(op.value).lower(),
        ]
    if op.op == "client_unset":
        return ["access", "client", "unset", op.role, op.module]
    if op.op == "server_unset":
        return ["access", "server", "unset", op.role, op.module]
    if op.op == "delete":
        return ["access", "delete", op.role, op.module, "--force"]
    raise HTTPException(status_code=400, detail=f"Unknown op '{op.op}'")


@router.post("/bulk")
def bulk_apply(project_id: str, body: BulkBody):
    """
    Apply multiple access mutations sequentially via CLI.
    Cap protects against runaway bulk fills.
    """
    ops = body.operations or []
    if not ops:
        raise HTTPException(status_code=400, detail="operations must not be empty")
    if len(ops) > BULK_OP_LIMIT:
        raise HTTPException(
            status_code=400,
            detail=f"Too many operations ({len(ops)}). Max is {BULK_OP_LIMIT}.",
        )

    all_steps: list[dict] = []
    applied = 0
    failed = 0
    for op in ops:
        argv = _bulk_argv(op)
        results = cli.run_scoped(project_id, argv)
        step_dicts = [r.to_dict() for r in results]
        all_steps.extend(step_dicts)
        # Last step for this op determines success (open+command pattern).
        if step_dicts and step_dicts[-1].get("ok"):
            applied += 1
        else:
            failed += 1

    return {
        "steps": all_steps,
        "ok": failed == 0,
        "applied": applied,
        "failed": failed,
    }


@router.get("/coverage")
def get_coverage(project_id: str):
    """Structured expected-vs-observed coverage (same data as talos access coverage)."""
    db_path = _db_path(project_id)
    if not db_path.exists():
        return {"rows": []}
    from talos.projects.access import get_access_coverage

    rows = get_access_coverage(db_path)
    return {"rows": rows}


@router.get("/signals")
def get_signals(project_id: str):
    """Structured BAC/IDOR signals (same data as talos access signals)."""
    db_path = _db_path(project_id)
    if not db_path.exists():
        return {
            "multi_role": [],
            "server_deny_endpoints": [],
            "deny_with_flows": [],
            "allow_without_flows": [],
        }
    from talos.projects.access import (
        detect_allow_without_flows,
        detect_deny_with_flows,
        detect_server_deny_endpoints,
        list_endpoints_multi_role,
    )

    return {
        "multi_role": list_endpoints_multi_role(db_path),
        "server_deny_endpoints": detect_server_deny_endpoints(db_path),
        "deny_with_flows": detect_deny_with_flows(db_path),
        "allow_without_flows": detect_allow_without_flows(db_path),
    }


@router.post("/coverage")
def run_coverage(project_id: str):
    """CLI coverage report (stdout in steps) — Console / legacy parity."""
    results = cli.run_scoped(project_id, ["access", "coverage"])
    return {"steps": [r.to_dict() for r in results]}


@router.post("/signals")
def run_signals(project_id: str):
    """CLI signals report (stdout in steps) — Console / legacy parity."""
    results = cli.run_scoped(project_id, ["access", "signals"])
    return {"steps": [r.to_dict() for r in results]}
