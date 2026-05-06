"""
Module: talos.ui.api.access

Purpose:
    REST routes for the role-module access matrix (BAC model).
    Exposes the two-layer client/server access model for reading and writing,
    plus analytical views: coverage and signals.

Dependencies: fastapi, pydantic, talos.projects.access, talos.ui.db, talos.ui.api._deps
Data flow:
    HTTP request → route → talos.projects.access (writes) / talos.ui.db (reads) → JSON response
Side effects:
    PUT /api/access        — upserts one row in access_map.
    DELETE /api/access/{role}/{module} — deletes one row from access_map.

Routes:
    GET    /api/access                     → full access matrix
    PUT    /api/access                     → set client or server access state
    DELETE /api/access/{role}/{module}     → remove entire access-map row
    GET    /api/access/coverage            → per-(role,module) flow + endpoint counts
    GET    /api/access/signals             → BAC warning signals
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Literal

from talos.projects import access as acc
from talos.ui import db as idb
from talos.ui.api._deps import ActiveProject

router = APIRouter(prefix="/access", tags=["access"])


class _SetAccessBody(BaseModel):
    role: str
    module: str
    layer: Literal["client", "server"]
    state: Literal["allow", "deny", "unknown"]


@router.get("/coverage")
def get_coverage(project: ActiveProject) -> list[dict]:
    """
    Purpose: Return per-(role,module) flow counts and endpoint exposure counts.
    Output:  List of dicts: role_name, module_name, client_allowed, server_expected,
             flow_count, endpoint_count.
    Side effects: None.
    """
    return idb.get_access_coverage(project.db_path)


@router.get("/signals")
def get_signals(project: ActiveProject) -> dict:
    """
    Purpose: Return all four BAC warning signal sets for the active project.
    Output:  Dict with keys:
        multi_role              — endpoints accessed by more than one role.
        server_deny             — endpoints reached where server_expected=DENY.
        client_deny_with_flows  — role/module pairs where client=DENY but traffic exists.
        client_allow_without_flows — role/module pairs where client=ALLOW but no flows.
    Side effects: None.
    """
    return {
        "multi_role": idb.list_endpoints_multi_role(project.db_path),
        "server_deny": idb.detect_server_deny_endpoints(project.db_path),
        "client_deny_with_flows": idb.detect_deny_with_flows(project.db_path),
        "client_allow_without_flows": idb.detect_allow_without_flows(project.db_path),
    }


@router.get("")
def get_access_matrix(project: ActiveProject) -> list[dict]:
    """
    Purpose: Return the full role × module access matrix for the active project.
    Output:  List of dicts: role_name, module_name, client_allowed, server_expected.
    Side effects: None.
    """
    return idb.get_access_map_rows(project.db_path)


@router.put("")
def set_access(body: _SetAccessBody, project: ActiveProject) -> dict:
    """
    Purpose: Set client_allowed or server_expected for a role-module pair.
    Input:
        body.role   — name of an existing role.
        body.module — name of an existing module.
        body.layer  — "client" or "server".
        body.state  — "allow", "deny", or "unknown".
    Output:  Confirmation dict echoing the applied values.
    Side effects: Upserts one row in access_map.
    Raises:  404 if role or module does not exist.
             422 if state is invalid (caught by Literal type).
    """
    try:
        if body.layer == "client":
            acc.set_client_access(project.db_path, body.role, body.module, body.state)
        else:
            acc.set_server_access(project.db_path, body.role, body.module, body.state)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {"role": body.role, "module": body.module, "layer": body.layer, "state": body.state}


@router.delete("/{role}/{module}")
def delete_access(role: str, module: str, project: ActiveProject) -> dict:
    """
    Purpose: Remove the entire access-map row for a role-module pair.
    Input:   role, module — path parameters identifying the pair.
    Output:  Confirmation dict.
    Side effects: Deletes one row from access_map.
    Raises:  404 if role or module does not exist.
    """
    try:
        acc.delete_access(project.db_path, role, module)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {"deleted": True, "role": role, "module": module}
