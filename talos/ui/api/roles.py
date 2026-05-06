"""
Module: talos.ui.api.roles

Purpose:
    REST routes for role management within the active project.
    Roles are identity types used to tag captured flows and model BAC boundaries.

Dependencies: fastapi, pydantic, talos.projects.access, talos.ui.api._deps
Data flow:
    HTTP request → route → talos.projects.access → project SQLite DB → JSON response
Side effects:
    POST /roles           — inserts row into roles table.
    POST /{name}/activate — updates is_active on all role rows.
    DELETE /active        — resets active role to "global".

Routes:
    GET    /api/roles              → list all roles
    POST   /api/roles              → create role
    POST   /api/roles/{name}/activate → activate role for flow tagging
    DELETE /api/roles/active       → reset active role to global
"""

import sqlite3

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from talos.projects import access as acc
from talos.ui.api._deps import ActiveProject

router = APIRouter(prefix="/roles", tags=["roles"])


class _CreateBody(BaseModel):
    name: str


@router.get("")
def list_roles(project: ActiveProject) -> list[dict]:
    """
    Purpose: Return all roles for the active project ordered by name.
    Output:  List of dicts: id, name, is_active.
    Side effects: None.
    """
    return acc.list_roles(project.db_path)


@router.post("", status_code=201)
def create_role(body: _CreateBody, project: ActiveProject) -> dict:
    """
    Purpose: Create a new role in the active project.
    Input:   body.name — unique role label.
    Output:  Dict: id, name, is_active=0.
    Side effects: Inserts one row into roles.
    Raises:  409 if a role with this name already exists.
    """
    try:
        role_id = acc.create_role(project.db_path, body.name)
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail=f"Role '{body.name}' already exists.")
    return {"id": role_id, "name": body.name, "is_active": 0}


@router.delete("/active")
def reset_active_role(project: ActiveProject) -> dict:
    """
    Purpose: Reset the active role to "global", clearing any user-selected role.
    Output:  Dict: name="global", is_active=1.
    Side effects: Updates is_active on all role rows.
    """
    acc.set_active_role(project.db_path, "global")
    return {"name": "global", "is_active": 1}


@router.post("/{name}/activate")
def activate_role(name: str, project: ActiveProject) -> dict:
    """
    Purpose: Set the named role as active for future flow tagging.
    Input:   name — exact role name.
    Output:  Dict: name, is_active=1.
    Side effects: Updates is_active on all role rows.
    Raises:  404 if no role with this name exists.
    """
    try:
        acc.set_active_role(project.db_path, name)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {"name": name, "is_active": 1}
