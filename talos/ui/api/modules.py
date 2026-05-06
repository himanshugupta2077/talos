"""
Module: talos.ui.api.modules

Purpose:
    REST routes for module management within the active project.
    Modules are logical feature areas used to tag captured flows and model BAC boundaries.

Dependencies: fastapi, pydantic, talos.projects.access, talos.ui.api._deps
Data flow:
    HTTP request → route → talos.projects.access → project SQLite DB → JSON response
Side effects:
    POST /modules              — inserts row into modules table.
    POST /{name}/activate      — updates is_active on all module rows.
    DELETE /active             — resets active module to "global".

Routes:
    GET    /api/modules                  → list all modules
    POST   /api/modules                  → create module
    POST   /api/modules/{name}/activate  → activate module for flow tagging
    DELETE /api/modules/active           → reset active module to global
"""

import sqlite3

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from talos.projects import access as acc
from talos.ui.api._deps import ActiveProject

router = APIRouter(prefix="/modules", tags=["modules"])


class _CreateBody(BaseModel):
    name: str
    description: str = ""


@router.get("")
def list_modules(project: ActiveProject) -> list[dict]:
    """
    Purpose: Return all modules for the active project ordered by name.
    Output:  List of dicts: id, name, description, is_active.
    Side effects: None.
    """
    return acc.list_modules(project.db_path)


@router.post("", status_code=201)
def create_module(body: _CreateBody, project: ActiveProject) -> dict:
    """
    Purpose: Create a new module in the active project.
    Input:   body.name — unique module label; body.description — optional context.
    Output:  Dict: id, name, description, is_active=0.
    Side effects: Inserts one row into modules.
    Raises:  409 if a module with this name already exists.
    """
    try:
        module_id = acc.create_module(project.db_path, body.name, body.description)
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail=f"Module '{body.name}' already exists.")
    return {"id": module_id, "name": body.name, "description": body.description, "is_active": 0}


@router.delete("/active")
def reset_active_module(project: ActiveProject) -> dict:
    """
    Purpose: Reset the active module to "global", clearing any user-selected module.
    Output:  Dict: name="global", is_active=1.
    Side effects: Updates is_active on all module rows.
    """
    acc.set_active_module(project.db_path, "global")
    return {"name": "global", "is_active": 1}


@router.post("/{name}/activate")
def activate_module(name: str, project: ActiveProject) -> dict:
    """
    Purpose: Set the named module as active for future flow tagging.
    Input:   name — exact module name.
    Output:  Dict: name, is_active=1.
    Side effects: Updates is_active on all module rows.
    Raises:  404 if no module with this name exists.
    """
    try:
        acc.set_active_module(project.db_path, name)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {"name": name, "is_active": 1}
