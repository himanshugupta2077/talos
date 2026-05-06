"""
Module: talos.ui.api.projects

Purpose:
    REST routes for project lifecycle management.
    Wraps ProjectManager operations — no direct registry access.

Dependencies: fastapi, pydantic, talos.projects.manager, talos.ui.api._deps
Data flow:
    HTTP request → route → ProjectManager → registry.json → JSON response
Side effects:
    POST /projects       — creates project directory + DB on disk, writes registry.
    POST /{id}/open      — writes registry (marks active).
    POST /{id}/close     — writes registry (deactivates).

Routes:
    GET  /api/projects           → list all projects
    POST /api/projects           → create project
    POST /api/projects/{id}/open → open (activate) project
    POST /api/projects/{id}/close→ close (deactivate) project
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from talos.projects.manager import (
    ProjectAlreadyExists,
    ProjectManager,
    ProjectNotFound,
)
from talos.projects.model import ScopeConstraints
from talos.ui.api._deps import ProjectsRoot
from talos.ui import db as idb

router = APIRouter(prefix="/projects", tags=["projects"])


class _CreateBody(BaseModel):
    name: str
    description: str = ""
    scope: list[str] = []


@router.get("")
def list_projects(root: ProjectsRoot) -> list[dict]:
    """
    Purpose: Return all registered projects from the registry.
    Output:  List of project dicts, active project first.
    Side effects: None (read-only).
    """
    registry = idb.load_registry(root)
    projects = list(registry.values())
    projects.sort(key=lambda p: (0 if p.get("status") == "active" else 1, p.get("id", "")))
    return projects


@router.post("", status_code=201)
def create_project(body: _CreateBody, root: ProjectsRoot) -> dict:
    """
    Purpose: Create a new project, initialise its directory and SQLite DB.
    Input:   body — name (required), description, scope list.
    Output:  The created project dict.
    Side effects: Creates directories + DB on disk; writes registry.
    Raises:  409 if the project slug already exists.
             422 if the name produces an empty slug.
    """
    try:
        project = ProjectManager(root).create(
            name=body.name,
            description=body.description,
            scope=body.scope,
        )
    except ProjectAlreadyExists as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return project.to_dict()


@router.post("/{project_id}/open")
def open_project(project_id: str, root: ProjectsRoot) -> dict:
    """
    Purpose: Activate a project as the capture target.
    Input:   project_id — slug of the project to open.
    Output:  The now-active project dict.
    Side effects: Writes registry; deactivates any previously active project.
    Raises:  404 if project not found.
    """
    try:
        project = ProjectManager(root).open(project_id)
    except ProjectNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return project.to_dict()


@router.post("/{project_id}/close")
def close_project(project_id: str, root: ProjectsRoot) -> dict:
    """
    Purpose: Deactivate the currently active project.
    Input:   project_id — slug used only to validate the caller targets the active project.
    Output:  The deactivated project dict, or {"closed": None} if nothing was active.
    Side effects: Writes registry.
    Raises:  409 if the specified project is not the active one.
    """
    manager = ProjectManager(root)
    active = manager.active()
    if active is None:
        return {"closed": None}
    if active.id != project_id:
        raise HTTPException(
            status_code=409,
            detail=f"Project '{project_id}' is not the active project.",
        )
    closed = manager.close()
    return closed.to_dict() if closed else {"closed": None}


class _SetScopeBody(BaseModel):
    scope: list[str]


@router.put("/{project_id}/scope")
def set_scope(project_id: str, body: _SetScopeBody, root: ProjectsRoot) -> dict:
    """
    Purpose: Replace the scope list for a project.
    Input:   body.scope — new list of host/URL patterns.
    Output:  Updated project dict.
    Side effects: Writes registry.
    Raises:  404 if project not found.
    """
    try:
        project = ProjectManager(root).set_scope(project_id, body.scope)
    except ProjectNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return project.to_dict()


class _SetConstraintsBody(BaseModel):
    store_bodies: bool
    max_body_size: int
    capture_in_scope_only: bool


@router.put("/{project_id}/constraints")
def set_constraints(project_id: str, body: _SetConstraintsBody, root: ProjectsRoot) -> dict:
    """
    Purpose: Replace the capture constraints for a project.
    Input:   body — store_bodies, max_body_size, capture_in_scope_only.
    Output:  Updated project dict.
    Side effects: Writes registry.
    Raises:  404 if project not found.
             422 if max_body_size is invalid (caught by Pydantic).
    """
    try:
        constraints = ScopeConstraints(
            store_bodies=body.store_bodies,
            max_body_size=body.max_body_size,
            capture_in_scope_only=body.capture_in_scope_only,
        )
        project = ProjectManager(root).set_constraints(project_id, constraints)
    except ProjectNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return project.to_dict()
