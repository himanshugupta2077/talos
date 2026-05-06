"""
Module: talos.ui.api._deps

Purpose:
    Shared FastAPI dependency providers for all /api/* routers.
    Centralises access to projects_root and the active project so
    individual route modules don't repeat the same resolution logic.

Dependencies: fastapi, talos.projects.manager, talos.projects.model
Data flow:
    FastAPI Depends() → _projects_root → ProjectManager.active() → Project
Side effects: None (read-only registry access inside each dependency call).
"""

from pathlib import Path
from typing import Annotated

from fastapi import Depends, HTTPException, Request

from talos.projects.manager import ProjectManager
from talos.projects.model import Project


def _projects_root(request: Request) -> Path:
    """
    Purpose: Extract the projects_root path injected into app.state at startup.
    Input:   request — FastAPI Request carrying app.state.
    Output:  Path to the projects directory.
    Side effects: None.
    """
    return request.app.state.projects_root


ProjectsRoot = Annotated[Path, Depends(_projects_root)]


def _active_project(root: ProjectsRoot) -> Project:
    """
    Purpose:
        Resolve the currently active project or raise 422.
        Routes that require an active project declare this as a dependency —
        they never need to duplicate the resolution logic.
    Input:   root — projects_root resolved by _projects_root.
    Output:  The currently active Project instance.
    Side effects: Reads registry.json once per request.
    Raises:  HTTPException(422) when no project is active.
    """
    project = ProjectManager(root).active()
    if project is None:
        raise HTTPException(
            status_code=422,
            detail="No active project. Open a project first.",
        )
    return project


ActiveProject = Annotated[Project, Depends(_active_project)]
