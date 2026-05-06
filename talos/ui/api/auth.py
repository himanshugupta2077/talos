"""
Module: talos.ui.api.auth

Purpose:
    REST routes for per-project auth config management.
    Auth config holds the cookie and header names that constitute
    authentication credentials (names only — no actual credential values).
    Used by the auth-bypass replay engine to strip auth from requests.

Dependencies: fastapi, pydantic, talos.projects.auth, talos.ui.api._deps
Data flow:
    HTTP request → route → talos.projects.auth → project SQLite (auth_config) → JSON response
Side effects:
    POST /auth   — inserts rows into auth_config (additive).
    DELETE /auth — removes all rows from auth_config.

Routes:
    GET    /api/auth  → show current auth config (cookies + headers)
    POST   /api/auth  → add cookie/header names (additive)
    DELETE /api/auth  → clear all auth config entries
"""

from fastapi import APIRouter
from pydantic import BaseModel

from talos.projects.auth import clear_auth_config, get_auth_config, set_auth_fields
from talos.ui.api._deps import ActiveProject

router = APIRouter(prefix="/auth", tags=["auth"])


class _SetBody(BaseModel):
    # Lists of names to add. Empty lists are accepted (no-op).
    cookies: list[str] = []
    headers: list[str] = []


@router.get("")
def show_auth(project: ActiveProject) -> dict:
    """
    Purpose: Return the current auth config for the active project.
    Output:  Dict with 'cookies' (list[str]) and 'headers' (list[str]).
    Side effects: None.
    """
    return get_auth_config(project.db_path)


@router.post("", status_code=200)
def set_auth(body: _SetBody, project: ActiveProject) -> dict:
    """
    Purpose: Merge cookie and header names into the auth config (additive).
    Input:   body.cookies — cookie names; body.headers — header names.
    Output:  Updated auth config dict.
    Side effects: Inserts rows into auth_config; duplicates silently ignored.
    """
    set_auth_fields(project.db_path, body.cookies, body.headers)
    return get_auth_config(project.db_path)


@router.delete("")
def clear_auth(project: ActiveProject) -> dict:
    """
    Purpose: Remove all auth config entries for the active project.
    Output:  Empty auth config dict: {cookies: [], headers: []}.
    Side effects: Deletes all rows from auth_config.
    """
    clear_auth_config(project.db_path)
    return {"cookies": [], "headers": []}
