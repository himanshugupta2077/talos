"""
Module: talos.ui.api.mutations

Purpose:
    REST routes for managing per-project request mutations.
    Mutations are static header injections applied by the proxy to every
    outgoing request.  Changes take effect on the next proxy restart.

Dependencies: fastapi, pydantic, sqlite3, talos.projects.mutation, talos.ui.api._deps
Data flow:
    HTTP request → route → talos.projects.mutation (or direct SQL for toggle) → DB → JSON
Side effects:
    POST   /api/mutations        — inserts one row into request_mutations.
    PATCH  /api/mutations/{id}   — flips enabled flag on one row.
    DELETE /api/mutations/{id}   — deletes one row from request_mutations.

Routes:
    GET    /api/mutations        → list all mutations (id, type, key, value, enabled)
    POST   /api/mutations        → add mutation
    PATCH  /api/mutations/{id}   → toggle enabled/disabled
    DELETE /api/mutations/{id}   → delete mutation
"""

import sqlite3

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Literal

from talos.projects import mutation as mut
from talos.ui.api._deps import ActiveProject

router = APIRouter(prefix="/mutations", tags=["mutations"])


class _AddBody(BaseModel):
    type: Literal["header"]
    key: str
    value: str


@router.get("")
def list_mutations(project: ActiveProject) -> list[dict]:
    """
    Purpose: Return all request mutations for the active project.
    Output:  List of dicts: id, type, key, value, enabled.
    Side effects: None.
    """
    return mut.list_mutations(project.db_path)


@router.post("", status_code=201)
def add_mutation(body: _AddBody, project: ActiveProject) -> dict:
    """
    Purpose: Add a new header mutation to the active project.
    Input:   body.type="header", body.key — header name, body.value — header value.
    Output:  Dict: id, type, key, value, enabled=True.
    Side effects: Inserts one row into request_mutations.
    Note:    Proxy must be restarted for the new mutation to take effect.
    """
    mutation_id = mut.add_mutation(project.db_path, body.type, body.key, body.value)
    return {"id": mutation_id, "type": body.type, "key": body.key, "value": body.value, "enabled": True}


@router.patch("/{mutation_id}")
def toggle_mutation(mutation_id: str, project: ActiveProject) -> dict:
    """
    Purpose: Toggle the enabled state of a mutation (enabled ↔ disabled).
    Input:   mutation_id — UUID string.
    Output:  Dict: id, enabled (new state).
    Side effects: Updates enabled column on one row in request_mutations.
    Raises:  404 if no mutation with this ID exists.
    Note:    Proxy must be restarted for the change to take effect.
    """
    if not project.db_path.exists():
        raise HTTPException(status_code=404, detail="Mutation not found")
    with sqlite3.connect(str(project.db_path)) as conn:
        cursor = conn.execute(
            "UPDATE request_mutations SET enabled = 1 - enabled WHERE id = ?",
            (mutation_id,),
        )
        conn.commit()
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Mutation not found")
        row = conn.execute(
            "SELECT enabled FROM request_mutations WHERE id = ?", (mutation_id,)
        ).fetchone()
    return {"id": mutation_id, "enabled": bool(row[0])}


@router.delete("/{mutation_id}")
def delete_mutation(mutation_id: str, project: ActiveProject) -> dict:
    """
    Purpose: Remove a mutation from the active project.
    Input:   mutation_id — UUID string.
    Output:  Dict: deleted=True.
    Side effects: Deletes one row from request_mutations.
    Raises:  404 if no mutation with this ID exists.
    Note:    Proxy must be restarted for the removal to take effect.
    """
    deleted = mut.delete_mutation(project.db_path, mutation_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Mutation not found")
    return {"deleted": True, "id": mutation_id}
