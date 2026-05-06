"""
Module: talos.ui.api.outscope

Purpose:
    REST routes for managing the per-project out-of-scope domain block-list.
    Domains on this list are never captured, processed, or replayed regardless
    of whether they match the scope allow-list.

Dependencies: fastapi, pydantic, talos.projects.outscope, talos.ui.api._deps
Data flow:
    HTTP request → route → talos.projects.outscope → project SQLite DB → JSON response
Side effects:
    POST /outscope         — inserts one row into out_of_scope_domains.
    DELETE /outscope/{dom} — deletes one row from out_of_scope_domains.

Routes:
    GET    /api/outscope          → list all out-of-scope domains
    POST   /api/outscope          → add a domain to the block-list
    DELETE /api/outscope/{domain} → remove a domain from the block-list
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from talos.projects.outscope import add_domain, list_domains, remove_domain
from talos.ui.api._deps import ActiveProject

router = APIRouter(prefix="/outscope", tags=["outscope"])


class _AddBody(BaseModel):
    domain: str


@router.get("")
def list_outscope(project: ActiveProject) -> list[dict]:
    """
    Purpose: Return all out-of-scope domain entries for the active project.
    Output:  List of dicts: id, domain, created_at.
    Side effects: None.
    """
    return list_domains(project.db_path)


@router.post("", status_code=201)
def add_outscope(body: _AddBody, project: ActiveProject) -> dict:
    """
    Purpose: Add a domain to the out-of-scope block-list.
    Input:   body.domain — domain string (e.g. 'cdn.example.com').
    Output:  Dict: domain (lowercased), inserted (True if new, False if duplicate).
    Side effects: Inserts one row into out_of_scope_domains when new.
    """
    domain_lower = body.domain.strip().lower()
    if not domain_lower:
        raise HTTPException(status_code=422, detail="domain must not be empty.")
    inserted = add_domain(project.db_path, project.id, domain_lower)
    return {"domain": domain_lower, "inserted": inserted}


@router.delete("/{domain}")
def remove_outscope(domain: str, project: ActiveProject) -> dict:
    """
    Purpose: Remove a domain from the out-of-scope block-list.
    Input:   domain — path parameter; exact domain string to remove.
    Output:  Confirmation dict.
    Side effects: Deletes one row from out_of_scope_domains.
    Raises:  404 if the domain is not in the list.
    """
    removed = remove_domain(project.db_path, project.id, domain)
    if not removed:
        raise HTTPException(
            status_code=404,
            detail=f"Domain '{domain}' is not in the out-of-scope list.",
        )
    return {"deleted": True, "domain": domain}
