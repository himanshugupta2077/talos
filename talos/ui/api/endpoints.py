"""
Module: talos.ui.api.endpoints

Purpose:
    REST routes for reading normalised endpoints from the active project.
    Read-only — endpoints are derived from captured flows; no manual creation.

Dependencies: fastapi, talos.ui.db, talos.ui.api._deps
Data flow:
    HTTP GET → route → talos.ui.db query → JSON response
Side effects: None (read-only SQLite access).

Routes:
    GET /api/endpoints                   → paginated endpoint list with hit counts
    GET /api/endpoints/{endpoint_id}     → endpoint detail with parameters + linked flows
"""

import json

from fastapi import APIRouter, HTTPException

from talos.ui import db as idb
from talos.ui.api._deps import ActiveProject

router = APIRouter(prefix="/endpoints", tags=["endpoints"])


@router.get("")
def list_endpoints(
    project: ActiveProject,
    page: int = 1,
    limit: int = 50,
) -> dict:
    """
    Purpose: Return a paginated slice of normalised endpoints for the active project.
    Input:   page (1-based), limit (capped at 200).
    Output:  Dict with keys: items (list), page, limit, total, total_pages.
             Each item: id, method, host, normalized_path, hit_count, roles, modules.
    Side effects: None.
    """
    limit = min(max(limit, 1), 200)
    page = max(page, 1)
    offset = (page - 1) * limit

    total = idb.get_endpoint_count(project.db_path)
    endpoints = idb.list_endpoints(project.db_path, offset=offset, limit=limit)
    total_pages = max(1, (total + limit - 1) // limit)

    return {
        "items": endpoints,
        "page": page,
        "limit": limit,
        "total": total,
        "total_pages": total_pages,
    }


@router.get("/{endpoint_id}")
def get_endpoint(endpoint_id: str, project: ActiveProject) -> dict:
    """
    Purpose: Return full detail for a single endpoint: parameters and recent flows.
    Input:   endpoint_id — UUID string.
    Output:  Dict with keys: endpoint, parameters, flows, roles.
             parameter.example_values is a parsed list (not raw JSON string).
    Side effects: None.
    Raises:  404 if not found.
    """
    endpoint = idb.get_endpoint_detail(project.db_path, endpoint_id)
    if endpoint is None:
        raise HTTPException(status_code=404, detail="Endpoint not found")

    parameters = idb.get_endpoint_parameters(project.db_path, endpoint_id)
    # Parse example_values JSON strings into lists for clean API output.
    for param in parameters:
        raw = param.get("example_values", "[]")
        try:
            param["example_values"] = json.loads(raw) if isinstance(raw, str) else raw
        except (json.JSONDecodeError, TypeError):
            param["example_values"] = []

    linked_flows = idb.get_endpoint_flows(project.db_path, endpoint_id)
    roles = [r["role_name"] for r in idb.list_endpoint_roles(project.db_path, endpoint_id)]

    return {
        "endpoint": endpoint,
        "parameters": parameters,
        "flows": linked_flows,
        "roles": roles,
    }
