"""
Module: talos.ui.api.flows

Purpose:
    REST routes for reading captured flows from the active project.
    Read-only — no mutations to flow data.

Dependencies: fastapi, talos.ui.db, talos.ui.api._deps
Data flow:
    HTTP GET → route → talos.ui.db query → JSON response
Side effects: None (read-only SQLite access).

Routes:
    GET /api/flows              → paginated flow list
    GET /api/flows/{flow_id}    → single flow detail (bytes fields as UTF-8 strings)
"""

import base64

from fastapi import APIRouter, HTTPException

from talos.ui import db as idb
from talos.ui.api._deps import ActiveProject

router = APIRouter(prefix="/flows", tags=["flows"])


def _bytes_safe(value: object) -> object:
    """
    Purpose:
        Convert a bytes value to a JSON-safe string.
        Used when returning raw DB columns that may be BLOBs.
    Input:   value — any Python object from a DB row.
    Output:  UTF-8 string if bytes; base64 string if non-UTF-8 bytes; original otherwise.
    Side effects: None.
    """
    if not isinstance(value, bytes):
        return value
    try:
        return value.decode("utf-8")
    except UnicodeDecodeError:
        return base64.b64encode(value).decode("ascii")


def _sanitize_row(row: dict) -> dict:
    """
    Purpose:
        Walk a DB row dict and convert any bytes fields to JSON-safe strings.
    Input:   row — dict from a SQLite query.
    Output:  New dict with bytes replaced by strings.
    Side effects: None.
    """
    return {k: _bytes_safe(v) for k, v in row.items()}


@router.get("")
def list_flows(
    project: ActiveProject,
    page: int = 1,
    limit: int = 50,
    source: str | None = None,
    method: str | None = None,
    host: str | None = None,
    status: str | None = None,
    role: str | None = None,
    module: str | None = None,
) -> dict:
    """
    Purpose: Return a paginated, optionally filtered slice of flows for the active project.
    Input:   page (1-based), limit (capped at 200), optional filter params.
    Output:  Dict with keys: items (list), page, limit, total, total_pages.
    Side effects: None.
    """
    limit = min(max(limit, 1), 200)
    page = max(page, 1)
    offset = (page - 1) * limit
    status_int: int | None = int(status) if status else None

    total = idb.get_flow_count(
        project.db_path,
        source=source, method=method, host=host,
        status_code=status_int, role=role, module=module,
    )
    flows = idb.list_flows(
        project.db_path, offset=offset, limit=limit,
        source=source, method=method, host=host,
        status_code=status_int, role=role, module=module,
    )
    total_pages = max(1, (total + limit - 1) // limit)

    return {
        "items": flows,
        "page": page,
        "limit": limit,
        "total": total,
        "total_pages": total_pages,
    }


@router.get("/{flow_id}")
def get_flow(flow_id: str, project: ActiveProject) -> dict:
    """
    Purpose: Return full detail for a single flow including request/response bodies.
    Input:   flow_id — UUID string.
    Output:  Full flow dict with bytes fields decoded to strings.
    Side effects: None.
    Raises:  404 if not found.
    """
    flow = idb.get_flow_detail(project.db_path, flow_id)
    if flow is None:
        raise HTTPException(status_code=404, detail="Flow not found")
    return _sanitize_row(flow)
