"""
Projects router — registry list/detail, lifecycle, scope, constraints, outscope.

All mutations go through the Talos CLI (`cli.run` / `cli.run_scoped` /
`cli.run_scoped_with_temp_file`). Scope semantics live only in Talos core;
this router never mutates registry or SQLite for scope directly.

Open-directory is a Control Panel OS UI action (not a Talos state mutation):
paths are resolved server-side from project identity + predefined targets only.
"""
from enum import Enum
from pathlib import Path

from fastapi import APIRouter, File, HTTPException, Query, UploadFile
from pydantic import BaseModel, Field

from .. import cli, config, db, dashboard_reads
from ..platform_open import OpenDirectoryError, open_directory

router = APIRouter(prefix="/api/projects", tags=["projects"])

# Scope import lists are configuration text, not arbitrary artifacts.
_MAX_SCOPE_UPLOAD_BYTES = 256 * 1024


def _default_constraints() -> dict:
    return {
        "capture_in_scope_only": True,
        "store_bodies": True,
        "max_body_size": 1 * 1024 * 1024,
    }


def _augment(project_id: str, record: dict) -> dict:
    data_dir = config.project_data_dir(project_id, record)
    db_path = config.project_db_path(project_id, record)
    constraints = record.get("constraints") or {}
    if not isinstance(constraints, dict):
        constraints = {}
    merged = {**_default_constraints(), **constraints}
    status = record.get("status") or "inactive"
    auth_mode = "artifacts"
    try:
        from talos.projects.auth_mode import resolve_auth_mode

        auth_mode = resolve_auth_mode(db_path)
    except Exception:
        auth_mode = "artifacts"
    return {
        "id": project_id,
        "name": record.get("name", project_id),
        "description": record.get("description", ""),
        "scope": record.get("scope", []) or [],
        "created_at": record.get("created_at"),
        "status": status,
        "auth_mode": auth_mode,
        "constraints": {
            "capture_in_scope_only": bool(merged.get("capture_in_scope_only", True)),
            "store_bodies": bool(merged.get("store_bodies", True)),
            "max_body_size": int(merged.get("max_body_size") or 1 * 1024 * 1024),
        },
        "data_dir": str(data_dir),
        "db_path": str(db_path),
        "db_exists": db.db_exists(db_path),
        "active": status == "active"
        or bool(record.get("active") or record.get("is_active")),
    }


# ------------------------------------------------------------------ #
# List / active / status (static paths first)                        #
# ------------------------------------------------------------------ #


@router.get("")
def list_projects():
    registry = db.load_registry()
    active_id = db.get_active_project_id()
    out = []
    for project_id, record in registry.items():
        if project_id.startswith("_") or not isinstance(record, dict):
            continue
        item = _augment(project_id, record)
        item["active"] = item["active"] or (project_id == active_id)
        if item["active"]:
            item["status"] = "active"
        out.append(item)
    out.sort(key=lambda p: p.get("created_at") or "", reverse=True)
    return {"projects": out, "active_project_id": active_id}


@router.get("/active")
def active_project():
    active_id = db.get_active_project_id()
    if not active_id:
        return {"active_project_id": None, "project": None}
    record = db.get_project_record(active_id) or {}
    return {"active_project_id": active_id, "project": _augment(active_id, record)}


@router.get("/status")
def project_status():
    result = cli.run(["project", "status"])
    return result.to_dict()


@router.post("/close")
def close_project():
    result = cli.run(["project", "close"])
    return result.to_dict()


# ------------------------------------------------------------------ #
# Create                                                              #
# ------------------------------------------------------------------ #


class CreateProjectBody(BaseModel):
    name: str
    description: str = ""
    scope: list[str] = []
    auth_mode: str = "artifacts"


@router.post("")
def create_project(body: CreateProjectBody):
    args = ["project", "create", body.name]
    if body.description:
        args += ["--description", body.description]
    mode = (body.auth_mode or "artifacts").strip() or "artifacts"
    if mode not in ("artifacts", "platform_ntlm"):
        raise HTTPException(400, "auth_mode must be artifacts or platform_ntlm")
    args += ["--auth-mode", mode]
    for pattern in body.scope:
        args += ["--scope", pattern]
    result = cli.run(args)
    return result.to_dict()


class AuthModeBody(BaseModel):
    mode: str


@router.get("/{project_id}/auth-mode")
def get_auth_mode(project_id: str):
    record = db.get_project_record(project_id)
    if record is None:
        raise HTTPException(404, "unknown project")
    db_path = config.project_db_path(project_id, record)
    try:
        from talos.projects.auth_mode import auth_mode_public_dict

        return auth_mode_public_dict(db_path)
    except Exception as exc:
        raise HTTPException(500, f"Failed to read auth mode: {exc}") from exc


@router.post("/{project_id}/auth-mode")
def set_auth_mode(project_id: str, body: AuthModeBody):
    mode = (body.mode or "").strip()
    if mode not in ("artifacts", "platform_ntlm"):
        raise HTTPException(400, "mode must be artifacts or platform_ntlm")
    results = cli.run_scoped(project_id, ["project", "auth-mode", "set", mode])
    return {"steps": [r.to_dict() for r in results]}


# ------------------------------------------------------------------ #
# Detail + summary                                                    #
# ------------------------------------------------------------------ #


@router.get("/{project_id}")
def get_project(project_id: str):
    record = db.get_project_record(project_id)
    if record is None:
        raise HTTPException(404, "unknown project")
    active_id = db.get_active_project_id()
    item = _augment(project_id, record)
    item["active"] = item["active"] or (project_id == active_id)
    if item["active"]:
        item["status"] = "active"
    return {"project": item, "active_project_id": active_id}


@router.get("/{project_id}/summary")
def project_summary(project_id: str):
    record = db.get_project_record(project_id)
    if record is None:
        raise HTTPException(404, "unknown project")
    db_path = config.project_db_path(project_id, record)
    if not db.db_exists(db_path):
        return {
            "flows": 0,
            "endpoints": 0,
            "findings_primary": 0,
            "findings_total": 0,
            "findings_triaging": 0,
            "findings_confirmed": 0,
            "scheduler_pending": 0,
            "roles": 0,
            "modules": 0,
        }
    return {
        "flows": db.scalar(db_path, "SELECT COUNT(*) FROM flows"),
        "endpoints": db.scalar(db_path, "SELECT COUNT(*) FROM endpoints"),
        "findings_primary": db.scalar(
            db_path,
            "SELECT COUNT(*) FROM findings "
            "WHERE COALESCE(relation_type, 'PRIMARY') = 'PRIMARY'",
        ),
        "findings_total": db.scalar(db_path, "SELECT COUNT(*) FROM findings"),
        "findings_triaging": db.scalar(
            db_path, "SELECT COUNT(*) FROM findings WHERE status='TRIAGING'"
        ),
        "findings_confirmed": db.scalar(
            db_path, "SELECT COUNT(*) FROM findings WHERE status='CONFIRMED'"
        ),
        "scheduler_pending": db.scalar(
            db_path, "SELECT COUNT(*) FROM scheduler_jobs WHERE status='pending'"
        ),
        "roles": db.scalar(db_path, "SELECT COUNT(*) FROM roles"),
        "modules": db.scalar(db_path, "SELECT COUNT(*) FROM modules"),
    }


@router.get("/{project_id}/dashboard")
def project_dashboard(project_id: str):
    """
    Mission-control aggregate for the Dashboard page: project readiness,
    findings/scheduler/proxy/endpoints/flows/session health/HTTP rules/config.
    """
    payload = dashboard_reads.project_dashboard(project_id)
    if payload is None:
        raise HTTPException(404, "unknown project")
    return payload


# ------------------------------------------------------------------ #
# Open directory (OS UI integration — not a Talos mutation)           #
# ------------------------------------------------------------------ #


class OpenDirectoryTarget(str, Enum):
    """
    Purpose:
        Strict allow-list of directories the browser may request to open.
        The browser never supplies a filesystem path — only a target enum.
    Values:
        data_dir — project data directory (project_data_dir)
        database_dir — parent directory of talos.db (may exist before the file)
    """

    data_dir = "data_dir"
    database_dir = "database_dir"


class OpenDirectoryBody(BaseModel):
    """
    Purpose:
        Request body for POST …/open-directory.
    Fields:
        target — predefined OpenDirectoryTarget (enum-validated).
    """

    target: OpenDirectoryTarget


def _resolve_open_directory_target(
    project_id: str, record: dict, target: OpenDirectoryTarget
) -> Path:
    """
    Purpose:
        Map a predefined target to a directory path via existing path helpers.
    Input:
        project_id — registry project id
        record — registry record (may include data_dir override)
        target — data_dir or database_dir
    Output:
        Path of the directory to open (not necessarily existing yet).
    Side effects:
        None.
    """
    if target is OpenDirectoryTarget.data_dir:
        return config.project_data_dir(project_id, record)
    # database_dir: open the folder that contains (or will contain) talos.db.
    # Do not require the .db file to exist — parent project dir is enough.
    return config.project_db_path(project_id, record).parent


@router.post("/{project_id}/open-directory")
def open_project_directory(project_id: str, body: OpenDirectoryBody):
    """
    Purpose:
        Open a predefined project directory in the OS file explorer.
    Input:
        project_id — path; must exist in the registry
        body.target — "data_dir" | "database_dir" only
    Output:
        Structured result: ok, project_id, target, path, message.
    Side effects:
        Launches the platform directory opener; no registry/SQLite writes.
    Errors:
        404 project not found; 400 missing directory / unsupported OS /
        opener failure (detail is actionable text).
    """
    record = db.get_project_record(project_id)
    if record is None:
        raise HTTPException(404, "project not found")

    directory = _resolve_open_directory_target(project_id, record, body.target)
    try:
        open_directory(directory)
    except OpenDirectoryError as exc:
        raise HTTPException(400, exc.message) from exc

    return {
        "ok": True,
        "project_id": project_id,
        "target": body.target.value,
        "path": str(directory),
        "message": "Directory open requested",
    }


# ------------------------------------------------------------------ #
# Lifecycle mutations (CLI is authority)                              #
# ------------------------------------------------------------------ #


@router.post("/{project_id}/open")
def open_project(project_id: str):
    result = cli.run(["project", "open", project_id])
    return result.to_dict()


@router.delete("/{project_id}")
def delete_project(
    project_id: str,
    force: bool = Query(False),
    purge: bool = Query(False),
):
    """
    Remove project from registry. With purge=true, also rmtree data_dir.
    Non-interactive CLI requires --force (always pass force from the UI).
    """
    args = ["project", "delete", project_id]
    if purge:
        args.append("--purge")
    if force:
        args.append("--force")
    result = cli.run(args)
    return result.to_dict()


class RenameBody(BaseModel):
    new_name: str = Field(..., min_length=1)


@router.post("/{project_id}/rename")
def rename_project(project_id: str, body: RenameBody):
    result = cli.run(["project", "rename", project_id, body.new_name.strip()])
    return result.to_dict()


class DescriptionBody(BaseModel):
    description: str = ""


@router.post("/{project_id}/description")
def set_description(project_id: str, body: DescriptionBody):
    text = body.description
    # CLI: omit TEXT to show; provide TEXT to set. Empty string clears via a space? 
    # Looking at CLI: " ".join(args.text) — empty list is display-only.
    # To clear, we need to pass something that becomes empty... actually empty
    # join of empty would not run set. Pass a single empty? nargs='*' with [""]
    # would join to "". That still is truthy for `if args.text` (non-empty list).
    # `" ".join([""])` → "" which set_description can accept.
    args = ["project", "description", project_id]
    # Always pass one token so we enter the set path even for clear.
    args.append(text if text else "")
    result = cli.run(args)
    return result.to_dict()


# ------------------------------------------------------------------ #
# Scope / constraints                                                 #
# ------------------------------------------------------------------ #


class ScopeBody(BaseModel):
    """Legacy replace-all body (still accepted for bulk replace)."""

    patterns: list[str]


class ScopePrefixBody(BaseModel):
    prefix: str = Field(..., min_length=1)


class ScopeBulkBody(BaseModel):
    """
    Multiline bulk paste — one prefix per line.
    Backend routes text through Talos core import (temp file + CLI).
    """

    text: str = ""
    replace: bool = False


@router.post("/{project_id}/scope")
def set_scope(project_id: str, body: ScopeBody):
    """
    Compatibility: replace entire scope list via legacy CLI form.
    Prefer add / import endpoints for incremental edits.
    """
    if not body.patterns:
        results = cli.run_scoped(
            project_id, ["project", "scope", "clear", "--force"]
        )
        return {"steps": [r.to_dict() for r in results]}
    result = cli.run(["project", "scope", project_id, *body.patterns])
    return result.to_dict()


@router.post("/{project_id}/scope/add")
def add_scope_prefix(project_id: str, body: ScopePrefixBody):
    results = cli.run_scoped(
        project_id, ["project", "scope", "add", body.prefix.strip()]
    )
    return {"steps": [r.to_dict() for r in results]}


@router.delete("/{project_id}/scope/entry")
def remove_scope_prefix(
    project_id: str,
    prefix: str = Query(..., min_length=1),
):
    results = cli.run_scoped(
        project_id, ["project", "scope", "remove", prefix]
    )
    return {"steps": [r.to_dict() for r in results]}


@router.post("/{project_id}/scope/bulk")
def bulk_scope(project_id: str, body: ScopeBulkBody):
    """
    Bulk paste: write text to a temp file and run
    `talos project scope import <temp>` (core validates atomically).
    """
    args = ["project", "scope", "import"]
    if body.replace:
        args.append("--replace")
    results = cli.run_scoped_with_temp_file(
        project_id,
        args,
        body.text or "",
        suffix=".txt",
    )
    return {"steps": [r.to_dict() for r in results]}


@router.post("/{project_id}/scope/import")
async def import_scope_file(
    project_id: str,
    file: UploadFile = File(...),
    replace: bool = Query(False),
):
    """
    File picker upload → temp file → `talos project scope import`.
    Operators cannot supply arbitrary backend filesystem paths.
    """
    content = await _read_scope_upload(file)
    args = ["project", "scope", "import"]
    if replace:
        args.append("--replace")
    results = cli.run_scoped_with_temp_file(
        project_id,
        args,
        content,
        suffix=".txt",
    )
    return {"steps": [r.to_dict() for r in results]}


class ConstraintsBody(BaseModel):
    store_bodies: bool | None = None
    max_body_size: int | None = None


@router.post("/{project_id}/constraints")
def set_constraints(project_id: str, body: ConstraintsBody):
    args = ["project", "constraints", project_id]
    if body.store_bodies is not None:
        args += ["--store-bodies", "true" if body.store_bodies else "false"]
    if body.max_body_size is not None:
        args += ["--max-body-size", str(body.max_body_size)]
    result = cli.run(args)
    return result.to_dict()


# ------------------------------------------------------------------ #
# Out-of-scope prefixes (same Basic Scope model as in-scope)          #
# ------------------------------------------------------------------ #


@router.get("/{project_id}/outscope")
def list_outscope(project_id: str):
    record = db.get_project_record(project_id)
    if record is None:
        raise HTTPException(404, "unknown project")
    db_path = config.project_db_path(project_id, record)
    if not db.db_exists(db_path):
        return {"prefixes": [], "domains": []}
    rows = db.query_all(
        db_path,
        "SELECT id, domain, created_at FROM out_of_scope_domains "
        "WHERE project_id=? ORDER BY domain",
        (project_id,),
    )
    prefixes = [
        {
            "id": r.get("id"),
            "prefix": r.get("domain"),
            "domain": r.get("domain"),
            "created_at": r.get("created_at"),
        }
        for r in rows
    ]
    return {"prefixes": prefixes, "domains": prefixes}


class DomainBody(BaseModel):
    """Accept either prefix or domain field name from the UI."""

    prefix: str | None = None
    domain: str | None = None

    def resolved(self) -> str:
        value = (self.prefix or self.domain or "").strip()
        if not value:
            raise ValueError("prefix is required")
        return value


@router.post("/{project_id}/outscope")
def add_outscope(project_id: str, body: DomainBody):
    try:
        prefix = body.resolved()
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    results = cli.run_scoped(
        project_id, ["project", "outscope", "add", prefix]
    )
    return {"steps": [r.to_dict() for r in results]}


@router.delete("/{project_id}/outscope/{prefix:path}")
def remove_outscope(project_id: str, prefix: str):
    results = cli.run_scoped(
        project_id, ["project", "outscope", "remove", prefix]
    )
    return {"steps": [r.to_dict() for r in results]}


@router.post("/{project_id}/outscope/bulk")
def bulk_outscope(project_id: str, body: ScopeBulkBody):
    args = ["project", "outscope", "import"]
    if body.replace:
        args.append("--replace")
    results = cli.run_scoped_with_temp_file(
        project_id,
        args,
        body.text or "",
        suffix=".txt",
    )
    return {"steps": [r.to_dict() for r in results]}


@router.post("/{project_id}/outscope/import")
async def import_outscope_file(
    project_id: str,
    file: UploadFile = File(...),
    replace: bool = Query(False),
):
    content = await _read_scope_upload(file)
    args = ["project", "outscope", "import"]
    if replace:
        args.append("--replace")
    results = cli.run_scoped_with_temp_file(
        project_id,
        args,
        content,
        suffix=".txt",
    )
    return {"steps": [r.to_dict() for r in results]}


async def _read_scope_upload(file: UploadFile) -> str:
    """
    Purpose:
        Read an uploaded scope list with size guardrails.
        Path is never taken from the client — only file bytes.
    """
    data = await file.read(_MAX_SCOPE_UPLOAD_BYTES + 1)
    if len(data) > _MAX_SCOPE_UPLOAD_BYTES:
        raise HTTPException(
            413,
            f"Scope upload exceeds {_MAX_SCOPE_UPLOAD_BYTES} bytes "
            "(scope lists are small text configuration).",
        )
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise HTTPException(400, "Scope file must be UTF-8 text") from exc
