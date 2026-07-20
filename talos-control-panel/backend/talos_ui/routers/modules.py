"""
Modules API — list from project DB; all mutations via Talos CLI.

CLI surface (project-scoped):
  module create | set | unset | rename | delete
"""

from fastapi import APIRouter
from pydantic import BaseModel

from .. import cli, config, db

router = APIRouter(prefix="/api/modules", tags=["modules"])


@router.get("")
def list_modules(project_id: str):
    """
    Purpose: Return all modules for the project (including built-in global).
    Input: project_id query.
    Output: { modules: [{ id, name, description, is_active }, ...] }.
    Side effects: none (read-only DB).
    """
    record = db.get_project_record(project_id)
    db_path = config.project_db_path(project_id, record)
    rows = db.query_all(
        db_path, "SELECT id, name, description, is_active FROM modules ORDER BY name"
    )
    return {"modules": rows}


class CreateModuleBody(BaseModel):
    name: str
    description: str = ""


@router.post("")
def create_module(project_id: str, body: CreateModuleBody):
    """
    Purpose: Create a module (talos module create).
    Input: project_id, body.name, optional description.
    Output: { steps } from CLI.
    Side effects: CLI mutates project DB.
    """
    args = ["module", "create", body.name]
    if body.description:
        args += ["--description", body.description]
    results = cli.run_scoped(project_id, args)
    return {"steps": [r.to_dict() for r in results]}


class SetModuleBody(BaseModel):
    name: str


@router.post("/set")
def set_module(project_id: str, body: SetModuleBody):
    """
    Purpose: Activate a module for capture tagging (talos module set).
    Input: project_id, body.name.
    Output: { steps } from CLI.
    Side effects: active module changes; running proxy may restart via core notify.
    """
    results = cli.run_scoped(project_id, ["module", "set", body.name])
    return {"steps": [r.to_dict() for r in results]}


@router.post("/unset")
def unset_module(project_id: str):
    """
    Purpose: Reset active module to built-in global (talos module unset).
    Input: project_id.
    Output: { steps } from CLI.
    Side effects: active module → global; running proxy may restart via core notify.
    """
    results = cli.run_scoped(project_id, ["module", "unset"])
    return {"steps": [r.to_dict() for r in results]}


class RenameModuleBody(BaseModel):
    name: str
    new_name: str


@router.post("/rename")
def rename_module(project_id: str, body: RenameModuleBody):
    """
    Purpose: Rename a module display name; UUID stays stable (talos module rename).
    Input: project_id, body.name (current name or UUID), body.new_name.
    Output: { steps } from CLI.
    Side effects: CLI renames row; refuses built-in global.
    """
    results = cli.run_scoped(
        project_id, ["module", "rename", body.name, body.new_name]
    )
    return {"steps": [r.to_dict() for r in results]}


class DeleteModuleBody(BaseModel):
    name: str


@router.post("/delete")
def delete_module(project_id: str, body: DeleteModuleBody):
    """
    Purpose: Delete a module with cascade (talos module delete --force).
    Input: project_id, body.name (name or UUID).
    Output: { steps } from CLI.
    Side effects: CLI deletes module, cascades config, reassigns flows to global.
    UI confirmation is required before calling; --force skips interactive prompt.
    """
    results = cli.run_scoped(
        project_id, ["module", "delete", body.name, "--force"]
    )
    return {"steps": [r.to_dict() for r in results]}
