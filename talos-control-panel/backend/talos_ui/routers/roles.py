"""
Roles API — list from project DB; all mutations via Talos CLI.

CLI surface (project-scoped):
  role create | set | unset | rename | delete
"""

from fastapi import APIRouter
from pydantic import BaseModel

from .. import cli, config, db

router = APIRouter(prefix="/api/roles", tags=["roles"])


@router.get("")
def list_roles(project_id: str):
    """
    Purpose: Return all roles for the project (including built-in global).
    Input: project_id query.
    Output: { roles: [{ id, name, is_active }, ...] }.
    Side effects: none (read-only DB).
    """
    record = db.get_project_record(project_id)
    db_path = config.project_db_path(project_id, record)
    rows = db.query_all(db_path, "SELECT id, name, is_active FROM roles ORDER BY name")
    return {"roles": rows}


class CreateRoleBody(BaseModel):
    name: str


@router.post("")
def create_role(project_id: str, body: CreateRoleBody):
    """
    Purpose: Create a role (talos role create).
    Input: project_id, body.name.
    Output: { steps } from CLI.
    Side effects: CLI mutates project DB.
    """
    results = cli.run_scoped(project_id, ["role", "create", body.name])
    return {"steps": [r.to_dict() for r in results]}


class SetRoleBody(BaseModel):
    name: str


@router.post("/set")
def set_role(project_id: str, body: SetRoleBody):
    """
    Purpose: Activate a role for capture tagging (talos role set).
    Input: project_id, body.name.
    Output: { steps } from CLI.
    Side effects: active role changes; running proxy may restart via core notify.
    """
    results = cli.run_scoped(project_id, ["role", "set", body.name])
    return {"steps": [r.to_dict() for r in results]}


@router.post("/unset")
def unset_role(project_id: str):
    """
    Purpose: Reset active role to built-in global (talos role unset).
    Input: project_id.
    Output: { steps } from CLI.
    Side effects: active role → global; running proxy may restart via core notify.
    """
    results = cli.run_scoped(project_id, ["role", "unset"])
    return {"steps": [r.to_dict() for r in results]}


class RenameRoleBody(BaseModel):
    name: str
    new_name: str


@router.post("/rename")
def rename_role(project_id: str, body: RenameRoleBody):
    """
    Purpose: Rename a role display name; UUID stays stable (talos role rename).
    Input: project_id, body.name (current name or UUID), body.new_name.
    Output: { steps } from CLI.
    Side effects: CLI renames row; refuses built-in global.
    """
    results = cli.run_scoped(
        project_id, ["role", "rename", body.name, body.new_name]
    )
    return {"steps": [r.to_dict() for r in results]}


class DeleteRoleBody(BaseModel):
    name: str


@router.post("/delete")
def delete_role(project_id: str, body: DeleteRoleBody):
    """
    Purpose: Delete a role with cascade (talos role delete --force).
    Input: project_id, body.name (name or UUID).
    Output: { steps } from CLI.
    Side effects: CLI deletes role, cascades config, reassigns flows to global.
    UI confirmation is required before calling; --force skips interactive prompt.
    """
    results = cli.run_scoped(
        project_id, ["role", "delete", body.name, "--force"]
    )
    return {"steps": [r.to_dict() for r in results]}
