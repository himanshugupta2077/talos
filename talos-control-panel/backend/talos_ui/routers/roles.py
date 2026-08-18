"""
Roles API — list from project DB; all mutations via Talos CLI.

CLI surface (project-scoped):
  role create | set | unset | rename | delete | privilege
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
    rows = db.query_all(
        db_path,
        "SELECT id, name, is_active, COALESCE(privilege, 0) AS privilege "
        "FROM roles ORDER BY privilege ASC, name ASC",
    )
    return {"roles": rows}


class CreateRoleBody(BaseModel):
    name: str
    privilege: int = 0


@router.post("")
def create_role(project_id: str, body: CreateRoleBody):
    """
    Purpose: Create a role (talos role create [--privilege N]).
    Input: project_id, body.name, optional body.privilege (0 = highest).
    Output: { steps } from CLI.
    Side effects: CLI mutates project DB.
    """
    argv = ["role", "create", body.name]
    if body.privilege:
        argv.extend(["--privilege", str(int(body.privilege))])
    results = cli.run_scoped(project_id, argv)
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


class PrivilegeBody(BaseModel):
    name: str
    privilege: int


@router.post("/privilege")
def set_privilege(project_id: str, body: PrivilegeBody):
    """
    Purpose: Set a role's privilege rank (talos role privilege).
    Input: project_id, body.name (name or UUID), body.privilege (0 = highest).
    Output: { steps } from CLI.
    Side effects: CLI updates roles.privilege.
    """
    results = cli.run_scoped(
        project_id,
        ["role", "privilege", body.name, str(int(body.privilege))],
    )
    return {"steps": [r.to_dict() for r in results]}
