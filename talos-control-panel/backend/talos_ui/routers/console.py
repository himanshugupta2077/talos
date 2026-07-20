from fastapi import APIRouter
from pydantic import BaseModel
from typing import Any

from .. import cli
from ..command_tree import COMMAND_TREE, build_argv, find_command

router = APIRouter(prefix="/api/console", tags=["console"])


@router.get("/tree")
def get_tree():
    return {"groups": COMMAND_TREE}


class RunBody(BaseModel):
    command_id: str
    values: dict[str, Any] = {}
    project_id: str | None = None


@router.post("/run")
def run_command(body: RunBody):
    command = find_command(body.command_id)
    if command is None:
        return {"error": f"unknown command '{body.command_id}'"}
    argv = build_argv(command, body.values)
    if command.get("background"):
        result = cli.process_manager.start(command["id"], argv)
        return {"background": True, **result}
    if body.project_id:
        results = cli.run_scoped(body.project_id, argv)
        return {"steps": [r.to_dict() for r in results]}
    result = cli.run(argv)
    return {"steps": [result.to_dict()]}


class RawBody(BaseModel):
    args: list[str]
    project_id: str | None = None


@router.post("/raw")
def run_raw(body: RawBody):
    """Escape hatch: run an arbitrary talos argv list, e.g. for commands not
    yet modeled in the tree. Still goes through subprocess with a list argv
    (never a shell), so no shell-injection risk — but no argument validation
    either, so use the modeled commands where possible."""
    if body.project_id:
        results = cli.run_scoped(body.project_id, body.args)
        return {"steps": [r.to_dict() for r in results]}
    result = cli.run(body.args)
    return {"steps": [result.to_dict()]}
