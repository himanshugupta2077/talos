from fastapi import APIRouter
from pydantic import BaseModel

from .. import cli

router = APIRouter(prefix="/api/replay", tags=["replay"])


class ReplayBody(BaseModel):
    right_now: bool = False


@router.post("/flow/{flow_id}")
def replay_flow(project_id: str, flow_id: str, body: ReplayBody):
    args = ["replay", "flow", flow_id]
    if body.right_now:
        args.append("--right-now")
    results = cli.run_scoped(project_id, args)
    return {"steps": [r.to_dict() for r in results]}


@router.post("/endpoint/{endpoint_id}")
def replay_endpoint(project_id: str, endpoint_id: str, body: ReplayBody):
    args = ["replay", "endpoint", endpoint_id]
    if body.right_now:
        args.append("--right-now")
    results = cli.run_scoped(project_id, args)
    return {"steps": [r.to_dict() for r in results]}
