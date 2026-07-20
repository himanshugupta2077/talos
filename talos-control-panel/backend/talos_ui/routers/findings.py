from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from .. import cli, config, db

router = APIRouter(prefix="/api/findings", tags=["findings"])


_FINDING_SELECT = """
    SELECT f.*,
        (SELECT r.name FROM finding_evidence fe JOIN roles r ON r.id = fe.reference_id
         WHERE fe.finding_id = f.id AND fe.evidence_type = 'role' LIMIT 1) AS role_name,
        (SELECT m.name FROM finding_evidence fe JOIN modules m ON m.id = fe.reference_id
         WHERE fe.finding_id = f.id AND fe.evidence_type = 'module' LIMIT 1) AS module_name
    FROM findings f
"""


@router.get("")
def list_findings(project_id: str, status: str | None = None):
    record = db.get_project_record(project_id)
    db_path = config.project_db_path(project_id, record)
    if status:
        rows = db.query_all(
            db_path,
            f"{_FINDING_SELECT} WHERE f.project_id=? AND f.status=? ORDER BY f.created_at DESC",
            (project_id, status),
        )
    else:
        rows = db.query_all(
            db_path,
            f"{_FINDING_SELECT} WHERE f.project_id=? ORDER BY f.created_at DESC",
            (project_id,),
        )
    return {"findings": rows}


@router.get("/{finding_id}")
def finding_detail(project_id: str, finding_id: str):
    record = db.get_project_record(project_id)
    db_path = config.project_db_path(project_id, record)
    finding = db.query_one(db_path, f"{_FINDING_SELECT} WHERE f.id=?", (finding_id,))
    if finding is None:
        raise HTTPException(404, "finding not found")
    evidence = db.query_all(
        db_path, "SELECT * FROM finding_evidence WHERE finding_id=? ORDER BY created_at ASC", (finding_id,)
    )
    for e in evidence:
        e["data"] = db.safe_json(e.get("data"), {})
    timeline = db.query_all(
        db_path, "SELECT * FROM finding_timeline WHERE finding_id=? ORDER BY created_at ASC", (finding_id,)
    )
    duplicates = db.query_all(
        db_path, "SELECT * FROM findings WHERE duplicate_of=? ORDER BY created_at DESC", (finding_id,)
    )
    return {"finding": finding, "evidence": evidence, "timeline": timeline, "duplicates": duplicates}


@router.post("/{finding_id}/confirm")
def confirm(project_id: str, finding_id: str):
    results = cli.run_scoped(project_id, ["finding", "confirm", finding_id])
    return {"steps": [r.to_dict() for r in results]}


@router.post("/{finding_id}/reject")
def reject(project_id: str, finding_id: str):
    results = cli.run_scoped(project_id, ["finding", "reject", finding_id])
    return {"steps": [r.to_dict() for r in results]}


@router.post("/{finding_id}/reopen")
def reopen(project_id: str, finding_id: str):
    results = cli.run_scoped(project_id, ["finding", "reopen", finding_id])
    return {"steps": [r.to_dict() for r in results]}


class DuplicateBody(BaseModel):
    of: str


@router.post("/{finding_id}/duplicate")
def duplicate(project_id: str, finding_id: str, body: DuplicateBody):
    results = cli.run_scoped(project_id, ["finding", "duplicate", finding_id, "--of", body.of])
    return {"steps": [r.to_dict() for r in results]}


class NotesBody(BaseModel):
    notes: str


@router.get("/{finding_id}/report")
def report(project_id: str, finding_id: str):
    results = cli.run_scoped(project_id, ["finding", "report", finding_id])
    return {"steps": [r.to_dict() for r in results]}


# ------------------------------------------------------------------ #
# Groups                                                               #
# ------------------------------------------------------------------ #

@router.get("/groups/list")
def list_groups(project_id: str):
    record = db.get_project_record(project_id)
    db_path = config.project_db_path(project_id, record)
    rows = db.query_all(
        db_path,
        """
        SELECT g.*, COUNT(m.finding_id) AS member_count
        FROM finding_groups g
        LEFT JOIN finding_group_members m ON m.group_id = g.id
        WHERE g.project_id=?
        GROUP BY g.id ORDER BY g.created_at ASC
        """,
        (project_id,),
    )
    return {"groups": rows}


@router.get("/groups/{group_id}/members")
def group_members(project_id: str, group_id: str):
    record = db.get_project_record(project_id)
    db_path = config.project_db_path(project_id, record)
    rows = db.query_all(
        db_path,
        """
        SELECT f.* FROM findings f
        JOIN finding_group_members m ON m.finding_id = f.id
        WHERE m.group_id=? ORDER BY f.created_at DESC
        """,
        (group_id,),
    )
    return {"findings": rows}


class GroupCreateBody(BaseModel):
    name: str


@router.post("/groups")
def create_group(project_id: str, body: GroupCreateBody):
    results = cli.run_scoped(project_id, ["finding", "group", "create", body.name])
    return {"steps": [r.to_dict() for r in results]}


class GroupMemberBody(BaseModel):
    group: str
    finding: str


@router.post("/groups/add")
def group_add(project_id: str, body: GroupMemberBody):
    results = cli.run_scoped(project_id, ["finding", "group", "add", body.group, body.finding])
    return {"steps": [r.to_dict() for r in results]}


@router.post("/groups/remove-member")
def group_remove_member(project_id: str, body: GroupMemberBody):
    results = cli.run_scoped(project_id, ["finding", "group", "remove", body.group, body.finding])
    return {"steps": [r.to_dict() for r in results]}


class GroupDeleteBody(BaseModel):
    group: str
    remove_findings: bool = False


@router.post("/groups/delete")
def group_delete(project_id: str, body: GroupDeleteBody):
    args = ["finding", "group", "remove", body.group]
    if body.remove_findings:
        args.append("--remove-findings")
    results = cli.run_scoped(project_id, args)
    return {"steps": [r.to_dict() for r in results]}


@router.get("/groups/report/{group_name}")
def group_report(project_id: str, group_name: str):
    results = cli.run_scoped(project_id, ["finding", "report", "--group", group_name])
    return {"steps": [r.to_dict() for r in results]}
