from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from .. import cli, config, db

router = APIRouter(prefix="/api/findings", tags=["findings"])


_FINDING_SELECT = """
    SELECT f.*,
        (SELECT r.name FROM finding_evidence fe JOIN roles r ON r.id = fe.reference_id
         WHERE fe.finding_id = f.id AND fe.evidence_type = 'role' LIMIT 1) AS role_name,
        (SELECT m.name FROM finding_evidence fe JOIN modules m ON m.id = fe.reference_id
         WHERE fe.finding_id = f.id AND fe.evidence_type = 'module' LIMIT 1) AS module_name,
        CASE
            WHEN COALESCE(f.relation_type, 'PRIMARY') = 'PRIMARY' THEN (
                SELECT COUNT(*) FROM findings child
                WHERE child.parent_finding_id = f.id
                  AND COALESCE(child.relation_type, 'PRIMARY') = 'LINKED'
            )
            ELSE 0
        END AS linked_count
    FROM findings f
"""


def _relation_clause(view: str) -> str:
    """Map list view mode to SQL relation filter (CLI: default PRIMARY, --linked, --all)."""
    mode = (view or "primary").lower()
    if mode == "linked":
        return "AND COALESCE(f.relation_type, 'PRIMARY') = 'LINKED'"
    if mode == "all":
        return ""
    # default / primary
    return "AND COALESCE(f.relation_type, 'PRIMARY') = 'PRIMARY'"


@router.get("")
def list_findings(
    project_id: str,
    status: str | None = None,
    view: str = Query(
        "primary",
        description="primary (default, CLI list) | linked (--linked) | all (--all)",
    ),
):
    record = db.get_project_record(project_id)
    db_path = config.project_db_path(project_id, record)
    rel = _relation_clause(view)
    if status:
        rows = db.query_all(
            db_path,
            f"{_FINDING_SELECT} WHERE f.project_id=? AND f.status=? {rel} ORDER BY f.created_at DESC",
            (project_id, status),
        )
    else:
        rows = db.query_all(
            db_path,
            f"{_FINDING_SELECT} WHERE f.project_id=? {rel} ORDER BY f.created_at DESC",
            (project_id,),
        )
    return {"findings": rows, "view": (view or "primary").lower()}


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

    # Cluster: parent (if LINKED) + LINKED children (if PRIMARY).
    parent = None
    parent_id = finding.get("parent_finding_id")
    if parent_id:
        parent = db.query_one(db_path, f"{_FINDING_SELECT} WHERE f.id=?", (parent_id,))
    linked = db.query_all(
        db_path,
        f"""
        {_FINDING_SELECT}
        WHERE f.parent_finding_id=?
          AND COALESCE(f.relation_type, 'PRIMARY') = 'LINKED'
        ORDER BY f.created_at ASC
        """,
        (finding_id,),
    )
    return {
        "finding": finding,
        "evidence": evidence,
        "timeline": timeline,
        "duplicates": duplicates,
        "parent": parent,
        "linked": linked,
    }


class LifecycleBody(BaseModel):
    """Optional bulk apply to LINKED children (CLI --linked [--force])."""
    linked: bool = False
    force: bool = False


def _lifecycle_args(action: str, finding_id: str, body: LifecycleBody | None) -> list[str]:
    args = ["finding", action, finding_id]
    if body and body.linked:
        args.append("--linked")
        if body.force:
            args.append("--force")
    return args


@router.post("/{finding_id}/confirm")
def confirm(project_id: str, finding_id: str, body: LifecycleBody | None = None):
    results = cli.run_scoped(project_id, _lifecycle_args("confirm", finding_id, body))
    return {"steps": [r.to_dict() for r in results]}


@router.post("/{finding_id}/reject")
def reject(project_id: str, finding_id: str, body: LifecycleBody | None = None):
    results = cli.run_scoped(project_id, _lifecycle_args("reject", finding_id, body))
    return {"steps": [r.to_dict() for r in results]}


@router.post("/{finding_id}/reopen")
def reopen(project_id: str, finding_id: str, body: LifecycleBody | None = None):
    results = cli.run_scoped(project_id, _lifecycle_args("reopen", finding_id, body))
    return {"steps": [r.to_dict() for r in results]}


class DuplicateBody(BaseModel):
    of: str


@router.post("/{finding_id}/duplicate")
def duplicate(project_id: str, finding_id: str, body: DuplicateBody):
    results = cli.run_scoped(project_id, ["finding", "duplicate", finding_id, "--of", body.of])
    return {"steps": [r.to_dict() for r in results]}


class NotesBody(BaseModel):
    notes: str


@router.post("/{finding_id}/notes")
def set_notes(project_id: str, finding_id: str, body: NotesBody):
    """Set analyst notes via ``talos finding note set <uuid>`` (stdin)."""
    if not body.notes or not body.notes.strip():
        raise HTTPException(400, "notes text is empty; use DELETE to clear")
    results = cli.run_scoped_with_stdin(
        project_id,
        ["finding", "note", "set", finding_id],
        body.notes,
    )
    return {"steps": [r.to_dict() for r in results]}


@router.delete("/{finding_id}/notes")
def clear_notes(project_id: str, finding_id: str):
    """Clear analyst notes via ``talos finding note clear <uuid>``."""
    results = cli.run_scoped(project_id, ["finding", "note", "clear", finding_id])
    return {"steps": [r.to_dict() for r in results]}


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


# ------------------------------------------------------------------ #
# Bulk lifecycle (multi-select on Findings list)                       #
# ------------------------------------------------------------------ #

_BULK_ACTIONS = frozenset({"confirm", "reject", "reopen"})
_BULK_MAX = 500


class BulkLifecycleBody(BaseModel):
    """
    Multi-finding status change (list-page selection).

    Mirrors ``talos finding confirm|reject|reopen`` per id. Optional
    ``linked`` applies PRIMARY+LINKED bulk for each selected PRIMARY
    (CLI ``--linked --force``).
    """

    action: str = Field(..., description="confirm | reject | reopen")
    finding_ids: list[str] = Field(default_factory=list)
    linked: bool = False


class BulkGroupBody(BaseModel):
    """Add many findings to a named group (CLI group add per id)."""

    group: str
    finding_ids: list[str] = Field(default_factory=list)


class BulkNotesBody(BaseModel):
    """Set the same analyst notes on many findings (CLI note set)."""

    notes: str
    finding_ids: list[str] = Field(default_factory=list)


def _normalize_ids(ids: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for raw in ids or []:
        fid = (raw or "").strip()
        if not fid or fid in seen:
            continue
        seen.add(fid)
        out.append(fid)
    return out


@router.post("/bulk")
def bulk_lifecycle(project_id: str, body: BulkLifecycleBody):
    """
    Confirm / reject / reopen many findings in one request.

    Runs the same CLI lifecycle path as single-finding routes so audit
    timeline and --linked semantics stay consistent.
    """
    action = (body.action or "").strip().lower()
    if action not in _BULK_ACTIONS:
        raise HTTPException(400, f"action must be one of {sorted(_BULK_ACTIONS)}")
    ids = _normalize_ids(body.finding_ids)
    if not ids:
        raise HTTPException(400, "finding_ids is empty")
    if len(ids) > _BULK_MAX:
        raise HTTPException(400, f"at most {_BULK_MAX} findings per bulk request")

    lifecycle = LifecycleBody(linked=bool(body.linked), force=True)
    results = []
    ok = 0
    failed = 0
    for fid in ids:
        steps = cli.run_scoped(project_id, _lifecycle_args(action, fid, lifecycle))
        step_dicts = [r.to_dict() for r in steps]
        all_ok = all(s.get("ok", False) for s in step_dicts) if step_dicts else False
        if all_ok:
            ok += 1
        else:
            failed += 1
        results.append({"finding_id": fid, "ok": all_ok, "steps": step_dicts})
    return {
        "action": action,
        "requested": len(ids),
        "ok": ok,
        "failed": failed,
        "linked": bool(body.linked),
        "results": results,
    }


@router.post("/bulk/group")
def bulk_group_add(project_id: str, body: BulkGroupBody):
    """Add many findings to a group (``talos finding group add`` per id)."""
    group = (body.group or "").strip()
    if not group:
        raise HTTPException(400, "group name is required")
    ids = _normalize_ids(body.finding_ids)
    if not ids:
        raise HTTPException(400, "finding_ids is empty")
    if len(ids) > _BULK_MAX:
        raise HTTPException(400, f"at most {_BULK_MAX} findings per bulk request")

    results = []
    ok = 0
    failed = 0
    for fid in ids:
        steps = cli.run_scoped(
            project_id, ["finding", "group", "add", group, fid]
        )
        step_dicts = [r.to_dict() for r in steps]
        all_ok = all(s.get("ok", False) for s in step_dicts) if step_dicts else False
        if all_ok:
            ok += 1
        else:
            failed += 1
        results.append({"finding_id": fid, "ok": all_ok, "steps": step_dicts})
    return {
        "group": group,
        "requested": len(ids),
        "ok": ok,
        "failed": failed,
        "results": results,
    }


@router.post("/bulk/notes")
def bulk_notes(project_id: str, body: BulkNotesBody):
    """Set the same notes text on many findings (``talos finding note set``)."""
    notes = body.notes if body.notes is not None else ""
    if not str(notes).strip():
        raise HTTPException(400, "notes text is empty")
    ids = _normalize_ids(body.finding_ids)
    if not ids:
        raise HTTPException(400, "finding_ids is empty")
    if len(ids) > _BULK_MAX:
        raise HTTPException(400, f"at most {_BULK_MAX} findings per bulk request")

    results = []
    ok = 0
    failed = 0
    for fid in ids:
        steps = cli.run_scoped_with_stdin(
            project_id, ["finding", "note", "set", fid], notes
        )
        step_dicts = [r.to_dict() for r in steps]
        all_ok = all(s.get("ok", False) for s in step_dicts) if step_dicts else False
        if all_ok:
            ok += 1
        else:
            failed += 1
        results.append({"finding_id": fid, "ok": all_ok, "steps": step_dicts})
    return {
        "requested": len(ids),
        "ok": ok,
        "failed": failed,
        "results": results,
    }
