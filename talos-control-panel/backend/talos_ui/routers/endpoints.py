"""
Endpoint Workspace API.

Reads use Talos core's policy resolver (via endpoint_reads) so the UI never
infers effective priority, exclusion, or qualification. Mutations always go
through multi-ID Talos CLI commands in a single invocation (atomic bulk).
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from .. import cli, config, db, endpoint_reads

router = APIRouter(prefix="/api/endpoints", tags=["endpoints"])


# ------------------------------------------------------------------ #
# List / filters / summary (static routes first)                       #
# ------------------------------------------------------------------ #


@router.get("")
def list_endpoints(
    project_id: str,
    offset: int = 0,
    limit: int = 50,
    search: str = "",
    method: str = "",
    role: str = "",
    module: str = "",
    priority: str = "",
    priority_source: str = "",
    qualified: str = "",
    excluded: str = "",
    dangerous: str = "",
    logout: str = "",
    qualification_reason: str = "",
    tag: str = "",
    has_parameters: str = "",
    has_baseline: str = "",
    baseline_status: str = "",
    decision: str = "",
    state: str = "",
    origin: str = "",
    host: str = "",
    problem: str = "",
    ids_only: str = "",
):
    """
    Resolved endpoint inventory for Inventory / Policy tables.

    When ids_only=1, returns only matching IDs (for select-all-matching).
    total is always the filtered match count (not unfiltered project size).
    """
    rows = endpoint_reads.list_resolved(
        project_id,
        method=method or None,
        host=host or None,
        search=search or None,
        role=role or None,
        priority=priority or None,
        priority_source=priority_source or None,
        qualified=qualified or None,
        excluded=excluded or None,
        dangerous=dangerous or None,
        logout=logout or None,
        qualification_reason=qualification_reason or None,
        module=module or None,
        tag=tag or None,
        has_parameters=has_parameters or None,
        has_baseline=has_baseline or None,
        baseline_status=baseline_status or None,
        decision=decision or None,
        state=state or None,
        origin=origin or None,
        problem=problem or None,
    )
    total = len(rows)
    if ids_only in ("1", "true", "yes"):
        return {"ids": [r["id"] for r in rows], "total": total}
    page = rows[offset : offset + max(1, min(limit, 500))]
    return {"endpoints": page, "total": total, "offset": offset, "limit": limit}


@router.get("/filters")
def endpoint_filters(project_id: str):
    record = db.get_project_record(project_id)
    db_path = config.project_db_path(project_id, record)
    if not db.db_exists(db_path):
        return {
            "methods": [],
            "roles": [],
            "modules": [],
            "priorities": ["CRITICAL", "HIGH", "NORMAL", "LOW"],
            "priority_sources": ["MANUAL", "RULE", "AUTO"],
            "qualification_reasons": [],
            "tags": [],
            "origins": [],
        }
    tags_raw = db.query_all(
        db_path,
        "SELECT DISTINCT tags FROM endpoint_policy WHERE tags IS NOT NULL AND tags != '[]'",
    )
    tag_set: set[str] = set()
    for row in tags_raw:
        for t in db.safe_json(row.get("tags"), []):
            if isinstance(t, str) and t.strip():
                tag_set.add(t.strip())
    reasons = [
        r["qualification_reason"]
        for r in db.query_all(
            db_path,
            "SELECT DISTINCT qualification_reason FROM endpoint_policy "
            "WHERE qualification_reason IS NOT NULL ORDER BY qualification_reason",
        )
        if r.get("qualification_reason")
    ]
    origins = [
        r["host"]
        for r in db.query_all(
            db_path, "SELECT DISTINCT host FROM endpoints ORDER BY host"
        )
        if r.get("host")
    ]
    return {
        "methods": [
            r["method"]
            for r in db.query_all(
                db_path, "SELECT DISTINCT method FROM endpoints ORDER BY method"
            )
        ],
        "roles": [
            r["name"]
            for r in db.query_all(db_path, "SELECT name FROM roles ORDER BY name")
        ],
        "modules": [
            r["name"]
            for r in db.query_all(db_path, "SELECT name FROM modules ORDER BY name")
        ],
        "priorities": ["CRITICAL", "HIGH", "NORMAL", "LOW"],
        "priority_sources": ["MANUAL", "RULE", "AUTO"],
        "qualification_reasons": reasons,
        "tags": sorted(tag_set),
        "origins": origins,
    }


@router.get("/summary")
def inventory_summary(project_id: str):
    return endpoint_reads.inventory_summary(project_id)


@router.get("/policy-summary")
def policy_summary(project_id: str):
    return endpoint_reads.policy_summary(project_id)


@router.get("/coverage")
def coverage(project_id: str):
    return endpoint_reads.coverage(project_id)


@router.get("/parameters/search")
def search_parameters(project_id: str, search: str = "", limit: int = 200):
    """
    Project-wide parameter lookup for the Input Validation picker and
    Coverage parameter table.
    """
    record = db.get_project_record(project_id)
    db_path = config.project_db_path(project_id, record)
    where = ""
    params: tuple = (limit,)
    if search:
        where = "WHERE p.name LIKE ? OR e.normalized_path LIKE ? OR e.host LIKE ?"
        like = f"%{search}%"
        params = (like, like, like, limit)
    rows = db.query_all(
        db_path,
        f"""
        SELECT p.id, p.name, p.location, p.param_type, p.endpoint_id,
               e.method, e.host, e.normalized_path
        FROM parameters p
        JOIN endpoints e ON e.id = p.endpoint_id
        {where}
        ORDER BY p.name
        LIMIT ?
        """,
        params,
    )
    return {"parameters": rows}


# ------------------------------------------------------------------ #
# Rules (canonical first-class resource)                               #
# ------------------------------------------------------------------ #


@router.get("/rules")
def rules_list(project_id: str):
    return {"rules": endpoint_reads.rules_with_impact(project_id)}


# Keep legacy path for existing clients
@router.get("/policy/rules")
def rules_list_legacy(project_id: str):
    return rules_list(project_id)


class RuleCreateBody(BaseModel):
    pattern: str
    priority: Optional[str] = None
    exclude: bool = False


@router.post("/rules")
def rule_create(project_id: str, body: RuleCreateBody):
    if not body.pattern.strip():
        raise HTTPException(400, "pattern is required")
    if not body.priority and not body.exclude:
        raise HTTPException(400, "Provide priority and/or exclude")
    args = ["endpoint", "rule", "add", body.pattern.strip(), "--format", "json"]
    if body.priority:
        args.extend(["--priority", body.priority.upper()])
    if body.exclude:
        args.append("--exclude")
    results = cli.run_scoped(project_id, args)
    return _steps_with_bulk(results)


class RuleUpdateBody(BaseModel):
    priority: Optional[str] = None
    clear_priority: bool = False
    exclude: Optional[bool] = None


class RulePreviewBody(BaseModel):
    pattern: str
    priority: Optional[str] = None
    exclude: bool = False


@router.post("/rules/preview")
def rule_preview(project_id: str, body: RulePreviewBody):
    """Live impact preview using the same core matcher/resolver as live policy."""
    record = db.get_project_record(project_id)
    db_path = config.project_db_path(project_id, record)
    if not body.pattern.strip():
        raise HTTPException(400, "pattern is required")
    if not db.db_exists(db_path):
        return {
            "pattern": body.pattern,
            "matching_count": 0,
            "current": {},
            "proposed": {},
            "endpoints": [],
        }
    pol = endpoint_reads.policy_mod()
    try:
        preview = pol.preview_path_rule_impact(
            db_path,
            project_id,
            body.pattern.strip(),
            priority=body.priority.upper() if body.priority else None,
            excluded=True if body.exclude else None,
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return preview


@router.post("/rules/{rule_id}")
def rule_update(project_id: str, rule_id: str, body: RuleUpdateBody):
    args = ["endpoint", "rule", "update", rule_id, "--format", "json"]
    if body.priority:
        args.extend(["--priority", body.priority.upper()])
    if body.clear_priority:
        args.append("--clear-priority")
    if body.exclude is True:
        args.append("--exclude")
    elif body.exclude is False:
        args.append("--include")
    if len(args) == 5:  # only id + format
        raise HTTPException(
            400,
            "Provide at least one of: priority, clear_priority, exclude",
        )
    results = cli.run_scoped(project_id, args)
    return _steps_with_bulk(results)


@router.delete("/rules/{rule_id}")
def rule_delete(project_id: str, rule_id: str):
    results = cli.run_scoped(
        project_id, ["endpoint", "rule", "delete", rule_id, "--format", "json"]
    )
    return _steps_with_bulk(results)


class PathPriorityBody(BaseModel):
    pattern: str
    priority: str


@router.post("/policy/path-priority")
def set_path_priority(project_id: str, body: PathPriorityBody):
    results = cli.run_scoped(
        project_id,
        [
            "endpoint",
            "priority",
            "set",
            "path",
            body.pattern,
            body.priority,
            "--format",
            "json",
        ],
    )
    return _steps_with_bulk(results)


class PathPatternBody(BaseModel):
    pattern: str


@router.post("/policy/path-exclude")
def exclude_path(project_id: str, body: PathPatternBody):
    results = cli.run_scoped(
        project_id,
        ["endpoint", "exclude", "path", body.pattern, "--format", "json"],
    )
    return _steps_with_bulk(results)


@router.post("/policy/path-include")
def include_path(project_id: str, body: PathPatternBody):
    results = cli.run_scoped(
        project_id,
        ["endpoint", "include", "path", body.pattern, "--format", "json"],
    )
    return _steps_with_bulk(results)


# ------------------------------------------------------------------ #
# Bulk mutations (single multi-ID CLI call each)                       #
# ------------------------------------------------------------------ #


class BulkIdsBody(BaseModel):
    endpoint_ids: list[str] = Field(default_factory=list)


class BulkMarkBody(BulkIdsBody):
    tag: str  # dangerous | logout | safe | --dangerous | --logout | --safe


class BulkUnmarkBody(BulkIdsBody):
    tag: str  # dangerous | logout


class BulkPriorityBody(BulkIdsBody):
    priority: Optional[str] = None  # CRITICAL|HIGH|NORMAL|LOW; omit/null to clear
    clear: bool = False


class BulkTagsBody(BulkIdsBody):
    action: str  # add | remove | set | clear
    tags: list[str] = Field(default_factory=list)


class BulkTestBody(BulkIdsBody):
    action: str  # enqueue_replay | replay_now | enqueue_auth


def _normalize_ids(ids: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for i in ids:
        i = (i or "").strip()
        if not i or i in seen:
            continue
        seen.add(i)
        out.append(i)
    return out


def _require_ids(ids: list[str]) -> list[str]:
    clean = _normalize_ids(ids)
    if not clean:
        raise HTTPException(400, "endpoint_ids is required")
    return clean


def _steps_with_bulk(results: list) -> dict:
    steps = [r.to_dict() for r in results]
    bulk: dict = {}
    for step in reversed(steps):
        if step.get("ok") and step.get("stdout"):
            parsed = endpoint_reads.parse_bulk_stdout(step["stdout"])
            if parsed:
                bulk = parsed
                break
    return {"steps": steps, "bulk": bulk, "ok": all(s.get("ok") for s in steps)}


@router.post("/bulk/mark")
def bulk_mark(project_id: str, body: BulkMarkBody):
    ids = _require_ids(body.endpoint_ids)
    tag = body.tag.lstrip("-")
    if tag not in ("dangerous", "logout", "safe"):
        raise HTTPException(400, "tag must be dangerous, logout, or safe")
    args = ["endpoint", "mark", *ids, f"--{tag}", "--format", "json"]
    results = cli.run_scoped(project_id, args)
    return _steps_with_bulk(results)


@router.post("/bulk/unmark")
def bulk_unmark(project_id: str, body: BulkUnmarkBody):
    ids = _require_ids(body.endpoint_ids)
    tag = body.tag.lstrip("-")
    if tag not in ("dangerous", "logout"):
        raise HTTPException(400, "tag must be dangerous or logout")
    args = ["endpoint", "unmark", *ids, f"--{tag}", "--format", "json"]
    results = cli.run_scoped(project_id, args)
    return _steps_with_bulk(results)


@router.post("/bulk/priority")
def bulk_priority(project_id: str, body: BulkPriorityBody):
    ids = _require_ids(body.endpoint_ids)
    if body.clear or not body.priority:
        args = [
            "endpoint",
            "priority",
            "clear",
            "endpoint",
            *ids,
            "--format",
            "json",
        ]
    else:
        level = body.priority.upper()
        if level not in ("CRITICAL", "HIGH", "NORMAL", "LOW"):
            raise HTTPException(400, f"Invalid priority '{body.priority}'")
        args = [
            "endpoint",
            "priority",
            "set",
            "endpoint",
            *ids,
            level,
            "--format",
            "json",
        ]
    results = cli.run_scoped(project_id, args)
    return _steps_with_bulk(results)


@router.post("/bulk/exclude")
def bulk_exclude(project_id: str, body: BulkIdsBody):
    ids = _require_ids(body.endpoint_ids)
    args = ["endpoint", "exclude", "endpoint", *ids, "--format", "json"]
    results = cli.run_scoped(project_id, args)
    return _steps_with_bulk(results)


@router.post("/bulk/include")
def bulk_include(project_id: str, body: BulkIdsBody):
    ids = _require_ids(body.endpoint_ids)
    args = ["endpoint", "include", "endpoint", *ids, "--format", "json"]
    results = cli.run_scoped(project_id, args)
    return _steps_with_bulk(results)


@router.post("/bulk/tags")
def bulk_tags(project_id: str, body: BulkTagsBody):
    ids = _require_ids(body.endpoint_ids)
    action = body.action.lower()
    if action not in ("add", "remove", "set", "clear"):
        raise HTTPException(400, "action must be add, remove, set, or clear")
    if action == "clear":
        args = ["endpoint", "tags", "clear", *ids, "--format", "json"]
    else:
        if not body.tags:
            raise HTTPException(400, "tags required for add/remove/set")
        args = ["endpoint", "tags", action, *ids]
        for t in body.tags:
            args.extend(["--tag", t])
        args.extend(["--format", "json"])
    results = cli.run_scoped(project_id, args)
    return _steps_with_bulk(results)


@router.post("/bulk/test")
def bulk_test(project_id: str, body: BulkTestBody):
    """
    Test orchestration (not endpoint policy mutation).
    Replay now requires exactly one ID; enqueue accepts multiple sequential CLI calls
    only for scheduler enqueue (no atomic multi-ID enqueue in core yet) — we still
    pass explicit IDs resolved by the panel, never invent filter mutation.
    """
    ids = _require_ids(body.endpoint_ids)
    action = body.action.lower()
    all_results = []

    if action == "replay_now":
        if len(ids) != 1:
            raise HTTPException(400, "Replay now requires exactly one endpoint")
        results = cli.run_scoped(
            project_id, ["replay", "endpoint", ids[0], "--right-now"]
        )
        return _steps_with_bulk(results)

    if action == "enqueue_replay":
        for eid in ids:
            results = cli.run_scoped(
                project_id, ["scheduler", "enqueue", "endpoint", eid]
            )
            all_results.extend(results)
        return _steps_with_bulk(all_results)

    if action == "enqueue_auth":
        for eid in ids:
            results = cli.run_scoped(
                project_id,
                ["scheduler", "enqueue", "endpoint", eid, "--type", "auth-test"],
            )
            all_results.extend(results)
        return _steps_with_bulk(all_results)

    raise HTTPException(400, f"Unknown test action '{body.action}'")


# ------------------------------------------------------------------ #
# Single-endpoint detail / policy / mutations                          #
# ------------------------------------------------------------------ #


@router.get("/{endpoint_id}/policy")
def endpoint_policy_explain(project_id: str, endpoint_id: str):
    data = endpoint_reads.explain_policy(project_id, endpoint_id)
    if not data:
        raise HTTPException(404, "endpoint not found")
    return data


@router.get("/{endpoint_id}")
def endpoint_detail(project_id: str, endpoint_id: str):
    record = db.get_project_record(project_id)
    db_path = config.project_db_path(project_id, record)
    endpoint = db.query_one(db_path, "SELECT * FROM endpoints WHERE id=?", (endpoint_id,))
    if endpoint is None:
        raise HTTPException(404, "endpoint not found")
    policy_row = db.query_one(
        db_path, "SELECT * FROM endpoint_policy WHERE endpoint_id=?", (endpoint_id,)
    )
    annotations = db.query_all(
        db_path,
        "SELECT tag, created_at FROM endpoint_annotations WHERE endpoint_id=?",
        (endpoint_id,),
    )
    parameters = db.query_all(
        db_path,
        "SELECT * FROM parameters WHERE endpoint_id=? ORDER BY location, name",
        (endpoint_id,),
    )
    roles = db.query_all(
        db_path,
        "SELECT r.id, r.name, er.first_seen, er.last_seen FROM endpoint_roles er "
        "JOIN roles r ON r.id = er.role_id WHERE er.endpoint_id=?",
        (endpoint_id,),
    )
    modules = db.query_all(
        db_path,
        """
        SELECT DISTINCT m.id, m.name
        FROM flows f
        JOIN modules m ON m.id = f.module_id
        WHERE f.endpoint_id=?
        ORDER BY m.name
        """,
        (endpoint_id,),
    )
    flows = db.query_all(
        db_path,
        """
        SELECT f.id, f.method, f.path, f.status_code, f.captured_at, f.source,
               COALESCE(r.name,'—') AS role_name, COALESCE(m.name,'—') AS module_name
        FROM flows f
        LEFT JOIN roles r ON r.id = f.role_id
        LEFT JOIN modules m ON m.id = f.module_id
        WHERE f.endpoint_id=?
        ORDER BY f.captured_at DESC LIMIT 50
        """,
        (endpoint_id,),
    )
    for p in parameters:
        p["example_values"] = db.safe_json(p.get("example_values"), [])
        p["appears_in_roles"] = db.safe_json(p.get("appears_in_roles"), [])
        p["appears_in_modules"] = db.safe_json(p.get("appears_in_modules"), [])
        p["reflection_locations"] = db.safe_json(p.get("reflection_locations"), [])

    explanation = endpoint_reads.explain_policy(project_id, endpoint_id)
    pol = endpoint_reads.policy_mod()
    origin, host_display = pol.split_origin_identity(endpoint.get("host") or "")
    hit_count = db.scalar(
        db_path, "SELECT COUNT(*) FROM flows WHERE endpoint_id=?", (endpoint_id,)
    )

    tags_from_policy: list[str] = []
    if policy_row:
        tags_from_policy = db.safe_json(policy_row.get("tags"), [])

    return {
        "endpoint": {
            **dict(endpoint),
            "origin": origin,
            "host_display": host_display,
            "hit_count": hit_count,
        },
        "policy": policy_row,
        "policy_explanation": explanation,
        "annotations": annotations,
        "tags": tags_from_policy,
        "parameters": parameters,
        "roles": roles,
        "modules": modules,
        "flows": flows,
        "activity_available": False,
    }


@router.get("/{endpoint_id}/adjacent")
def adjacent(project_id: str, endpoint_id: str):
    record = db.get_project_record(project_id)
    db_path = config.project_db_path(project_id, record)
    rows = db.query_all(
        db_path,
        """
        SELECT e.id, COUNT(f.id) AS hit_count
        FROM endpoints e LEFT JOIN flows f ON f.endpoint_id = e.id
        GROUP BY e.id ORDER BY hit_count DESC, e.normalized_path ASC
        """,
    )
    ids = [r["id"] for r in rows]
    if endpoint_id not in ids:
        return {"prev_id": None, "next_id": None}
    idx = ids.index(endpoint_id)
    return {
        "prev_id": ids[idx - 1] if idx > 0 else None,
        "next_id": ids[idx + 1] if idx < len(ids) - 1 else None,
    }


class MarkBody(BaseModel):
    tag: str  # --logout | --dangerous | --safe | logout | dangerous | safe


@router.post("/{endpoint_id}/mark")
def mark(project_id: str, endpoint_id: str, body: MarkBody):
    tag = body.tag if body.tag.startswith("--") else f"--{body.tag.lstrip('-')}"
    results = cli.run_scoped(
        project_id, ["endpoint", "mark", endpoint_id, tag, "--format", "json"]
    )
    return _steps_with_bulk(results)


class UnmarkBody(BaseModel):
    tag: str


@router.post("/{endpoint_id}/unmark")
def unmark(project_id: str, endpoint_id: str, body: UnmarkBody):
    tag = body.tag if body.tag.startswith("--") else f"--{body.tag.lstrip('-')}"
    results = cli.run_scoped(
        project_id, ["endpoint", "unmark", endpoint_id, tag, "--format", "json"]
    )
    return _steps_with_bulk(results)


@router.post("/{endpoint_id}/export")
def export_endpoint(project_id: str, endpoint_id: str):
    results = cli.run_scoped(project_id, ["endpoint", "export", endpoint_id])
    return _steps_with_bulk(results)


class PriorityBody(BaseModel):
    priority: str


@router.post("/{endpoint_id}/priority")
def set_priority(project_id: str, endpoint_id: str, body: PriorityBody):
    results = cli.run_scoped(
        project_id,
        [
            "endpoint",
            "priority",
            "set",
            "endpoint",
            endpoint_id,
            body.priority.upper(),
            "--format",
            "json",
        ],
    )
    return _steps_with_bulk(results)


@router.delete("/{endpoint_id}/priority")
def clear_priority(project_id: str, endpoint_id: str):
    results = cli.run_scoped(
        project_id,
        [
            "endpoint",
            "priority",
            "clear",
            "endpoint",
            endpoint_id,
            "--format",
            "json",
        ],
    )
    return _steps_with_bulk(results)


@router.post("/{endpoint_id}/exclude")
def exclude(project_id: str, endpoint_id: str):
    results = cli.run_scoped(
        project_id,
        ["endpoint", "exclude", "endpoint", endpoint_id, "--format", "json"],
    )
    return _steps_with_bulk(results)


@router.post("/{endpoint_id}/include")
def include(project_id: str, endpoint_id: str):
    results = cli.run_scoped(
        project_id,
        ["endpoint", "include", "endpoint", endpoint_id, "--format", "json"],
    )
    return _steps_with_bulk(results)


class TagsBody(BaseModel):
    action: str
    tags: list[str] = Field(default_factory=list)


@router.post("/{endpoint_id}/tags")
def endpoint_tags(project_id: str, endpoint_id: str, body: TagsBody):
    return bulk_tags(
        project_id,
        BulkTagsBody(endpoint_ids=[endpoint_id], action=body.action, tags=body.tags),
    )
