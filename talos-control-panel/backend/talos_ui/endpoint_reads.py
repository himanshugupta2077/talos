"""
Read helpers for the Endpoint Workspace.

Purpose:
    Load **resolved** endpoint policy for Control Panel listings without
    re-implementing the policy engine in SQL or React. Uses the same Talos
    core resolver as `talos endpoint list` / `talos endpoint policy`.

Mutations never go through this module — only `cli.run_scoped`.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Optional

from . import config, db


def _ensure_talos_on_path() -> None:
    root = str(config.TALOS_ROOT)
    if root not in sys.path:
        sys.path.insert(0, root)


def policy_mod():
    """Import talos.projects.policy from TALOS_ROOT (read-only resolver)."""
    _ensure_talos_on_path()
    from talos.projects import policy as policy_module

    return policy_module


def _db_path(project_id: str) -> Path:
    record = db.get_project_record(project_id)
    return config.project_db_path(project_id, record)


def inventory_enrichment(db_path: Path) -> dict[str, dict]:
    """
    Hit counts, modules observed, and parameter counts keyed by endpoint id.
    Read-only SQL observation (not policy decisions).
    """
    if not db.db_exists(db_path):
        return {}
    rows = db.query_all(
        db_path,
        """
        SELECT
            e.id,
            COUNT(DISTINCT f.id) AS hit_count,
            GROUP_CONCAT(DISTINCT m.name) AS modules,
            (SELECT COUNT(*) FROM parameters p WHERE p.endpoint_id = e.id) AS parameter_count
        FROM endpoints e
        LEFT JOIN flows f ON f.endpoint_id = e.id
        LEFT JOIN modules m ON m.id = f.module_id
        GROUP BY e.id
        """,
    )
    return {
        r["id"]: {
            "hit_count": int(r["hit_count"] or 0),
            "modules": r["modules"],
            "parameter_count": int(r["parameter_count"] or 0),
        }
        for r in rows
    }


def rule_id_by_pattern(db_path: Path, project_id: str) -> dict[str, str]:
    if not db.db_exists(db_path):
        return {}
    rows = db.query_all(
        db_path,
        "SELECT id, pattern FROM policy_rules WHERE project_id=?",
        (project_id,),
    )
    return {r["pattern"]: r["id"] for r in rows}


def decision_for(row: dict) -> str:
    """TESTABLE when qualified and not excluded; else SKIPPED."""
    if row.get("qualified") and not row.get("excluded"):
        return "TESTABLE"
    return "SKIPPED"


def state_for(row: dict) -> str:
    """Primary operator-facing state label for Inventory."""
    if row.get("logout"):
        return "LOGOUT"
    if row.get("dangerous"):
        return "DANGEROUS"
    if row.get("excluded"):
        return "EXCLUDED"
    if not row.get("qualified"):
        return "UNQUALIFIED"
    return "TESTABLE"


def list_resolved(
    project_id: str,
    *,
    method: Optional[str] = None,
    host: Optional[str] = None,
    search: Optional[str] = None,
    role: Optional[str] = None,
    priority: Optional[str] = None,
    priority_source: Optional[str] = None,
    qualified: Optional[str] = None,
    excluded: Optional[str] = None,
    dangerous: Optional[str] = None,
    logout: Optional[str] = None,
    qualification_reason: Optional[str] = None,
    module: Optional[str] = None,
    tag: Optional[str] = None,
    has_parameters: Optional[str] = None,
    has_baseline: Optional[str] = None,
    baseline_status: Optional[str] = None,
    decision: Optional[str] = None,
    state: Optional[str] = None,
    origin: Optional[str] = None,
    problem: Optional[str] = None,
) -> list[dict]:
    """
    Full resolved inventory with enrichment and Control Panel filters applied.
    """
    db_path = _db_path(project_id)
    if not db.db_exists(db_path):
        return []

    pol = policy_mod()
    role_id: Optional[str] = None
    if role:
        # Resolve role name → id when needed
        role_row = db.query_one(
            db_path,
            "SELECT id FROM roles WHERE name=? OR id=?",
            (role, role),
        )
        if role_row is None:
            return []
        role_id = role_row["id"]

    q_filter: Optional[bool] = None
    if qualified in ("0", "1"):
        q_filter = qualified == "1"
    e_filter: Optional[bool] = None
    if excluded in ("0", "1"):
        e_filter = excluded == "1"

    try:
        endpoints = pol.list_endpoints(
            db_path,
            project_id,
            method=method or None,
            host=host or origin or None,
            qualified=q_filter,
            excluded=e_filter,
            search=search or None,
            role_id=role_id,
            priority=priority or None,
        )
    except ValueError:
        return []

    enrich = inventory_enrichment(db_path)
    patterns = rule_id_by_pattern(db_path, project_id)

    out: list[dict] = []
    for e in endpoints:
        eid = e["id"]
        extra = enrich.get(eid, {})
        src = (e.get("source") or "default").lower()
        # Map core source names to operator labels
        if src == "manual":
            priority_source_label = "MANUAL"
        elif src == "rule":
            priority_source_label = "RULE"
        elif src == "auto":
            priority_source_label = "AUTO"
        else:
            priority_source_label = "AUTO"

        matching = e.get("matching_rule")
        row = {
            "id": eid,
            "method": e.get("method"),
            "host": e.get("host_display") or e.get("host"),
            "origin": e.get("origin") or e.get("host"),
            "normalized_path": e.get("normalized_path"),
            "path": e.get("normalized_path"),
            "first_seen": e.get("first_seen"),
            "last_seen": e.get("last_seen"),
            "hit_count": extra.get("hit_count", 0),
            "parameter_count": extra.get(
                "parameter_count", int(e.get("parameter_count") or 0)
            ),
            "roles": ", ".join(e.get("roles_seen") or []) or None,
            "roles_list": e.get("roles_seen") or [],
            "modules": extra.get("modules"),
            "effective_priority": e.get("effective_level"),
            "priority_source": priority_source_label,
            "priority_source_raw": src,
            "manual_priority": e.get("manual_priority"),
            "auto_priority": e.get("effective_level") if src == "auto" else None,
            "matching_rule": matching,
            "priority_rule_id": patterns.get(matching) if matching else None,
            "excluded": bool(e.get("excluded")),
            "exclusion_source": e.get("exclusion_source"),
            "dangerous": bool(e.get("dangerous")),
            "logout": bool(e.get("logout")),
            "qualified": bool(e.get("qualified")),
            "qualification_reason": e.get("qualification_reason"),
            "baseline_flow_id": e.get("baseline_flow_id"),
            "baseline_status": e.get("baseline_status"),
            "tags": e.get("tags") or [],
            "auth_required": bool(e.get("auth_required")),
            "auto_score": e.get("auto_score"),
        }
        row["decision"] = decision_for(row)
        row["state"] = state_for(row)

        if not _passes_extra_filters(
            row,
            priority_source=priority_source,
            dangerous=dangerous,
            logout=logout,
            qualification_reason=qualification_reason,
            module=module,
            tag=tag,
            has_parameters=has_parameters,
            has_baseline=has_baseline,
            baseline_status=baseline_status,
            decision=decision,
            state=state,
            problem=problem,
        ):
            continue
        out.append(row)

    # Sort: hit_count desc, path asc (operator browse order)
    out.sort(
        key=lambda r: (-int(r.get("hit_count") or 0), r.get("normalized_path") or "")
    )
    return out


def _passes_extra_filters(
    row: dict,
    *,
    priority_source: Optional[str],
    dangerous: Optional[str],
    logout: Optional[str],
    qualification_reason: Optional[str],
    module: Optional[str],
    tag: Optional[str],
    has_parameters: Optional[str],
    has_baseline: Optional[str],
    baseline_status: Optional[str],
    decision: Optional[str],
    state: Optional[str],
    problem: Optional[str],
) -> bool:
    if priority_source:
        want = priority_source.upper()
        if row["priority_source"] != want:
            return False
    if dangerous in ("0", "1"):
        if bool(row["dangerous"]) != (dangerous == "1"):
            return False
    if logout in ("0", "1"):
        if bool(row["logout"]) != (logout == "1"):
            return False
    if qualification_reason:
        if (row.get("qualification_reason") or "") != qualification_reason:
            return False
    if module:
        mods = (row.get("modules") or "").split(",")
        mods = [m.strip() for m in mods if m and m.strip()]
        if module not in mods:
            return False
    if tag:
        tags = row.get("tags") or []
        if tag not in tags:
            return False
    if has_parameters in ("0", "1"):
        has = int(row.get("parameter_count") or 0) > 0
        if has != (has_parameters == "1"):
            return False
    if has_baseline in ("0", "1"):
        has = bool(row.get("baseline_flow_id"))
        if has != (has_baseline == "1"):
            return False
    if baseline_status:
        try:
            want_status = int(baseline_status)
        except ValueError:
            want_status = None
        if want_status is not None and row.get("baseline_status") != want_status:
            return False
    if decision:
        if row["decision"] != decision.upper():
            return False
    if state:
        if row["state"] != state.upper():
            return False
    if problem:
        if not _matches_problem(row, problem):
            return False
    return True


def _matches_problem(row: dict, problem: str) -> bool:
    """Policy problem filters for automation debugging."""
    p = problem.lower().replace(" ", "_").replace("-", "_")
    if p in ("why_not_testable", "not_testable"):
        return row["decision"] != "TESTABLE"
    if p == "no_baseline":
        return not row.get("baseline_flow_id")
    if p in ("no_2xx_response", "no_2xx"):
        return row.get("qualification_reason") == "no_2xx_response"
    if p in ("only_redirects",):
        return row.get("qualification_reason") == "only_redirects"
    if p == "dangerous":
        return bool(row.get("dangerous"))
    if p == "logout":
        return bool(row.get("logout"))
    if p in ("excluded_by_endpoint", "excluded_endpoint"):
        return bool(row.get("excluded")) and row.get("exclusion_source") == "endpoint"
    if p in ("excluded_by_rule", "excluded_rule"):
        return bool(row.get("excluded")) and row.get("exclusion_source") == "path_rule"
    if p in ("manual_overrides", "manual"):
        return row.get("priority_source") == "MANUAL"
    if p == "no_flows":
        return row.get("qualification_reason") == "no_flows"
    if p == "unqualified":
        return not row.get("qualified")
    if p == "excluded":
        return bool(row.get("excluded"))
    return True


def inventory_summary(project_id: str) -> dict[str, Any]:
    rows = list_resolved(project_id)
    return {
        "total": len(rows),
        "testable": sum(1 for r in rows if r["decision"] == "TESTABLE"),
        "excluded": sum(1 for r in rows if r["excluded"]),
        "dangerous": sum(1 for r in rows if r["dangerous"]),
        "logout": sum(1 for r in rows if r["logout"]),
        "unqualified": sum(1 for r in rows if not r["qualified"]),
    }


def policy_summary(project_id: str) -> dict[str, Any]:
    rows = list_resolved(project_id)
    by_prio = {"CRITICAL": 0, "HIGH": 0, "NORMAL": 0, "LOW": 0}
    for r in rows:
        level = r.get("effective_priority") or "NORMAL"
        if level in by_prio:
            by_prio[level] += 1
    return {
        "testable": sum(1 for r in rows if r["decision"] == "TESTABLE"),
        "excluded": sum(1 for r in rows if r["excluded"]),
        "unqualified": sum(1 for r in rows if not r["qualified"]),
        "manual_overrides": sum(1 for r in rows if r["priority_source"] == "MANUAL"),
        "rule_controlled": sum(1 for r in rows if r["priority_source"] == "RULE"),
        "auto_controlled": sum(1 for r in rows if r["priority_source"] == "AUTO"),
        "by_priority": by_prio,
        "total": len(rows),
    }


def explain_policy(project_id: str, endpoint_id: str) -> dict[str, Any]:
    db_path = _db_path(project_id)
    if not db.db_exists(db_path):
        return {}
    endpoint = db.query_one(
        db_path, "SELECT * FROM endpoints WHERE id=?", (endpoint_id,)
    )
    if endpoint is None:
        return {}
    pol = policy_mod()
    explanation = pol.explain_endpoint_policy(
        db_path,
        project_id,
        endpoint_id,
        endpoint["normalized_path"],
    )
    origin, host_display = pol.split_origin_identity(endpoint.get("host") or "")
    decision = "TESTABLE"
    if not explanation.get("qualified") or explanation.get("excluded"):
        decision = "SKIPPED"
    # Prefer nested blocks when present
    if explanation.get("qualification"):
        q = explanation["qualification"]
        e = explanation["exclusion"]
        if not q.get("qualified") or e.get("effective"):
            decision = "SKIPPED"
        else:
            decision = "TESTABLE"
    return {
        "endpoint": {
            "id": endpoint_id,
            "method": endpoint.get("method"),
            "origin": origin,
            "host": host_display,
            "path": endpoint.get("normalized_path"),
            "label": (
                f"{endpoint.get('method', '')} "
                f"{origin or host_display}"
                f"{endpoint.get('normalized_path', '')}"
            ),
        },
        "decision": decision,
        **explanation,
    }


def coverage(project_id: str) -> dict[str, Any]:
    rows = list_resolved(project_id)
    total = len(rows) or 1
    n = len(rows)
    qualified = sum(1 for r in rows if r["qualified"])
    with_baseline = sum(1 for r in rows if r.get("baseline_flow_id"))
    with_params = sum(1 for r in rows if int(r.get("parameter_count") or 0) > 0)
    excluded = sum(1 for r in rows if r["excluded"])
    multi_role = sum(1 for r in rows if len(r.get("roles_list") or []) >= 2)

    qual_reasons: dict[str, int] = {}
    for r in rows:
        reason = r.get("qualification_reason") or (
            "flow_2xx" if r["qualified"] else "unknown"
        )
        if r["qualified"]:
            reason = "qualified"
        qual_reasons[reason] = qual_reasons.get(reason, 0) + 1

    # Role observation
    role_counts: dict[str, int] = {}
    coverage_buckets = {"1": 0, "2": 0, "3+": 0}
    for r in rows:
        roles = r.get("roles_list") or []
        for name in roles:
            role_counts[name] = role_counts.get(name, 0) + 1
        rc = len(roles)
        if rc <= 0:
            continue
        if rc == 1:
            coverage_buckets["1"] += 1
        elif rc == 2:
            coverage_buckets["2"] += 1
        else:
            coverage_buckets["3+"] += 1

    all_roles = sorted(role_counts.keys())
    role_table = []
    for r in sorted(
        rows, key=lambda x: (-len(x.get("roles_list") or []), x.get("normalized_path") or "")
    )[:200]:
        roles = set(r.get("roles_list") or [])
        role_table.append({
            "id": r["id"],
            "method": r["method"],
            "path": r["normalized_path"],
            "roles": {name: name in roles for name in all_roles},
            "coverage": f"{len(roles)}/{len(all_roles)}" if all_roles else "0/0",
            "role_count": len(roles),
        })

    # Parameter location breakdown
    db_path = _db_path(project_id)
    param_by_loc: dict[str, int] = {}
    param_heavy: list[dict] = []
    if db.db_exists(db_path):
        for loc_row in db.query_all(
            db_path,
            "SELECT location, COUNT(*) AS c FROM parameters GROUP BY location",
        ):
            param_by_loc[loc_row["location"] or "unknown"] = int(loc_row["c"] or 0)
        param_heavy = db.query_all(
            db_path,
            """
            SELECT e.id, e.method, e.host, e.normalized_path,
                   COUNT(p.id) AS parameter_count
            FROM endpoints e
            JOIN parameters p ON p.endpoint_id = e.id
            GROUP BY e.id
            ORDER BY parameter_count DESC
            LIMIT 50
            """,
        )

    missing_baseline = n - with_baseline
    missing_reasons: dict[str, int] = {}
    for r in rows:
        if r.get("baseline_flow_id"):
            continue
        reason = r.get("qualification_reason") or "unknown"
        missing_reasons[reason] = missing_reasons.get(reason, 0) + 1

    def pct(x: int) -> int:
        return int(round(100 * x / total)) if n else 0

    return {
        "total": n,
        "cards": {
            "qualified_pct": pct(qualified),
            "baseline_pct": pct(with_baseline),
            "multi_role_pct": pct(multi_role),
            "parameters_pct": pct(with_params),
            "excluded_pct": pct(excluded),
            "qualified": qualified,
            "with_baseline": with_baseline,
            "multi_role": multi_role,
            "with_parameters": with_params,
            "excluded": excluded,
        },
        "qualification": {
            "qualified": qualified,
            "no_flows": qual_reasons.get("no_flows", 0),
            "no_2xx_response": qual_reasons.get("no_2xx_response", 0),
            "only_redirects": qual_reasons.get("only_redirects", 0),
            "is_dangerous": qual_reasons.get("is_dangerous", 0),
            "is_logout": qual_reasons.get("is_logout", 0),
            "by_reason": qual_reasons,
        },
        "baseline": {
            "ready": with_baseline,
            "missing": missing_baseline,
            "missing_by_reason": missing_reasons,
        },
        "roles": {
            "by_role": [
                {"name": k, "endpoints": v}
                for k, v in sorted(role_counts.items(), key=lambda x: -x[1])
            ],
            "coverage_buckets": coverage_buckets,
            "role_names": all_roles,
            "table": role_table,
        },
        "parameters": {
            "endpoints_with_parameters": with_params,
            "by_location": param_by_loc,
            "heavy": param_heavy,
        },
    }


def rules_with_impact(project_id: str) -> list[dict]:
    """List path rules enriched with match counts from live preview."""
    db_path = _db_path(project_id)
    if not db.db_exists(db_path):
        return []
    pol = policy_mod()
    rules = pol.list_path_rules(db_path, project_id)
    out = []
    for rule in rules:
        preview = pol.preview_path_rule_impact(
            db_path,
            project_id,
            rule["pattern"],
            priority=rule.get("priority"),
            excluded=bool(rule.get("excluded")) or None,
        )
        matches = preview.get("matching_count", 0)
        # Count how many matching endpoints also match another rule
        multi = 0
        if matches:
            from fnmatch import fnmatch

            other_patterns = [
                r["pattern"] for r in rules if r["id"] != rule["id"]
            ]
            for ep in preview.get("endpoints") or []:
                path = ep.get("path") or ""
                for op in other_patterns:
                    if fnmatch(path, op):
                        multi += 1
                        break
        effect_parts = []
        if rule.get("priority"):
            effect_parts.append(f"priority {rule['priority']}")
        if rule.get("excluded"):
            effect_parts.append("exclude")
        out.append({
            **rule,
            "matches": matches,
            "multi_rule_matches": multi,
            "effect": ", ".join(effect_parts) if effect_parts else "—",
            "priority_changes": (preview.get("proposed") or {}).get(
                "priority_changes", 0
            ),
            "newly_excluded": (preview.get("proposed") or {}).get(
                "newly_excluded", 0
            ),
        })
    return out


def parse_bulk_stdout(stdout: str) -> dict[str, Any]:
    """Parse CLI --format json bulk mutation result from last non-empty stdout."""
    text = (stdout or "").strip()
    if not text:
        return {}
    # CLI may print multiple documents; take last JSON object.
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # Try last {...} block
        start = text.rfind("{")
        if start >= 0:
            try:
                return json.loads(text[start:])
            except json.JSONDecodeError:
                return {}
        return {}
