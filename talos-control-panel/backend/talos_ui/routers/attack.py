from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from .. import cli, config, db
from . import attack_auth_session

router = APIRouter(prefix="/api/attack", tags=["attack"])

# Auth-Session Testing (helpers live in attack_auth_session.py — K20).
router.include_router(attack_auth_session.router)

BAC_TECHNIQUES = [
    "session-swap", "method-fuzz", "content-type", "url-fuzz",
    "header-inject", "host-fuzz", "role-inject", "parser-confuse",
]

# Fallback technique names when Core import is unavailable.
# Keep in sync with talos.projects.unauth.variants.UNAUTH_TECHNIQUES.
UNAUTH_TECHNIQUE_NAMES = [
    "baseline",
    "empty_auth",
    "malformed_auth",
    "auth_null",
    "auth_whitespace",
    "duplicate_empty_header",
    "duplicate_malformed_header",
]

# Backward-compatible alias used by run validation / tests.
UNAUTH_TECHNIQUES = UNAUTH_TECHNIQUE_NAMES


def _load_unauth_technique_meta() -> list[dict]:
    """
    Build technique picker metadata from Core recipes/variants when available.
    Each entry: name, description, mutation_family, recipe_count.
    """
    try:
        from talos.projects.unauth.recipes import UNAUTH_RECIPES
        from talos.projects.unauth.variants import UNAUTH_TECHNIQUES as CORE_TECHS
    except Exception:
        return [
            {
                "name": name,
                "description": "",
                "mutation_family": "",
                "recipe_count": 1 if name != "baseline" else 1,
            }
            for name in UNAUTH_TECHNIQUE_NAMES
        ]

    recipe_counts: dict[str, int] = {}
    for recipe in UNAUTH_RECIPES:
        tech = recipe.get("technique") or ""
        if tech:
            recipe_counts[tech] = recipe_counts.get(tech, 0) + 1

    out: list[dict] = []
    for tech in CORE_TECHS:
        name = tech.get("name") or ""
        if not name:
            continue
        out.append(
            {
                "name": name,
                "description": tech.get("description") or "",
                "mutation_family": tech.get("mutation_family") or "",
                "recipe_count": recipe_counts.get(name, 0),
            }
        )
    # Preserve known order if Core list is empty somehow.
    if not out:
        for name in UNAUTH_TECHNIQUE_NAMES:
            out.append(
                {
                    "name": name,
                    "description": "",
                    "mutation_family": "",
                    "recipe_count": recipe_counts.get(name, 0),
                }
            )
    return out


def _total_recipe_count() -> int:
    try:
        from talos.projects.unauth.recipes import UNAUTH_RECIPES

        return len(UNAUTH_RECIPES)
    except Exception:
        return len(UNAUTH_TECHNIQUE_NAMES)


def _count_testable_endpoints(db_path, project_id: str) -> int:
    """
    Same inclusion rules as talos.projects.unauth.cli._get_testable_flows:
    qualified, not logout/dangerous/excluded, baseline flow present.
    """
    try:
        row = db.query_one(
            db_path,
            """
            SELECT COUNT(*) AS n
            FROM endpoints e
            JOIN endpoint_policy ep ON ep.endpoint_id = e.id
            WHERE e.project_id = ?
              AND ep.qualified  = 1
              AND ep.logout     = 0
              AND ep.dangerous  = 0
              AND ep.excluded   = 0
              AND ep.baseline_flow_id IS NOT NULL
            """,
            (project_id,),
        )
        return int(row["n"]) if row else 0
    except Exception:
        return 0


def _unauth_job_counts(db_path) -> dict[str, int]:
    try:
        rows = db.query_all(
            db_path,
            """
            SELECT status, COUNT(*) AS n
            FROM scheduler_jobs
            WHERE job_type = 'unauth_attack'
            GROUP BY status
            """,
        )
        return {r["status"]: int(r["n"]) for r in rows}
    except Exception:
        return {}


def _read_unauth_auto_run(db_path) -> dict:
    """Effective auto-run flag via Core attack_config helper (layered)."""
    try:
        from talos.projects.attack_config import get_unauth_auto_run

        enabled = bool(get_unauth_auto_run(db_path))
        return {"enabled": enabled, "source": "effective"}
    except Exception:
        return {"enabled": False, "source": "default"}


# ------------------------------------------------------------------ #
# Unauth                                                               #
# ------------------------------------------------------------------ #

@router.get("/unauth/techniques")
def unauth_techniques():
    """
    Known Unauth technique metadata for UI pickers (matches CLI --technique).

    Returns both a flat name list (backward compatible) and enriched objects.
    """
    meta = _load_unauth_technique_meta()
    names = [t["name"] for t in meta] or list(UNAUTH_TECHNIQUE_NAMES)
    return {
        "techniques": names,
        "items": meta,
        "total_recipes": _total_recipe_count(),
    }


@router.get("/unauth/results")
def unauth_results(
    project_id: str,
    verdict: str | None = None,
    auth_mutation: str | None = None,
    request_mutation: str | None = None,
    search: str | None = None,
    limit: int = 200,
):
    record = db.get_project_record(project_id)
    db_path = config.project_db_path(project_id, record)

    clauses: list[str] = []
    params: list = []
    if verdict:
        clauses.append("ur.verdict = ?")
        params.append(verdict)
    if auth_mutation:
        clauses.append("ur.auth_mutation = ?")
        params.append(auth_mutation)
    if request_mutation:
        # Treat empty string filter as "no request mutation" (NULL or '').
        if request_mutation in ("—", "-", "__none__"):
            clauses.append("(ur.request_mutation IS NULL OR ur.request_mutation = '')")
        else:
            clauses.append("ur.request_mutation = ?")
            params.append(request_mutation)
    if search:
        q = f"%{search.strip()}%"
        clauses.append("(f.path LIKE ? OR f.host LIKE ? OR f.method LIKE ?)")
        params.extend([q, q, q])

    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    params.append(min(max(limit, 1), 1000))

    rows = db.query_all(
        db_path,
        f"""
        SELECT ur.*, f.method, f.path, f.status_code, f.host, f.captured_at
        FROM unauth_results ur
        JOIN flows f ON f.id = ur.replay_flow_id
        {where}
        ORDER BY f.captured_at DESC LIMIT ?
        """,
        tuple(params),
    )
    return {"results": rows}


@router.get("/unauth/summary")
def unauth_summary(project_id: str):
    record = db.get_project_record(project_id)
    db_path = config.project_db_path(project_id, record)
    rows = db.query_all(db_path, "SELECT verdict, COUNT(*) AS n FROM unauth_results GROUP BY verdict")
    return {"counts": {r["verdict"]: r["n"] for r in rows}}


@router.get("/unauth/overview")
def unauth_overview(project_id: str, top_n: int = 8):
    """
    Aggregate for the Unauth workspace Overview tab.

    Read-only: verdict counts, testable endpoints, recipe totals,
    unauth_attack job pressure, auto-run flag, recent BYPASS samples.
    """
    record = db.get_project_record(project_id)
    db_path = config.project_db_path(project_id, record)
    top_n = min(max(top_n, 1), 50)

    counts: dict[str, int] = {}
    recent_bypass: list[dict] = []
    try:
        rows = db.query_all(
            db_path,
            "SELECT verdict, COUNT(*) AS n FROM unauth_results GROUP BY verdict",
        )
        counts = {r["verdict"]: r["n"] for r in rows}
        recent_bypass = db.query_all(
            db_path,
            """
            SELECT ur.replay_flow_id, ur.verdict, ur.auth_mutation, ur.request_mutation,
                   ur.auth_mutation_family, f.method, f.path, f.host, f.status_code,
                   f.captured_at
            FROM unauth_results ur
            JOIN flows f ON f.id = ur.replay_flow_id
            WHERE ur.verdict = 'BYPASS'
            ORDER BY f.captured_at DESC
            LIMIT ?
            """,
            (top_n,),
        )
    except Exception:
        counts = {}
        recent_bypass = []

    testable = _count_testable_endpoints(db_path, project_id)
    jobs = _unauth_job_counts(db_path)
    total_recipes = _total_recipe_count()
    technique_meta = _load_unauth_technique_meta()
    auto_run = _read_unauth_auto_run(db_path)

    total_results = sum(counts.values())
    pending = int(jobs.get("pending") or 0)
    running = int(jobs.get("running") or 0)

    empty_state = {
        "no_testable": testable == 0,
        "no_results": total_results == 0,
        "jobs_in_flight": (pending + running) > 0,
    }

    return {
        "counts": counts,
        "testable_endpoints": testable,
        "total_recipes": total_recipes,
        "estimated_jobs_all": testable * total_recipes,
        "jobs": jobs,
        "jobs_pending": pending,
        "jobs_running": running,
        "auto_run": auto_run,
        "techniques": technique_meta,
        "recent_bypass": recent_bypass,
        "empty_state": empty_state,
    }


class UnauthRunBody(BaseModel):
    """Optional technique restricts to one Unauth recipe family (CLI --technique)."""
    technique: str | None = None
    flows: list[str] | None = None


@router.post("/unauth/run")
def run_unauth(project_id: str, body: UnauthRunBody):
    args = ["attack", "unauth", "run"]
    if body.technique:
        tech = body.technique.strip()
        if tech not in UNAUTH_TECHNIQUES:
            raise HTTPException(
                400,
                f"unknown unauth technique '{tech}'; "
                f"expected one of: {', '.join(UNAUTH_TECHNIQUES)}",
            )
        args += ["--technique", tech]
    for fid in [f.strip() for f in (body.flows or []) if f and f.strip()]:
        args += ["--flow", fid]
    results = cli.run_scoped(project_id, args)
    return {"steps": [r.to_dict() for r in results]}


@router.post("/unauth/filter/init")
def unauth_filter_init(project_id: str):
    results = cli.run_scoped(project_id, ["attack", "unauth", "filter", "init"])
    return {"steps": [r.to_dict() for r in results]}


@router.post("/unauth/filter/show")
def unauth_filter_show(project_id: str):
    results = cli.run_scoped(project_id, ["attack", "unauth", "filter", "show"])
    return {"steps": [r.to_dict() for r in results]}


@router.post("/unauth/filter/validate")
def unauth_filter_validate(project_id: str):
    results = cli.run_scoped(project_id, ["attack", "unauth", "filter", "validate"])
    return {"steps": [r.to_dict() for r in results]}


class UnauthFilterApplyBody(BaseModel):
    """Offline re-apply of unauth-decision-filter.yaml to stored results."""
    dry_run: bool = True
    force: bool = False


@router.post("/unauth/filter/apply")
def unauth_filter_apply(project_id: str, body: UnauthFilterApplyBody):
    """
    Re-evaluate stored unauth_results against the current decision filter.
    Returns a structured ApplySummary (native core call — not CLI stdout).
    dry_run=True (default) previews; force=True also rejects CONFIRMED findings.
    """
    record = db.get_project_record(project_id)
    db_path = config.project_db_path(project_id, record)
    data_dir = config.project_data_dir(project_id, record)
    try:
        from talos.projects.unauth.reclassify import (
            FilterApplyError,
            apply_unauth_decision_filter,
        )
    except ImportError as exc:
        raise HTTPException(500, f"Core reclassify unavailable: {exc}") from exc

    try:
        summary = apply_unauth_decision_filter(
            db_path,
            data_dir,
            dry_run=body.dry_run,
            include_confirmed=body.force,
        )
    except FilterApplyError as exc:
        raise HTTPException(400, str(exc)) from exc
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(500, f"Filter apply failed: {exc}") from exc

    return summary.to_dict()


# ------------------------------------------------------------------ #
# BAC                                                                  #
# ------------------------------------------------------------------ #

# CLI technique name → scheduler job_type / VARIANTS_BY_ATTACK key.
BAC_TECHNIQUE_TO_JOB: dict[str, str] = {
    "session-swap": "bac_session_swap",
    "method-fuzz": "bac_method_fuzz",
    "content-type": "bac_content_type",
    "url-fuzz": "bac_url_fuzz",
    "header-inject": "bac_header_inject",
    "host-fuzz": "bac_host_fuzz",
    "role-inject": "bac_role_inject",
    "parser-confuse": "bac_parser_confuse",
}

# Short descriptions for technique pickers (aligned with CLI help).
BAC_TECHNIQUE_DESCRIPTIONS: dict[str, str] = {
    "session-swap": (
        "Replay target-role flows with the attacker role's session token "
        "(direct horizontal/vertical access control)."
    ),
    "method-fuzz": (
        "HTTP method changes and X-HTTP-Method-Override injection."
    ),
    "content-type": (
        "Content-Type confusion (JSON↔form, multipart, invalid types)."
    ),
    "url-fuzz": (
        "Path manipulations: trailing slash, encoding, case, dot segments."
    ),
    "header-inject": (
        "Proxy/routing headers (X-Original-URL, X-Forwarded-*, X-Real-IP)."
    ),
    "host-fuzz": (
        "Host header swaps (example.com, localhost, 127.0.0.1)."
    ),
    "role-inject": (
        "Privilege-escalation params/headers (isAdmin, role=admin, …)."
    ),
    "parser-confuse": (
        "Parser discrepancies: HPP, duplicate headers, TE/CL conflicts."
    ),
}


def _load_bac_technique_meta(db_path=None) -> list[dict]:
    """
    Technique picker metadata for the BAC workspace.

    Each entry: name (CLI subcommand), description, attack_type (job key),
    variant_count, variants (name + description).
    """
    variants_by_attack: dict[str, list] = {}
    auth_mode = "artifacts"
    try:
        from talos.projects.auth_mode import resolve_auth_mode
        from talos.projects.bac.variants import variants_for_auth_mode

        if db_path is not None:
            auth_mode = resolve_auth_mode(db_path)
        for name in BAC_TECHNIQUES:
            job_type = BAC_TECHNIQUE_TO_JOB.get(name, f"bac_{name.replace('-', '_')}")
            variants_by_attack[job_type] = variants_for_auth_mode(job_type, auth_mode)
    except Exception:
        try:
            from talos.projects.bac.variants import VARIANTS_BY_ATTACK

            variants_by_attack = VARIANTS_BY_ATTACK
        except Exception:
            variants_by_attack = {}

    out: list[dict] = []
    for name in BAC_TECHNIQUES:
        job_type = BAC_TECHNIQUE_TO_JOB.get(name, f"bac_{name.replace('-', '_')}")
        variants = variants_by_attack.get(job_type) or []
        variant_items = [
            {
                "name": v.get("name") or "",
                "description": v.get("description") or "",
                "mutation": v.get("mutation") or "",
            }
            for v in variants
            if isinstance(v, dict)
        ]
        out.append(
            {
                "name": name,
                "description": BAC_TECHNIQUE_DESCRIPTIONS.get(name, ""),
                "attack_type": job_type,
                "variant_count": len(variant_items) if variant_items else max(len(variants), 1),
                "variants": variant_items,
            }
        )
    return out


def _bac_job_counts(db_path) -> dict[str, int]:
    try:
        rows = db.query_all(
            db_path,
            """
            SELECT status, COUNT(*) AS n
            FROM scheduler_jobs
            WHERE job_type LIKE 'bac_%'
            GROUP BY status
            """,
        )
        return {r["status"]: int(r["n"]) for r in rows}
    except Exception:
        return {}


def _scan_bac_candidates(
    db_path,
    project_id: str,
    attacker_role_id: str | None = None,
    endpoint_id: str | None = None,
    module_id: str | None = None,
) -> list:
    """Read-only candidate scan; empty list when Core unavailable or no data."""
    try:
        from talos.projects.bac.candidates import collect_bac_candidates

        return list(
            collect_bac_candidates(
                db_path,
                project_id,
                attacker_role_id=attacker_role_id,
                endpoint_id=endpoint_id,
                module_id=module_id,
            )
        )
    except Exception:
        return []


def _bac_candidate_summary(candidates: list) -> dict:
    flow_total = 0
    attacker_roles: set[str] = set()
    target_roles: set[str] = set()
    modules: set[str] = set()
    by_source: dict[str, int] = {}
    for c in candidates:
        flow_ids = getattr(c, "flow_ids", None) or []
        flow_total += len(flow_ids)
        if getattr(c, "attacker_role_name", None):
            attacker_roles.add(c.attacker_role_name)
        if getattr(c, "target_role_name", None):
            target_roles.add(c.target_role_name)
        if getattr(c, "module_name", None):
            modules.add(c.module_name)
        src = getattr(c, "source", None) or "access_map"
        by_source[src] = by_source.get(src, 0) + 1
    return {
        "candidate_count": len(candidates),
        "flow_count": flow_total,
        "attacker_roles": sorted(attacker_roles),
        "target_roles": sorted(target_roles),
        "modules": sorted(modules),
        "by_source": by_source,
    }


def _bac_auth_readiness(db_path, project_id: str, candidates: list) -> dict:
    """
    Check auth prerequisites once per distinct attacker role (no auto-generate).
    """
    roles: dict[str, dict] = {}
    for c in candidates:
        rid = getattr(c, "attacker_role_id", None)
        rname = getattr(c, "attacker_role_name", None) or rid
        if not rid or rid in roles:
            continue
        roles[rid] = {"role_id": rid, "role_name": rname, "passed": False, "errors": []}

    try:
        from talos.projects.bac.auth_prereq import check_auth_prereqs
    except Exception:
        return {
            "roles": list(roles.values()),
            "passed_count": 0,
            "failed_count": len(roles),
            "all_passed": len(roles) == 0,
        }

    for rid, info in roles.items():
        try:
            result = check_auth_prereqs(
                db_path=db_path,
                project_id=project_id,
                role_id=rid,
                role_name=info["role_name"],
                auto_generate=False,
            )
            info["passed"] = bool(result.passed)
            info["errors"] = list(getattr(result, "errors", None) or [])
        except Exception as exc:  # noqa: BLE001
            info["passed"] = False
            info["errors"] = [str(exc)]

    passed = sum(1 for r in roles.values() if r["passed"])
    failed = len(roles) - passed
    return {
        "roles": list(roles.values()),
        "passed_count": passed,
        "failed_count": failed,
        "all_passed": failed == 0 and len(roles) > 0,
    }


def _bac_build_args(
    technique: str,
    role: str | None = None,
    module: str | None = None,
    endpoint: str | None = None,
    flows: list[str] | None = None,
    exclude_endpoints: list[str] | None = None,
    auto_generate: bool = False,
) -> list[str]:
    """Build argv for one `talos attack bac <technique>` invocation."""
    args = ["attack", "bac", technique]
    if role:
        args += ["--role", role.strip()]
    if module:
        args += ["--module", module.strip()]
    if endpoint:
        args += ["--endpoint", endpoint.strip()]
    for fid in [f.strip() for f in (flows or []) if f and f.strip()]:
        args += ["--flow", fid]
    for eid in [e.strip() for e in (exclude_endpoints or []) if e and e.strip()]:
        args += ["--exclude-endpoint", eid]
    if auto_generate:
        args.append("--auto-generate")
    return args


def _bac_validate_scope(
    module: str | None,
    endpoint: str | None,
    flows: list[str] | None = None,
) -> None:
    flow_ids = [f.strip() for f in (flows or []) if f and f.strip()]
    scopes = [name for name, val in (
        ("--module", module),
        ("--endpoint", endpoint),
        ("--flow", flow_ids),
    ) if val]
    if len(scopes) > 1:
        raise HTTPException(
            400,
            f"{' and '.join(scopes)} are mutually exclusive; choose one scope.",
        )


def _bac_resolve_techniques(techniques: list[str] | None) -> list[str]:
    """Empty/omit → all techniques in stable BAC_TECHNIQUES order."""
    if not techniques:
        return list(BAC_TECHNIQUES)
    resolved: list[str] = []
    unknown: list[str] = []
    seen: set[str] = set()
    for raw in techniques:
        name = (raw or "").strip()
        if not name:
            continue
        if name not in BAC_TECHNIQUES:
            unknown.append(name)
            continue
        if name not in seen:
            seen.add(name)
            resolved.append(name)
    if unknown:
        raise HTTPException(
            400,
            f"unknown bac technique(s): {', '.join(unknown)}; "
            f"expected one of: {', '.join(BAC_TECHNIQUES)}",
        )
    if not resolved:
        return list(BAC_TECHNIQUES)
    # Preserve CLI order rather than request order for stable multi-run.
    return [t for t in BAC_TECHNIQUES if t in seen]


@router.get("/bac/techniques")
def bac_techniques(project_id: str | None = None):
    """
    Known BAC technique metadata for UI pickers (matches CLI subcommands).
    When project_id is set, NTLM projects drop artifact-only variants.
    """
    db_path = None
    if project_id:
        record = db.get_project_record(project_id)
        if record:
            db_path = config.project_db_path(project_id, record)
    meta = _load_bac_technique_meta(db_path)
    names = [t["name"] for t in meta]
    return {
        "techniques": names,
        "items": meta,
        "total_variants": sum(int(t.get("variant_count") or 0) for t in meta),
    }


@router.get("/bac/results")
def bac_results(
    project_id: str,
    verdict: str | None = None,
    attack_type: str | None = None,
    module_name: str | None = None,
    attacker_role: str | None = None,
    search: str | None = None,
    limit: int = 200,
):
    record = db.get_project_record(project_id)
    db_path = config.project_db_path(project_id, record)

    clauses: list[str] = []
    params: list = []
    if verdict:
        clauses.append("br.verdict = ?")
        params.append(verdict)
    if attack_type:
        # Accept either job type (bac_session_swap) or CLI name (session-swap).
        job = BAC_TECHNIQUE_TO_JOB.get(attack_type, attack_type)
        clauses.append("br.attack_type = ?")
        params.append(job)
    if module_name:
        clauses.append("mo.name = ?")
        params.append(module_name)
    if attacker_role:
        clauses.append("ar.name = ?")
        params.append(attacker_role)
    if search:
        q = f"%{search.strip()}%"
        clauses.append("(f.path LIKE ? OR f.host LIKE ? OR f.method LIKE ?)")
        params.extend([q, q, q])

    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    params.append(min(max(limit, 1), 1000))

    rows = db.query_all(
        db_path,
        f"""
        SELECT br.*, f.method, f.path, f.status_code, f.host, f.captured_at,
               ar.name AS attacker_role_name, tr.name AS target_role_name, mo.name AS module_name
        FROM bac_results br
        JOIN flows f ON f.id = br.replay_flow_id
        LEFT JOIN roles ar ON ar.id = br.attacker_role_id
        LEFT JOIN roles tr ON tr.id = br.target_role_id
        LEFT JOIN modules mo ON mo.id = br.module_id
        {where}
        ORDER BY f.captured_at DESC LIMIT ?
        """,
        tuple(params),
    )
    return {"results": rows}


@router.get("/bac/summary")
def bac_summary(project_id: str):
    record = db.get_project_record(project_id)
    db_path = config.project_db_path(project_id, record)
    rows = db.query_all(db_path, "SELECT verdict, COUNT(*) AS n FROM bac_results GROUP BY verdict")
    return {"counts": {r["verdict"]: r["n"] for r in rows}}


@router.get("/bac/overview")
def bac_overview(project_id: str, top_n: int = 8):
    """
    Aggregate for the BAC workspace Overview tab.

    Read-only: verdict counts, access-matrix candidates, variant totals,
    bac_* job pressure, auth readiness, recent POSSIBLE_BAC samples.
    """
    record = db.get_project_record(project_id)
    db_path = config.project_db_path(project_id, record)
    top_n = min(max(top_n, 1), 50)

    counts: dict[str, int] = {}
    recent_possible: list[dict] = []
    try:
        rows = db.query_all(
            db_path,
            "SELECT verdict, COUNT(*) AS n FROM bac_results GROUP BY verdict",
        )
        counts = {r["verdict"]: r["n"] for r in rows}
        recent_possible = db.query_all(
            db_path,
            """
            SELECT br.replay_flow_id, br.verdict, br.attack_type, br.variant,
                   br.mutation_family, br.mutation,
                   f.method, f.path, f.host, f.status_code, f.captured_at,
                   ar.name AS attacker_role_name, tr.name AS target_role_name,
                   mo.name AS module_name
            FROM bac_results br
            JOIN flows f ON f.id = br.replay_flow_id
            LEFT JOIN roles ar ON ar.id = br.attacker_role_id
            LEFT JOIN roles tr ON tr.id = br.target_role_id
            LEFT JOIN modules mo ON mo.id = br.module_id
            WHERE br.verdict = 'POSSIBLE_BAC'
            ORDER BY f.captured_at DESC
            LIMIT ?
            """,
            (top_n,),
        )
    except Exception:
        counts = {}
        recent_possible = []

    candidates = _scan_bac_candidates(db_path, project_id)
    cand_summary = _bac_candidate_summary(candidates)
    auth = _bac_auth_readiness(db_path, project_id, candidates)
    jobs = _bac_job_counts(db_path)
    technique_meta = _load_bac_technique_meta(db_path)
    total_variants = sum(int(t.get("variant_count") or 0) for t in technique_meta)
    flow_count = int(cand_summary.get("flow_count") or 0)
    estimated_jobs_all = flow_count * total_variants

    total_results = sum(counts.values())
    pending = int(jobs.get("pending") or 0)
    running = int(jobs.get("running") or 0)

    empty_state = {
        "no_candidates": cand_summary["candidate_count"] == 0,
        "no_results": total_results == 0,
        "jobs_in_flight": (pending + running) > 0,
        "auth_failed": int(auth.get("failed_count") or 0) > 0
        and cand_summary["candidate_count"] > 0,
    }

    auth_model = {}
    try:
        from talos.projects.auth_mode import AUTH_MODE_LABELS, resolve_auth_mode

        mode = resolve_auth_mode(db_path)
        auth_model = {
            "mode": mode,
            "label": AUTH_MODE_LABELS.get(mode, mode),
            "identity": (
                "ntlm_profile" if mode == "platform_ntlm" else "session_token"
            ),
        }
    except Exception:
        auth_model = {
            "mode": "artifacts",
            "label": "Cookie / header session",
            "identity": "session_token",
        }

    return {
        "counts": counts,
        "candidates": cand_summary,
        "total_variants": total_variants,
        "estimated_jobs_all": estimated_jobs_all,
        "jobs": jobs,
        "jobs_pending": pending,
        "jobs_running": running,
        "auth": auth,
        "auth_model": auth_model,
        "techniques": technique_meta,
        "recent_possible": recent_possible,
        "empty_state": empty_state,
    }


class BacRunBody(BaseModel):
    """Shared body for single-technique and multi-technique BAC enqueue."""

    role: str | None = None
    module: str | None = None
    endpoint: str | None = None
    flows: list[str] | None = None
    exclude_endpoints: list[str] | None = None
    auto_generate: bool = False
    # Multi-run only (POST /bac/run). null/omit/[] => all techniques.
    techniques: list[str] | None = None


@router.post("/bac/run")
def run_bac_multi(project_id: str, body: BacRunBody):
    """
    Enqueue one or more BAC technique families.

    Default (no techniques): all eight CLI subcommands, sequential
    `talos attack bac <technique>` invocations with shared scope flags.
    """
    _bac_validate_scope(body.module, body.endpoint, body.flows)
    techniques = _bac_resolve_techniques(body.techniques)

    all_steps: list[dict] = []
    previews: list[str] = []
    for tech in techniques:
        args = _bac_build_args(
            tech,
            role=body.role,
            module=body.module,
            endpoint=body.endpoint,
            flows=body.flows,
            exclude_endpoints=body.exclude_endpoints,
            auto_generate=body.auto_generate,
        )
        previews.append("talos " + " ".join(args))
        results = cli.run_scoped(project_id, args)
        all_steps.extend(r.to_dict() for r in results)

    return {
        "steps": all_steps,
        "techniques_run": techniques,
        "cli_previews": previews,
    }


@router.post("/bac/{technique}")
def run_bac(project_id: str, technique: str, body: BacRunBody):
    if technique not in BAC_TECHNIQUES:
        raise HTTPException(
            400,
            f"unknown technique '{technique}'; "
            f"expected one of: {', '.join(BAC_TECHNIQUES)}",
        )
    _bac_validate_scope(body.module, body.endpoint, body.flows)
    args = _bac_build_args(
        technique,
        role=body.role,
        module=body.module,
        endpoint=body.endpoint,
        flows=body.flows,
        exclude_endpoints=body.exclude_endpoints,
        auto_generate=body.auto_generate,
    )
    results = cli.run_scoped(project_id, args)
    return {
        "steps": [r.to_dict() for r in results],
        "techniques_run": [technique],
        "cli_previews": ["talos " + " ".join(args)],
    }


@router.post("/bac/filter/init")
def bac_filter_init(project_id: str):
    results = cli.run_scoped(project_id, ["attack", "bac", "filter", "init"])
    return {"steps": [r.to_dict() for r in results]}


@router.post("/bac/filter/show")
def bac_filter_show(project_id: str):
    results = cli.run_scoped(project_id, ["attack", "bac", "filter", "show"])
    return {"steps": [r.to_dict() for r in results]}


@router.post("/bac/filter/validate")
def bac_filter_validate(project_id: str):
    results = cli.run_scoped(project_id, ["attack", "bac", "filter", "validate"])
    return {"steps": [r.to_dict() for r in results]}


class BacFilterApplyBody(BaseModel):
    """Offline re-apply of BAC-decision-filter.yaml to stored results."""
    dry_run: bool = True
    force: bool = False


@router.post("/bac/filter/apply")
def bac_filter_apply(project_id: str, body: BacFilterApplyBody):
    """
    Re-evaluate stored bac_results against the current decision filter.
    Returns a structured ApplySummary (native core call — not CLI stdout).
    dry_run=True (default) previews; force=True also rejects CONFIRMED findings.
    """
    record = db.get_project_record(project_id)
    db_path = config.project_db_path(project_id, record)
    data_dir = config.project_data_dir(project_id, record)
    try:
        from talos.projects.bac.reclassify import (
            FilterApplyError,
            apply_bac_decision_filter,
        )
    except ImportError as exc:
        raise HTTPException(500, f"Core reclassify unavailable: {exc}") from exc

    try:
        summary = apply_bac_decision_filter(
            db_path,
            data_dir,
            dry_run=body.dry_run,
            include_confirmed=body.force,
        )
    except FilterApplyError as exc:
        raise HTTPException(400, str(exc)) from exc
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(500, f"Filter apply failed: {exc}") from exc

    return summary.to_dict()


# ------------------------------------------------------------------ #
# CORS misconfiguration                                                #
# ------------------------------------------------------------------ #

CORS_TECHNIQUE_FALLBACK = [
    "baseline_origin",
    "arbitrary_https",
    "arbitrary_http",
    "attacker_subdomain",
    "subdomain_of_target",
    "prefix_bypass",
    "suffix_bypass",
    "trusted_plus",
    "unescaped_dot",
    "encoded_dot",
    "underscore",
    "null_origin",
    "wildcard_origin",
    "localhost",
    "loopback",
    "scheme_downgrade",
    "port_443",
    "port_80",
    "port_8080",
    "preflight",
]


def _load_cors_technique_meta() -> list[dict]:
    """Purpose: Technique picker from Core catalogue when importable."""
    try:
        from talos.cors.models import TECHNIQUE_CATALOG

        return [dict(item) for item in TECHNIQUE_CATALOG]
    except Exception:
        return [
            {"name": name, "family": "", "description": ""}
            for name in CORS_TECHNIQUE_FALLBACK
        ]


def _cors_job_counts(db_path) -> dict[str, int]:
    try:
        rows = db.query_all(
            db_path,
            """
            SELECT status, COUNT(*) AS n
            FROM scheduler_jobs
            WHERE job_type = 'cors_attack'
            GROUP BY status
            """,
        )
        return {r["status"]: int(r["n"]) for r in rows}
    except Exception:
        return {}


def _count_cors_candidates(db_path, record) -> int:
    """Purpose: Same selection rules as talos attack cors candidates."""
    try:
        from talos.cors.candidates import (
            DEFAULT_CANDIDATE_LIMIT,
            select_cors_candidates,
        )

        scope: list[str] = []
        if isinstance(record, dict):
            scope = list(record.get("scope") or [])
        elif record is not None:
            scope = list(getattr(record, "scope", None) or [])
        return len(
            select_cors_candidates(
                db_path,
                in_scope_prefixes=scope,
                limit=DEFAULT_CANDIDATE_LIMIT,
            )
        )
    except Exception:
        return 0


@router.get("/cors/techniques")
def cors_techniques():
    """CORS Origin technique catalogue (matches CLI --technique)."""
    meta = _load_cors_technique_meta()
    return {
        "techniques": [t["name"] for t in meta],
        "items": meta,
        "total_techniques": len(meta),
    }


@router.get("/cors/results")
def cors_results(
    project_id: str,
    verdict: str | None = None,
    technique: str | None = None,
    host: str | None = None,
    limit: int = 200,
):
    record = db.get_project_record(project_id)
    db_path = config.project_db_path(project_id, record)
    try:
        from talos.cors.db import list_cors_results

        rows = list_cors_results(
            db_path,
            verdict=verdict,
            technique=technique,
            host=host,
            limit=limit,
        )
    except Exception:
        rows = []
    return {"results": rows}


@router.get("/cors/summary")
def cors_summary(project_id: str):
    record = db.get_project_record(project_id)
    db_path = config.project_db_path(project_id, record)
    try:
        from talos.cors.db import count_cors_verdicts

        counts = count_cors_verdicts(db_path)
    except Exception:
        counts = {}
    return {"counts": counts}


@router.get("/cors/overview")
def cors_overview(project_id: str, top_n: int = 8):
    """Aggregate for the CORS workspace Overview tab."""
    record = db.get_project_record(project_id)
    db_path = config.project_db_path(project_id, record)
    top_n = min(max(top_n, 1), 50)

    counts: dict[str, int] = {}
    recent: list[dict] = []
    try:
        from talos.cors.db import count_cors_verdicts, list_cors_results

        counts = count_cors_verdicts(db_path)
        recent = list_cors_results(db_path, verdict="CORS_MISCONFIG", limit=top_n)
    except Exception:
        counts = {}
        recent = []

    jobs = _cors_job_counts(db_path)
    pending = int(jobs.get("pending") or 0)
    running = int(jobs.get("running") or 0)
    techniques = _load_cors_technique_meta()
    candidates = _count_cors_candidates(db_path, record)
    total_results = sum(counts.values())

    return {
        "counts": counts,
        "candidates": candidates,
        "total_techniques": len(techniques),
        "estimated_jobs_all": candidates * len(techniques),
        "jobs": jobs,
        "jobs_pending": pending,
        "jobs_running": running,
        "techniques": techniques,
        "recent_issues": recent,
        "empty_state": {
            "no_candidates": candidates == 0,
            "no_results": total_results == 0,
            "jobs_in_flight": (pending + running) > 0,
        },
    }


class CorsRunBody(BaseModel):
    """Optional technique / scope mirrors talos attack cors run."""
    technique: str | None = None
    limit: int | None = None
    endpoint: str | None = None
    host: str | None = None
    flows: list[str] | None = None
    right_now: bool = False


@router.post("/cors/run")
def run_cors(project_id: str, body: CorsRunBody):
    known = {t["name"] for t in _load_cors_technique_meta()} or set(
        CORS_TECHNIQUE_FALLBACK
    )
    args = ["attack", "cors", "run"]
    if body.technique:
        tech = body.technique.strip()
        if tech not in known:
            raise HTTPException(
                400,
                f"unknown CORS technique '{tech}'; "
                f"expected one of: {', '.join(sorted(known))}",
            )
        args += ["--technique", tech]
    flow_ids = [fid.strip() for fid in (body.flows or []) if fid and fid.strip()]
    if flow_ids:
        for fid in flow_ids:
            args += ["--flow", fid]
    else:
        if body.limit:
            args += ["--limit", str(int(body.limit))]
        if body.endpoint:
            args += ["--endpoint", body.endpoint.strip()]
        if body.host:
            args += ["--host", body.host.strip()]
    if body.right_now:
        args.append("--right-now")
    results = cli.run_scoped(project_id, args)
    return {"steps": [r.to_dict() for r in results]}


# ------------------------------------------------------------------ #
# SQL injection                                                        #
# ------------------------------------------------------------------ #

SQLI_TECHNIQUE_FALLBACK = [
    "quote_single",
    "quote_double",
    "quote_paren",
    "comment_dash",
    "comment_dash_space",
    "stacked_semi",
    "tautology",
    "mssql_tautology",
    "mssql_convert",
    "mssql_convert_db",
    "mssql_cast",
    "mssql_divzero",
    "mssql_char_or",
    "mysql_extractvalue",
    "pg_cast",
    "oracle_to_number",
    "sqlite_error",
    "union_1",
    "union_2",
    "union_3",
    "union_4",
    "union_5",
    "bool_true",
    "bool_false",
    "mssql_bool_true",
    "mssql_bool_false",
    "mssql_waitfor",
    "mssql_waitfor_inline",
    "mssql_waitfor_if",
    "mysql_sleep",
    "pg_sleep",
    "oracle_pipe",
]

SQLI_FAMILY_FALLBACK = ["error", "union", "boolean", "time"]
SQLI_DB_FALLBACK = ["unknown", "mssql"]


def _load_sqli_technique_meta() -> list[dict]:
    """Purpose: Technique picker from Core catalogue when importable."""
    try:
        from talos.sqli.models import TECHNIQUE_CATALOG

        return [dict(item) for item in TECHNIQUE_CATALOG]
    except Exception:
        return [
            {"name": name, "family": "", "description": ""}
            for name in SQLI_TECHNIQUE_FALLBACK
        ]


def _sqli_job_counts(db_path) -> dict[str, int]:
    try:
        rows = db.query_all(
            db_path,
            """
            SELECT status, COUNT(*) AS n
            FROM scheduler_jobs
            WHERE job_type = 'sqli_attack'
            GROUP BY status
            """,
        )
        return {r["status"]: int(r["n"]) for r in rows}
    except Exception:
        return {}


def _sqli_db_meta() -> list[dict]:
    """Purpose: Select DB picker rows from Core when importable."""
    try:
        from talos.sqli.models import DB_TYPE_CATALOG
        from talos.sqli.payloads import payload_count_for_db

        return [
            {
                **dict(item),
                "payload_count": payload_count_for_db(str(item["name"])),
            }
            for item in DB_TYPE_CATALOG
        ]
    except Exception:
        return [
            {
                "name": name,
                "label": "Unknown" if name == "unknown" else "Microsoft SQL Server",
                "description": "",
                "payload_count": 0,
            }
            for name in SQLI_DB_FALLBACK
        ]


@router.get("/sqli/techniques")
def sqli_techniques():
    """SQLi payload catalogue (matches CLI --technique / --family / --db)."""
    meta = _load_sqli_technique_meta()
    db_types = _sqli_db_meta()
    return {
        "techniques": [t["name"] for t in meta],
        "families": list(SQLI_FAMILY_FALLBACK),
        "db_types": db_types,
        "items": meta,
        "total_techniques": len(meta),
        "payload_counts": {
            row["name"]: int(row.get("payload_count") or 0) for row in db_types
        },
    }


@router.get("/sqli/results")
def sqli_results(
    project_id: str,
    verdict: str | None = None,
    technique: str | None = None,
    family: str | None = None,
    host: str | None = None,
    flow_id: str | None = None,
    limit: int = 200,
):
    record = db.get_project_record(project_id)
    db_path = config.project_db_path(project_id, record)
    try:
        from talos.sqli.db import list_sqli_results

        rows = list_sqli_results(
            db_path,
            verdict=verdict,
            technique=technique,
            family=family,
            host=host,
            flow_id=flow_id,
            limit=limit,
        )
    except Exception:
        rows = []
    return {"results": rows}


@router.get("/sqli/summary")
def sqli_summary(project_id: str):
    record = db.get_project_record(project_id)
    db_path = config.project_db_path(project_id, record)
    try:
        from talos.sqli.db import count_sqli_verdicts

        counts = count_sqli_verdicts(db_path)
    except Exception:
        counts = {}
    return {"counts": counts}


@router.get("/sqli/overview")
def sqli_overview(project_id: str, top_n: int = 8):
    """Aggregate for the SQLi workspace Overview tab."""
    record = db.get_project_record(project_id)
    db_path = config.project_db_path(project_id, record)
    top_n = min(max(top_n, 1), 50)

    counts: dict[str, int] = {}
    recent: list[dict] = []
    try:
        from talos.sqli.db import count_sqli_verdicts, list_sqli_results

        counts = count_sqli_verdicts(db_path)
        recent = list_sqli_results(db_path, verdict="SQLI", limit=top_n)
    except Exception:
        counts = {}
        recent = []

    jobs = _sqli_job_counts(db_path)
    pending = int(jobs.get("pending") or 0)
    running = int(jobs.get("running") or 0)
    techniques = _load_sqli_technique_meta()
    db_types = _sqli_db_meta()
    total_results = sum(counts.values())
    unknown_payloads = next(
        (int(row.get("payload_count") or 0) for row in db_types if row["name"] == "unknown"),
        len(techniques),
    )

    return {
        "counts": counts,
        "total_techniques": unknown_payloads or len(techniques),
        "jobs": jobs,
        "jobs_pending": pending,
        "jobs_running": running,
        "techniques": techniques,
        "families": list(SQLI_FAMILY_FALLBACK),
        "db_types": db_types,
        "payload_counts": {
            row["name"]: int(row.get("payload_count") or 0) for row in db_types
        },
        "recent_issues": recent,
        "empty_state": {
            "no_results": total_results == 0,
            "jobs_in_flight": (pending + running) > 0,
        },
    }


class SqliRunBody(BaseModel):
    """Mirrors talos attack sqli run — --flow is required."""
    flows: list[str] | None = None
    technique: str | None = None
    family: str | None = None
    db: str | None = None
    param: str | None = None
    params: list[str] | None = None
    right_now: bool = False
    high_priority: bool = True


@router.get("/sqli/points")
def sqli_points(project_id: str, flow: str):
    """
    Purpose:
        List injectable entry points on one or more captured flows.
    Input:
        flow — comma-separated flow UUIDs.
    Output:
        {points: [{flow_id, location, name, original, surface_kind}, ...]}.
    """
    record = db.get_project_record(project_id)
    db_path = config.project_db_path(project_id, record)
    flow_ids = [part.strip() for part in (flow or "").split(",") if part.strip()]
    if not flow_ids:
        raise HTTPException(400, "Pass flow as one or more comma-separated UUIDs.")
    try:
        from talos.sqli.inject import extract_injection_points
    except Exception as exc:
        raise HTTPException(500, f"SQLi inject module unavailable: {exc}") from exc

    placeholders = ",".join("?" for _ in flow_ids)
    try:
        rows = db.query_all(
            db_path,
            f"""
            SELECT id, url, query, request_headers, request_body
            FROM flows
            WHERE id IN ({placeholders})
            """,
            tuple(flow_ids),
        )
    except Exception:
        rows = []
    by_id = {str(row.get("id") or ""): row for row in rows}
    missing = [fid for fid in flow_ids if fid not in by_id]
    points: list[dict] = []
    for fid in flow_ids:
        row = by_id.get(fid)
        if row is None:
            continue
        extracted = extract_injection_points(
            url=str(row.get("url") or ""),
            query=str(row.get("query") or ""),
            request_headers=row.get("request_headers"),
            request_body=row.get("request_body"),
        )
        for point in extracted:
            item = point.to_dict()
            item["flow_id"] = fid
            points.append(item)
    return {"points": points, "missing": missing}


@router.post("/sqli/run")
def run_sqli(project_id: str, body: SqliRunBody):
    known = {t["name"] for t in _load_sqli_technique_meta()} or set(
        SQLI_TECHNIQUE_FALLBACK
    )
    flow_ids = [fid.strip() for fid in (body.flows or []) if fid and fid.strip()]
    if not flow_ids:
        raise HTTPException(
            400,
            "SQLi run requires at least one flow UUID. "
            "Select flows in the table or pass flows: [\"…\"].",
        )
    args = ["attack", "sqli", "run"]
    for fid in flow_ids:
        args += ["--flow", fid]
    if body.db:
        db_name = body.db.strip().lower()
        if db_name not in SQLI_DB_FALLBACK and db_name not in {
            "sqlserver",
            "sql-server",
            "sql_server",
            "microsoft",
            "microsoft_sql_server",
            "microsoft-sql-server",
        }:
            raise HTTPException(
                400,
                f"unknown SQLi database '{body.db}'; "
                f"expected one of: {', '.join(SQLI_DB_FALLBACK)}",
            )
        args += ["--db", db_name]
    param_values: list[str] = []
    if body.param and body.param.strip():
        param_values.append(body.param.strip())
    for item in body.params or []:
        if item and item.strip():
            param_values.append(item.strip())
    for name in param_values:
        args += ["--param", name]
    if body.technique:
        tech = body.technique.strip()
        if tech not in known and "__" not in tech:
            raise HTTPException(
                400,
                f"unknown SQLi technique '{tech}'; "
                f"expected one of: {', '.join(sorted(known))}",
            )
        args += ["--technique", tech]
    if body.family:
        fam = body.family.strip()
        if fam not in SQLI_FAMILY_FALLBACK:
            raise HTTPException(
                400,
                f"unknown SQLi family '{fam}'; "
                f"expected one of: {', '.join(SQLI_FAMILY_FALLBACK)}",
            )
        args += ["--family", fam]
    if body.right_now:
        args.append("--right-now")
    if body.high_priority:
        args.append("--high-priority")
    else:
        args.append("--no-high-priority")
    results = cli.run_scoped(project_id, args)
    return {"steps": [r.to_dict() for r in results]}


# ------------------------------------------------------------------ #
# HTTP request smuggling                                               #
# ------------------------------------------------------------------ #

SMUGGLE_TECHNIQUE_FALLBACK = [
    "cl_te",
    "te_cl",
    "te_space",
    "te_tab",
    "te_xchunked",
    "te_dual",
    "cl_cl",
]


def _load_smuggle_technique_meta() -> list[dict]:
    """Purpose: Technique picker from Core catalogue when importable."""
    try:
        from talos.smuggle.models import TECHNIQUE_CATALOG

        return [dict(item) for item in TECHNIQUE_CATALOG]
    except Exception:
        return [
            {"name": name, "family": "", "description": ""}
            for name in SMUGGLE_TECHNIQUE_FALLBACK
        ]


def _smuggle_job_counts(db_path) -> dict[str, int]:
    try:
        rows = db.query_all(
            db_path,
            """
            SELECT status, COUNT(*) AS n
            FROM scheduler_jobs
            WHERE job_type = 'smuggle_attack'
            GROUP BY status
            """,
        )
        return {r["status"]: int(r["n"]) for r in rows}
    except Exception:
        return {}


@router.get("/smuggle/techniques")
def smuggle_techniques():
    """Smuggle technique catalogue (matches CLI --technique)."""
    meta = _load_smuggle_technique_meta()
    return {
        "techniques": [t["name"] for t in meta],
        "items": meta,
        "total_techniques": len(meta),
    }


@router.get("/smuggle/results")
def smuggle_results(
    project_id: str,
    verdict: str | None = None,
    technique: str | None = None,
    host: str | None = None,
    flow_id: str | None = None,
    limit: int = 200,
):
    record = db.get_project_record(project_id)
    db_path = config.project_db_path(project_id, record)
    try:
        from talos.smuggle.db import list_smuggle_results

        rows = list_smuggle_results(
            db_path,
            verdict=verdict,
            technique=technique,
            host=host,
            flow_id=flow_id,
            limit=limit,
        )
    except Exception:
        rows = []
    return {"results": rows}


@router.get("/smuggle/summary")
def smuggle_summary(project_id: str):
    record = db.get_project_record(project_id)
    db_path = config.project_db_path(project_id, record)
    try:
        from talos.smuggle.db import count_smuggle_verdicts

        counts = count_smuggle_verdicts(db_path)
    except Exception:
        counts = {}
    return {"counts": counts}


@router.get("/smuggle/overview")
def smuggle_overview(project_id: str, top_n: int = 8):
    """Aggregate for the Smuggle workspace Overview tab."""
    record = db.get_project_record(project_id)
    db_path = config.project_db_path(project_id, record)
    top_n = min(max(top_n, 1), 50)

    counts: dict[str, int] = {}
    recent: list[dict] = []
    try:
        from talos.smuggle.db import count_smuggle_verdicts, list_smuggle_results

        counts = count_smuggle_verdicts(db_path)
        recent = list_smuggle_results(db_path, verdict="SMUGGLE", limit=top_n)
    except Exception:
        counts = {}
        recent = []

    jobs = _smuggle_job_counts(db_path)
    pending = int(jobs.get("pending") or 0)
    running = int(jobs.get("running") or 0)
    techniques = _load_smuggle_technique_meta()
    total_results = sum(counts.values())

    return {
        "counts": counts,
        "total_techniques": len(techniques),
        "jobs": jobs,
        "jobs_pending": pending,
        "jobs_running": running,
        "techniques": techniques,
        "recent_issues": recent,
        "empty_state": {
            "no_results": total_results == 0,
            "jobs_in_flight": (pending + running) > 0,
        },
    }


class SmuggleRunBody(BaseModel):
    """Mirrors talos attack smuggle run — --flow is required."""
    flows: list[str] | None = None
    technique: str | None = None
    right_now: bool = False


@router.post("/smuggle/run")
def run_smuggle(project_id: str, body: SmuggleRunBody):
    known = {t["name"] for t in _load_smuggle_technique_meta()} or set(
        SMUGGLE_TECHNIQUE_FALLBACK
    )
    flow_ids = [fid.strip() for fid in (body.flows or []) if fid and fid.strip()]
    if not flow_ids:
        raise HTTPException(
            400,
            "Smuggle run requires at least one flow UUID. "
            "Select flows in the table or pass flows: [\"…\"].",
        )
    args = ["attack", "smuggle", "run"]
    for fid in flow_ids:
        args += ["--flow", fid]
    if body.technique:
        tech = body.technique.strip()
        if tech not in known:
            raise HTTPException(
                400,
                f"unknown smuggle technique '{tech}'; "
                f"expected one of: {', '.join(sorted(known))}",
            )
        args += ["--technique", tech]
    if body.right_now:
        args.append("--right-now")
    results = cli.run_scoped(project_id, args)
    return {"steps": [r.to_dict() for r in results]}


# ------------------------------------------------------------------ #
# XSS / HTML injection                                                 #
# ------------------------------------------------------------------ #

XSS_FAMILY_FALLBACK = [
    "html_tag",
    "htmli",
    "html_attr",
    "event",
    "js",
    "url",
    "encoded",
    "bypass",
    "polyglot",
]


def _load_xss_technique_meta() -> list[dict]:
    """Purpose: Technique picker from Core catalogue when importable."""
    try:
        from talos.xss.payloads import TECHNIQUE_CATALOG

        return [dict(item) for item in TECHNIQUE_CATALOG]
    except Exception:
        return [
            {"name": name, "family": "", "description": ""}
            for name in (
                "script_alert",
                "img_onerror",
                "h1_tag",
                "dq_img_break",
                "js_sq_break",
                "enc_url_script",
                "bypass_case",
            )
        ]


def _xss_job_counts(db_path) -> dict[str, int]:
    try:
        rows = db.query_all(
            db_path,
            """
            SELECT status, COUNT(*) AS n
            FROM scheduler_jobs
            WHERE job_type = 'xss_attack'
            GROUP BY status
            """,
        )
        return {r["status"]: int(r["n"]) for r in rows}
    except Exception:
        return {}


@router.get("/xss/techniques")
def xss_techniques():
    """XSS payload catalogue (matches CLI --technique / --family)."""
    meta = _load_xss_technique_meta()
    return {
        "techniques": [t["name"] for t in meta],
        "families": list(XSS_FAMILY_FALLBACK),
        "items": meta,
        "total_techniques": len(meta),
    }


@router.get("/xss/results")
def xss_results(
    project_id: str,
    verdict: str | None = None,
    technique: str | None = None,
    family: str | None = None,
    host: str | None = None,
    flow_id: str | None = None,
    limit: int = 200,
):
    record = db.get_project_record(project_id)
    db_path = config.project_db_path(project_id, record)
    try:
        from talos.xss.db import list_xss_results

        rows = list_xss_results(
            db_path,
            verdict=verdict,
            technique=technique,
            family=family,
            host=host,
            flow_id=flow_id,
            limit=limit,
        )
    except Exception:
        rows = []
    return {"results": rows}


@router.get("/xss/summary")
def xss_summary(project_id: str):
    record = db.get_project_record(project_id)
    db_path = config.project_db_path(project_id, record)
    try:
        from talos.xss.db import count_xss_verdicts

        counts = count_xss_verdicts(db_path)
    except Exception:
        counts = {}
    return {"counts": counts}


@router.get("/xss/overview")
def xss_overview(project_id: str, top_n: int = 8):
    """Aggregate for the XSS workspace Overview tab."""
    record = db.get_project_record(project_id)
    db_path = config.project_db_path(project_id, record)
    top_n = min(max(top_n, 1), 50)

    counts: dict[str, int] = {}
    recent: list[dict] = []
    try:
        from talos.xss.db import (
            count_xss_verdicts,
            list_xss_results,
        )

        counts = count_xss_verdicts(db_path)
        hits = list_xss_results(db_path, verdict="XSS", limit=top_n)
        if len(hits) < top_n:
            htmlis = list_xss_results(db_path, verdict="HTMLI", limit=top_n)
            seen = {row.get("replay_flow_id") for row in hits}
            for row in htmlis:
                if row.get("replay_flow_id") in seen:
                    continue
                hits.append(row)
                if len(hits) >= top_n:
                    break
        recent = hits[:top_n]
    except Exception:
        counts = {}
        recent = []

    jobs = _xss_job_counts(db_path)
    pending = int(jobs.get("pending") or 0)
    running = int(jobs.get("running") or 0)
    techniques = _load_xss_technique_meta()
    total_results = sum(counts.values())

    return {
        "counts": counts,
        "total_techniques": len(techniques),
        "jobs": jobs,
        "jobs_pending": pending,
        "jobs_running": running,
        "techniques": techniques,
        "families": list(XSS_FAMILY_FALLBACK),
        "recent_issues": recent,
        "empty_state": {
            "no_results": total_results == 0,
            "jobs_in_flight": (pending + running) > 0,
        },
    }


class XssRunBody(BaseModel):
    """Mirrors talos attack xss run — --flow is required."""
    flows: list[str] | None = None
    technique: str | None = None
    family: str | None = None
    param: str | None = None
    params: list[str] | None = None
    right_now: bool = False
    high_priority: bool = True


@router.get("/xss/points")
def xss_points(project_id: str, flow: str):
    """
    Purpose:
        List injectable entry points on one or more captured flows.
    Input:
        flow — comma-separated flow UUIDs.
    Output:
        {points: [{flow_id, location, name, original, surface_kind}, ...]}.
    """
    record = db.get_project_record(project_id)
    db_path = config.project_db_path(project_id, record)
    flow_ids = [part.strip() for part in (flow or "").split(",") if part.strip()]
    if not flow_ids:
        raise HTTPException(400, "Pass flow as one or more comma-separated UUIDs.")
    try:
        from talos.xss.inject import extract_injection_points
    except Exception as exc:
        raise HTTPException(
            500, f"XSS inject module unavailable: {exc}"
        ) from exc

    placeholders = ",".join("?" for _ in flow_ids)
    try:
        rows = db.query_all(
            db_path,
            f"""
            SELECT f.id, f.url, f.query, f.request_headers, f.request_body,
                   COALESCE(e.normalized_path, '') AS normalized_path
            FROM flows f
            LEFT JOIN endpoints e ON e.id = f.endpoint_id
            WHERE f.id IN ({placeholders})
            """,
            tuple(flow_ids),
        )
    except Exception:
        rows = []
    by_id = {str(row.get("id") or ""): row for row in rows}
    missing = [fid for fid in flow_ids if fid not in by_id]
    points: list[dict] = []
    for fid in flow_ids:
        row = by_id.get(fid)
        if row is None:
            continue
        extracted = extract_injection_points(
            url=str(row.get("url") or ""),
            query=str(row.get("query") or ""),
            request_headers=row.get("request_headers"),
            request_body=row.get("request_body"),
            normalized_path=str(row.get("normalized_path") or ""),
        )
        for point in extracted:
            item = point.to_dict()
            item["flow_id"] = fid
            points.append(item)
    return {"points": points, "missing": missing}


@router.post("/xss/run")
def run_xss(project_id: str, body: XssRunBody):
    known = {t["name"] for t in _load_xss_technique_meta()}
    flow_ids = [fid.strip() for fid in (body.flows or []) if fid and fid.strip()]
    if not flow_ids:
        raise HTTPException(
            400,
            "XSS run requires at least one flow UUID. "
            "Select flows in the table or pass flows: [\"…\"].",
        )
    args = ["attack", "xss", "run"]
    for fid in flow_ids:
        args += ["--flow", fid]
    param_values: list[str] = []
    if body.param and body.param.strip():
        param_values.append(body.param.strip())
    for item in body.params or []:
        if item and item.strip():
            param_values.append(item.strip())
    for name in param_values:
        args += ["--param", name]
    if body.technique:
        tech = body.technique.strip()
        if known and tech not in known:
            raise HTTPException(
                400,
                f"unknown xss technique '{tech}'; "
                f"expected one of: {', '.join(sorted(known))}",
            )
        args += ["--technique", tech]
    if body.family:
        fam = body.family.strip()
        if fam not in XSS_FAMILY_FALLBACK:
            raise HTTPException(
                400,
                f"unknown xss family '{fam}'; "
                f"expected one of: {', '.join(XSS_FAMILY_FALLBACK)}",
            )
        args += ["--family", fam]
    if body.right_now:
        args.append("--right-now")
    if body.high_priority:
        args.append("--high-priority")
    else:
        args.append("--no-high-priority")
    results = cli.run_scoped(project_id, args)
    return {"steps": [r.to_dict() for r in results]}


# ------------------------------------------------------------------ #
# Path traversal / LFI                                                 #
# ------------------------------------------------------------------ #

PATH_TRAVERSAL_FAMILY_FALLBACK = [
    "unix",
    "windows",
    "dotdot",
    "encoded",
    "wrapper",
    "nullbyte",
    "bypass",
]


def _load_path_traversal_technique_meta() -> list[dict]:
    """Purpose: Technique picker from Core catalogue when importable."""
    try:
        from talos.path_traversal.payloads import TECHNIQUE_CATALOG

        return [dict(item) for item in TECHNIQUE_CATALOG]
    except Exception:
        return [
            {"name": name, "family": "", "description": ""}
            for name in (
                "unix_passwd",
                "win_ini",
                "dd_unix_8",
                "enc_url_slash",
                "php_filter_passwd",
                "null_passwd_jpg",
                "bypass_semicolon",
            )
        ]


def _path_traversal_job_counts(db_path) -> dict[str, int]:
    try:
        rows = db.query_all(
            db_path,
            """
            SELECT status, COUNT(*) AS n
            FROM scheduler_jobs
            WHERE job_type = 'path_traversal_attack'
            GROUP BY status
            """,
        )
        return {r["status"]: int(r["n"]) for r in rows}
    except Exception:
        return {}


@router.get("/path-traversal/techniques")
def path_traversal_techniques():
    """Path-traversal payload catalogue (matches CLI --technique / --family)."""
    meta = _load_path_traversal_technique_meta()
    return {
        "techniques": [t["name"] for t in meta],
        "families": list(PATH_TRAVERSAL_FAMILY_FALLBACK),
        "items": meta,
        "total_techniques": len(meta),
    }


@router.get("/path-traversal/results")
def path_traversal_results(
    project_id: str,
    verdict: str | None = None,
    technique: str | None = None,
    family: str | None = None,
    host: str | None = None,
    flow_id: str | None = None,
    limit: int = 200,
):
    record = db.get_project_record(project_id)
    db_path = config.project_db_path(project_id, record)
    try:
        from talos.path_traversal.db import list_path_traversal_results

        rows = list_path_traversal_results(
            db_path,
            verdict=verdict,
            technique=technique,
            family=family,
            host=host,
            flow_id=flow_id,
            limit=limit,
        )
    except Exception:
        rows = []
    return {"results": rows}


@router.get("/path-traversal/summary")
def path_traversal_summary(project_id: str):
    record = db.get_project_record(project_id)
    db_path = config.project_db_path(project_id, record)
    try:
        from talos.path_traversal.db import count_path_traversal_verdicts

        counts = count_path_traversal_verdicts(db_path)
    except Exception:
        counts = {}
    return {"counts": counts}


@router.get("/path-traversal/overview")
def path_traversal_overview(project_id: str, top_n: int = 8):
    """Aggregate for the Path Traversal workspace Overview tab."""
    record = db.get_project_record(project_id)
    db_path = config.project_db_path(project_id, record)
    top_n = min(max(top_n, 1), 50)

    counts: dict[str, int] = {}
    recent: list[dict] = []
    try:
        from talos.path_traversal.db import (
            count_path_traversal_verdicts,
            list_path_traversal_results,
        )

        counts = count_path_traversal_verdicts(db_path)
        recent = list_path_traversal_results(
            db_path, verdict="PATH_TRAVERSAL", limit=top_n
        )
    except Exception:
        counts = {}
        recent = []

    jobs = _path_traversal_job_counts(db_path)
    pending = int(jobs.get("pending") or 0)
    running = int(jobs.get("running") or 0)
    techniques = _load_path_traversal_technique_meta()
    total_results = sum(counts.values())

    return {
        "counts": counts,
        "total_techniques": len(techniques),
        "jobs": jobs,
        "jobs_pending": pending,
        "jobs_running": running,
        "techniques": techniques,
        "families": list(PATH_TRAVERSAL_FAMILY_FALLBACK),
        "recent_issues": recent,
        "empty_state": {
            "no_results": total_results == 0,
            "jobs_in_flight": (pending + running) > 0,
        },
    }


class PathTraversalRunBody(BaseModel):
    """Mirrors talos attack path-traversal run — --flow is required."""
    flows: list[str] | None = None
    technique: str | None = None
    family: str | None = None
    param: str | None = None
    params: list[str] | None = None
    right_now: bool = False
    high_priority: bool = True


@router.get("/path-traversal/points")
def path_traversal_points(project_id: str, flow: str):
    """
    Purpose:
        List injectable entry points on one or more captured flows.
    Input:
        flow — comma-separated flow UUIDs.
    Output:
        {points: [{flow_id, location, name, original, surface_kind}, ...]}.
    """
    record = db.get_project_record(project_id)
    db_path = config.project_db_path(project_id, record)
    flow_ids = [part.strip() for part in (flow or "").split(",") if part.strip()]
    if not flow_ids:
        raise HTTPException(400, "Pass flow as one or more comma-separated UUIDs.")
    try:
        from talos.path_traversal.inject import extract_injection_points
    except Exception as exc:
        raise HTTPException(
            500, f"Path-traversal inject module unavailable: {exc}"
        ) from exc

    placeholders = ",".join("?" for _ in flow_ids)
    try:
        rows = db.query_all(
            db_path,
            f"""
            SELECT f.id, f.url, f.query, f.request_headers, f.request_body,
                   COALESCE(e.normalized_path, '') AS normalized_path
            FROM flows f
            LEFT JOIN endpoints e ON e.id = f.endpoint_id
            WHERE f.id IN ({placeholders})
            """,
            tuple(flow_ids),
        )
    except Exception:
        rows = []
    by_id = {str(row.get("id") or ""): row for row in rows}
    missing = [fid for fid in flow_ids if fid not in by_id]
    points: list[dict] = []
    for fid in flow_ids:
        row = by_id.get(fid)
        if row is None:
            continue
        extracted = extract_injection_points(
            url=str(row.get("url") or ""),
            query=str(row.get("query") or ""),
            request_headers=row.get("request_headers"),
            request_body=row.get("request_body"),
            normalized_path=str(row.get("normalized_path") or ""),
        )
        for point in extracted:
            item = point.to_dict()
            item["flow_id"] = fid
            points.append(item)
    return {"points": points, "missing": missing}


@router.post("/path-traversal/run")
def run_path_traversal(project_id: str, body: PathTraversalRunBody):
    known = {t["name"] for t in _load_path_traversal_technique_meta()}
    flow_ids = [fid.strip() for fid in (body.flows or []) if fid and fid.strip()]
    if not flow_ids:
        raise HTTPException(
            400,
            "Path-traversal run requires at least one flow UUID. "
            "Select flows in the table or pass flows: [\"…\"].",
        )
    args = ["attack", "path-traversal", "run"]
    for fid in flow_ids:
        args += ["--flow", fid]
    param_values: list[str] = []
    if body.param and body.param.strip():
        param_values.append(body.param.strip())
    for item in body.params or []:
        if item and item.strip():
            param_values.append(item.strip())
    for name in param_values:
        args += ["--param", name]
    if body.technique:
        tech = body.technique.strip()
        if known and tech not in known:
            raise HTTPException(
                400,
                f"unknown path-traversal technique '{tech}'; "
                f"expected one of: {', '.join(sorted(known))}",
            )
        args += ["--technique", tech]
    if body.family:
        fam = body.family.strip()
        if fam not in PATH_TRAVERSAL_FAMILY_FALLBACK:
            raise HTTPException(
                400,
                f"unknown path-traversal family '{fam}'; "
                f"expected one of: {', '.join(PATH_TRAVERSAL_FAMILY_FALLBACK)}",
            )
        args += ["--family", fam]
    if body.right_now:
        args.append("--right-now")
    if body.high_priority:
        args.append("--high-priority")
    else:
        args.append("--no-high-priority")
    results = cli.run_scoped(project_id, args)
    return {"steps": [r.to_dict() for r in results]}


# ------------------------------------------------------------------ #
# SSRF                                                                 #
# ------------------------------------------------------------------ #

SSRF_FAMILY_FALLBACK = [
    "loopback",
    "cloud",
    "protocol",
    "bypass",
    "encoded",
    "internal",
    "oast",
]


def _load_ssrf_technique_meta() -> list[dict]:
    """Purpose: Technique picker from Core catalogue when importable."""
    try:
        from talos.ssrf.payloads import TECHNIQUE_CATALOG

        return [dict(item) for item in TECHNIQUE_CATALOG]
    except Exception:
        return [
            {"name": name, "family": "", "description": ""}
            for name in (
                "lb_http_127",
                "cloud_aws_meta",
                "proto_file_passwd",
                "oast_http",
            )
        ]


def _ssrf_job_counts(db_path) -> dict[str, int]:
    try:
        rows = db.query_all(
            db_path,
            """
            SELECT status, COUNT(*) AS n
            FROM scheduler_jobs
            WHERE job_type = 'ssrf_attack'
            GROUP BY status
            """,
        )
        return {r["status"]: int(r["n"]) for r in rows}
    except Exception:
        return {}


@router.get("/ssrf/techniques")
def ssrf_techniques():
    """SSRF payload catalogue (matches CLI --technique / --family)."""
    meta = _load_ssrf_technique_meta()
    return {
        "techniques": [t["name"] for t in meta],
        "families": list(SSRF_FAMILY_FALLBACK),
        "items": meta,
        "total_techniques": len(meta),
    }


@router.get("/ssrf/results")
def ssrf_results(
    project_id: str,
    verdict: str | None = None,
    technique: str | None = None,
    family: str | None = None,
    host: str | None = None,
    flow_id: str | None = None,
    limit: int = 200,
):
    record = db.get_project_record(project_id)
    db_path = config.project_db_path(project_id, record)
    try:
        from talos.ssrf.db import list_ssrf_results

        rows = list_ssrf_results(
            db_path,
            verdict=verdict,
            technique=technique,
            family=family,
            host=host,
            flow_id=flow_id,
            limit=limit,
        )
    except Exception:
        rows = []
    return {"results": rows}


@router.get("/ssrf/summary")
def ssrf_summary(project_id: str):
    record = db.get_project_record(project_id)
    db_path = config.project_db_path(project_id, record)
    try:
        from talos.ssrf.db import count_ssrf_verdicts

        counts = count_ssrf_verdicts(db_path)
    except Exception:
        counts = {}
    return {"counts": counts}


@router.get("/ssrf/overview")
def ssrf_overview(project_id: str, top_n: int = 8):
    """Aggregate for the SSRF workspace Overview tab."""
    record = db.get_project_record(project_id)
    db_path = config.project_db_path(project_id, record)
    top_n = min(max(top_n, 1), 50)

    counts: dict[str, int] = {}
    recent: list[dict] = []
    try:
        from talos.ssrf.db import count_ssrf_verdicts, list_ssrf_results

        counts = count_ssrf_verdicts(db_path)
        recent = list_ssrf_results(db_path, verdict="SSRF", limit=top_n)
    except Exception:
        counts = {}
        recent = []

    jobs = _ssrf_job_counts(db_path)
    pending = int(jobs.get("pending") or 0)
    running = int(jobs.get("running") or 0)
    techniques = _load_ssrf_technique_meta()
    total_results = sum(counts.values())

    return {
        "counts": counts,
        "total_techniques": len(techniques),
        "jobs": jobs,
        "jobs_pending": pending,
        "jobs_running": running,
        "techniques": techniques,
        "families": list(SSRF_FAMILY_FALLBACK),
        "recent_issues": recent,
        "empty_state": {
            "no_results": total_results == 0,
            "jobs_in_flight": (pending + running) > 0,
        },
    }


class SsrfRunBody(BaseModel):
    """Mirrors talos attack ssrf run — --flow is required."""
    flows: list[str] | None = None
    technique: str | None = None
    family: str | None = None
    param: str | None = None
    params: list[str] | None = None
    collaborator: str | None = None
    right_now: bool = False
    high_priority: bool = True


@router.get("/ssrf/points")
def ssrf_points(project_id: str, flow: str):
    """List injectable entry points on one or more captured flows."""
    record = db.get_project_record(project_id)
    db_path = config.project_db_path(project_id, record)
    flow_ids = [part.strip() for part in (flow or "").split(",") if part.strip()]
    if not flow_ids:
        raise HTTPException(400, "Pass flow as one or more comma-separated UUIDs.")
    try:
        from talos.ssrf.inject import extract_injection_points
    except Exception as exc:
        raise HTTPException(500, f"SSRF inject module unavailable: {exc}") from exc

    placeholders = ",".join("?" for _ in flow_ids)
    try:
        rows = db.query_all(
            db_path,
            f"""
            SELECT f.id, f.url, f.query, f.request_headers, f.request_body,
                   COALESCE(e.normalized_path, '') AS normalized_path
            FROM flows f
            LEFT JOIN endpoints e ON e.id = f.endpoint_id
            WHERE f.id IN ({placeholders})
            """,
            tuple(flow_ids),
        )
    except Exception:
        rows = []
    by_id = {str(row.get("id") or ""): row for row in rows}
    missing = [fid for fid in flow_ids if fid not in by_id]
    points: list[dict] = []
    for fid in flow_ids:
        row = by_id.get(fid)
        if row is None:
            continue
        extracted = extract_injection_points(
            url=str(row.get("url") or ""),
            query=str(row.get("query") or ""),
            request_headers=row.get("request_headers"),
            request_body=row.get("request_body"),
            normalized_path=str(row.get("normalized_path") or ""),
        )
        for point in extracted:
            item = point.to_dict()
            item["flow_id"] = fid
            points.append(item)
    return {"points": points, "missing": missing}


@router.post("/ssrf/run")
def run_ssrf(project_id: str, body: SsrfRunBody):
    known = {t["name"] for t in _load_ssrf_technique_meta()}
    flow_ids = [fid.strip() for fid in (body.flows or []) if fid and fid.strip()]
    if not flow_ids:
        raise HTTPException(
            400,
            "SSRF run requires at least one flow UUID. "
            "Select flows in the table or pass flows: [\"…\"].",
        )
    args = ["attack", "ssrf", "run"]
    for fid in flow_ids:
        args += ["--flow", fid]
    param_values: list[str] = []
    if body.param and body.param.strip():
        param_values.append(body.param.strip())
    for item in body.params or []:
        if item and item.strip():
            param_values.append(item.strip())
    for name in param_values:
        args += ["--param", name]
    if body.technique:
        tech = body.technique.strip()
        if known and tech not in known:
            raise HTTPException(
                400,
                f"unknown SSRF technique '{tech}'; "
                f"expected one of: {', '.join(sorted(known))}",
            )
        args += ["--technique", tech]
    if body.family:
        fam = body.family.strip()
        if fam not in SSRF_FAMILY_FALLBACK:
            raise HTTPException(
                400,
                f"unknown SSRF family '{fam}'; "
                f"expected one of: {', '.join(SSRF_FAMILY_FALLBACK)}",
            )
        args += ["--family", fam]
    if body.collaborator and body.collaborator.strip():
        args += ["--collaborator", body.collaborator.strip()]
    if body.right_now:
        args.append("--right-now")
    if body.high_priority:
        args.append("--high-priority")
    else:
        args.append("--no-high-priority")
    results = cli.run_scoped(project_id, args)
    return {"steps": [r.to_dict() for r in results]}


# ------------------------------------------------------------------ #
# Open redirect                                                        #
# ------------------------------------------------------------------ #

OPEN_REDIRECT_FAMILY_FALLBACK = [
    "absolute",
    "proto_rel",
    "slash",
    "encoded",
    "userinfo",
    "data_js",
    "fragment",
    "crlf",
]


def _load_open_redirect_technique_meta() -> list[dict]:
    """Purpose: Technique picker from Core catalogue when importable."""
    try:
        from talos.open_redirect.payloads import TECHNIQUE_CATALOG

        return [dict(item) for item in TECHNIQUE_CATALOG]
    except Exception:
        return [
            {"name": name, "family": "", "description": ""}
            for name in ("abs_https", "pr_slash", "js_alert", "crlf_location")
        ]


def _open_redirect_job_counts(db_path) -> dict[str, int]:
    try:
        rows = db.query_all(
            db_path,
            """
            SELECT status, COUNT(*) AS n
            FROM scheduler_jobs
            WHERE job_type = 'open_redirect_attack'
            GROUP BY status
            """,
        )
        return {r["status"]: int(r["n"]) for r in rows}
    except Exception:
        return {}


@router.get("/open-redirect/techniques")
def open_redirect_techniques():
    """Open-redirect payload catalogue (matches CLI --technique / --family)."""
    meta = _load_open_redirect_technique_meta()
    return {
        "techniques": [t["name"] for t in meta],
        "families": list(OPEN_REDIRECT_FAMILY_FALLBACK),
        "items": meta,
        "total_techniques": len(meta),
    }


@router.get("/open-redirect/results")
def open_redirect_results(
    project_id: str,
    verdict: str | None = None,
    technique: str | None = None,
    family: str | None = None,
    host: str | None = None,
    flow_id: str | None = None,
    limit: int = 200,
):
    record = db.get_project_record(project_id)
    db_path = config.project_db_path(project_id, record)
    try:
        from talos.open_redirect.db import list_open_redirect_results

        rows = list_open_redirect_results(
            db_path,
            verdict=verdict,
            technique=technique,
            family=family,
            host=host,
            flow_id=flow_id,
            limit=limit,
        )
    except Exception:
        rows = []
    return {"results": rows}


@router.get("/open-redirect/summary")
def open_redirect_summary(project_id: str):
    record = db.get_project_record(project_id)
    db_path = config.project_db_path(project_id, record)
    try:
        from talos.open_redirect.db import count_open_redirect_verdicts

        counts = count_open_redirect_verdicts(db_path)
    except Exception:
        counts = {}
    return {"counts": counts}


@router.get("/open-redirect/overview")
def open_redirect_overview(project_id: str, top_n: int = 8):
    """Aggregate for the Open Redirect workspace Overview tab."""
    record = db.get_project_record(project_id)
    db_path = config.project_db_path(project_id, record)
    top_n = min(max(top_n, 1), 50)

    counts: dict[str, int] = {}
    recent: list[dict] = []
    try:
        from talos.open_redirect.db import (
            count_open_redirect_verdicts,
            list_open_redirect_results,
        )

        counts = count_open_redirect_verdicts(db_path)
        recent = list_open_redirect_results(
            db_path, verdict="OPEN_REDIRECT", limit=top_n
        )
    except Exception:
        counts = {}
        recent = []

    jobs = _open_redirect_job_counts(db_path)
    pending = int(jobs.get("pending") or 0)
    running = int(jobs.get("running") or 0)
    techniques = _load_open_redirect_technique_meta()
    total_results = sum(counts.values())

    return {
        "counts": counts,
        "total_techniques": len(techniques),
        "jobs": jobs,
        "jobs_pending": pending,
        "jobs_running": running,
        "techniques": techniques,
        "families": list(OPEN_REDIRECT_FAMILY_FALLBACK),
        "recent_issues": recent,
        "empty_state": {
            "no_results": total_results == 0,
            "jobs_in_flight": (pending + running) > 0,
        },
    }


class OpenRedirectRunBody(BaseModel):
    """Mirrors talos attack open-redirect run — --flow is required."""
    flows: list[str] | None = None
    technique: str | None = None
    family: str | None = None
    param: str | None = None
    params: list[str] | None = None
    right_now: bool = False
    high_priority: bool = True


@router.get("/open-redirect/points")
def open_redirect_points(project_id: str, flow: str):
    """List injectable entry points on one or more captured flows."""
    record = db.get_project_record(project_id)
    db_path = config.project_db_path(project_id, record)
    flow_ids = [part.strip() for part in (flow or "").split(",") if part.strip()]
    if not flow_ids:
        raise HTTPException(400, "Pass flow as one or more comma-separated UUIDs.")
    try:
        from talos.open_redirect.inject import extract_injection_points
    except Exception as exc:
        raise HTTPException(
            500, f"Open-redirect inject module unavailable: {exc}"
        ) from exc

    placeholders = ",".join("?" for _ in flow_ids)
    try:
        rows = db.query_all(
            db_path,
            f"""
            SELECT f.id, f.url, f.query, f.request_headers, f.request_body,
                   COALESCE(e.normalized_path, '') AS normalized_path
            FROM flows f
            LEFT JOIN endpoints e ON e.id = f.endpoint_id
            WHERE f.id IN ({placeholders})
            """,
            tuple(flow_ids),
        )
    except Exception:
        rows = []
    by_id = {str(row.get("id") or ""): row for row in rows}
    missing = [fid for fid in flow_ids if fid not in by_id]
    points: list[dict] = []
    for fid in flow_ids:
        row = by_id.get(fid)
        if row is None:
            continue
        extracted = extract_injection_points(
            url=str(row.get("url") or ""),
            query=str(row.get("query") or ""),
            request_headers=row.get("request_headers"),
            request_body=row.get("request_body"),
            normalized_path=str(row.get("normalized_path") or ""),
        )
        for point in extracted:
            item = point.to_dict()
            item["flow_id"] = fid
            points.append(item)
    return {"points": points, "missing": missing}


@router.post("/open-redirect/run")
def run_open_redirect(project_id: str, body: OpenRedirectRunBody):
    known = {t["name"] for t in _load_open_redirect_technique_meta()}
    flow_ids = [fid.strip() for fid in (body.flows or []) if fid and fid.strip()]
    if not flow_ids:
        raise HTTPException(
            400,
            "Open-redirect run requires at least one flow UUID. "
            "Select flows in the table or pass flows: [\"…\"].",
        )
    args = ["attack", "open-redirect", "run"]
    for fid in flow_ids:
        args += ["--flow", fid]
    param_values: list[str] = []
    if body.param and body.param.strip():
        param_values.append(body.param.strip())
    for item in body.params or []:
        if item and item.strip():
            param_values.append(item.strip())
    for name in param_values:
        args += ["--param", name]
    if body.technique:
        tech = body.technique.strip()
        if known and tech not in known:
            raise HTTPException(
                400,
                f"unknown open-redirect technique '{tech}'; "
                f"expected one of: {', '.join(sorted(known))}",
            )
        args += ["--technique", tech]
    if body.family:
        fam = body.family.strip()
        if fam not in OPEN_REDIRECT_FAMILY_FALLBACK:
            raise HTTPException(
                400,
                f"unknown open-redirect family '{fam}'; "
                f"expected one of: {', '.join(OPEN_REDIRECT_FAMILY_FALLBACK)}",
            )
        args += ["--family", fam]
    if body.right_now:
        args.append("--right-now")
    if body.high_priority:
        args.append("--high-priority")
    else:
        args.append("--no-high-priority")
    results = cli.run_scoped(project_id, args)
    return {"steps": [r.to_dict() for r in results]}


# ------------------------------------------------------------------ #
# Host-header injection                                                #
# ------------------------------------------------------------------ #

HOST_HEADER_FAMILY_FALLBACK = [
    "absolute",
    "port",
    "ambiguous",
    "absolute_url",
    "encoded",
    "bypass",
    "crlf",
]


def _load_host_header_technique_meta() -> list[dict]:
    """Purpose: Technique picker from Core catalogue when importable."""
    try:
        from talos.host_header.payloads import TECHNIQUE_CATALOG

        return [dict(item) for item in TECHNIQUE_CATALOG]
    except Exception:
        return [
            {"name": name, "family": "", "description": ""}
            for name in (
                "abs_canary",
                "port_canary_443",
                "amb_colon",
                "url_https",
                "enc_percent_dot",
                "bypass_sub_poison",
                "crlf_xfh",
            )
        ]


def _host_header_job_counts(db_path) -> dict[str, int]:
    try:
        rows = db.query_all(
            db_path,
            """
            SELECT status, COUNT(*) AS n
            FROM scheduler_jobs
            WHERE job_type = 'host_header_attack'
            GROUP BY status
            """,
        )
        return {r["status"]: int(r["n"]) for r in rows}
    except Exception:
        return {}


@router.get("/host-header/techniques")
def host_header_techniques():
    """Host-header payload catalogue (matches CLI --technique / --family)."""
    meta = _load_host_header_technique_meta()
    return {
        "techniques": [t["name"] for t in meta],
        "families": list(HOST_HEADER_FAMILY_FALLBACK),
        "items": meta,
        "total_techniques": len(meta),
    }


@router.get("/host-header/results")
def host_header_results(
    project_id: str,
    verdict: str | None = None,
    technique: str | None = None,
    family: str | None = None,
    host: str | None = None,
    flow_id: str | None = None,
    limit: int = 200,
):
    record = db.get_project_record(project_id)
    db_path = config.project_db_path(project_id, record)
    try:
        from talos.host_header.db import list_host_header_results

        rows = list_host_header_results(
            db_path,
            verdict=verdict,
            technique=technique,
            family=family,
            host=host,
            flow_id=flow_id,
            limit=limit,
        )
    except Exception:
        rows = []
    return {"results": rows}


@router.get("/host-header/summary")
def host_header_summary(project_id: str):
    record = db.get_project_record(project_id)
    db_path = config.project_db_path(project_id, record)
    try:
        from talos.host_header.db import count_host_header_verdicts

        counts = count_host_header_verdicts(db_path)
    except Exception:
        counts = {}
    return {"counts": counts}


@router.get("/host-header/overview")
def host_header_overview(project_id: str, top_n: int = 8):
    """Aggregate for the Host Header Injection workspace Overview tab."""
    record = db.get_project_record(project_id)
    db_path = config.project_db_path(project_id, record)
    top_n = min(max(top_n, 1), 50)

    counts: dict[str, int] = {}
    recent: list[dict] = []
    try:
        from talos.host_header.db import (
            count_host_header_verdicts,
            list_host_header_results,
        )

        counts = count_host_header_verdicts(db_path)
        recent = list_host_header_results(
            db_path, verdict="HOST_HEADER", limit=top_n
        )
    except Exception:
        counts = {}
        recent = []

    jobs = _host_header_job_counts(db_path)
    pending = int(jobs.get("pending") or 0)
    running = int(jobs.get("running") or 0)
    techniques = _load_host_header_technique_meta()
    total_results = sum(counts.values())

    return {
        "counts": counts,
        "total_techniques": len(techniques),
        "jobs": jobs,
        "jobs_pending": pending,
        "jobs_running": running,
        "techniques": techniques,
        "families": list(HOST_HEADER_FAMILY_FALLBACK),
        "recent_issues": recent,
        "empty_state": {
            "no_results": total_results == 0,
            "jobs_in_flight": (pending + running) > 0,
        },
    }


class HostHeaderRunBody(BaseModel):
    """Mirrors talos attack host-header run — --flow is required."""
    flows: list[str] | None = None
    technique: str | None = None
    family: str | None = None
    param: str | None = None
    params: list[str] | None = None
    right_now: bool = False
    high_priority: bool = True


@router.get("/host-header/points")
def host_header_points(project_id: str, flow: str):
    """
    Purpose:
        List host-related headers on one or more captured flows.
    Input:
        flow — comma-separated flow UUIDs.
    Output:
        {points: [{flow_id, location, name, original, surface_kind}, ...]}.
    """
    record = db.get_project_record(project_id)
    db_path = config.project_db_path(project_id, record)
    flow_ids = [part.strip() for part in (flow or "").split(",") if part.strip()]
    if not flow_ids:
        raise HTTPException(400, "Pass flow as one or more comma-separated UUIDs.")
    try:
        from talos.host_header.inject import extract_injection_points
    except Exception as exc:
        raise HTTPException(
            500, f"Host-header inject module unavailable: {exc}"
        ) from exc

    placeholders = ",".join("?" for _ in flow_ids)
    try:
        rows = db.query_all(
            db_path,
            f"""
            SELECT f.id, f.url, f.query, f.request_headers, f.request_body,
                   COALESCE(e.normalized_path, '') AS normalized_path
            FROM flows f
            LEFT JOIN endpoints e ON e.id = f.endpoint_id
            WHERE f.id IN ({placeholders})
            """,
            tuple(flow_ids),
        )
    except Exception:
        rows = []
    by_id = {str(row.get("id") or ""): row for row in rows}
    missing = [fid for fid in flow_ids if fid not in by_id]
    points: list[dict] = []
    for fid in flow_ids:
        row = by_id.get(fid)
        if row is None:
            continue
        extracted = extract_injection_points(
            url=str(row.get("url") or ""),
            query=str(row.get("query") or ""),
            request_headers=row.get("request_headers"),
            request_body=row.get("request_body"),
            normalized_path=str(row.get("normalized_path") or ""),
        )
        for point in extracted:
            item = point.to_dict()
            item["flow_id"] = fid
            points.append(item)
    return {"points": points, "missing": missing}


@router.post("/host-header/run")
def run_host_header(project_id: str, body: HostHeaderRunBody):
    known = {t["name"] for t in _load_host_header_technique_meta()}
    flow_ids = [fid.strip() for fid in (body.flows or []) if fid and fid.strip()]
    if not flow_ids:
        raise HTTPException(
            400,
            "Host-header run requires at least one flow UUID. "
            "Select flows in the table or pass flows: [\"…\"].",
        )
    args = ["attack", "host-header", "run"]
    for fid in flow_ids:
        args += ["--flow", fid]
    param_values: list[str] = []
    if body.param and body.param.strip():
        param_values.append(body.param.strip())
    for item in body.params or []:
        if item and item.strip():
            param_values.append(item.strip())
    for name in param_values:
        args += ["--header", name]
    if body.technique:
        tech = body.technique.strip()
        if known and tech not in known:
            raise HTTPException(
                400,
                f"unknown host-header technique '{tech}'; "
                f"expected one of: {', '.join(sorted(known))}",
            )
        args += ["--technique", tech]
    if body.family:
        fam = body.family.strip()
        if fam not in HOST_HEADER_FAMILY_FALLBACK:
            raise HTTPException(
                400,
                f"unknown host-header family '{fam}'; "
                f"expected one of: {', '.join(HOST_HEADER_FAMILY_FALLBACK)}",
            )
        args += ["--family", fam]
    if body.right_now:
        args.append("--right-now")
    if body.high_priority:
        args.append("--high-priority")
    else:
        args.append("--no-high-priority")
    results = cli.run_scoped(project_id, args)
    return {"steps": [r.to_dict() for r in results]}
