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


def _load_bac_technique_meta() -> list[dict]:
    """
    Technique picker metadata for the BAC workspace.

    Each entry: name (CLI subcommand), description, attack_type (job key),
    variant_count, variants (name + description).
    """
    variants_by_attack: dict[str, list] = {}
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
        from talos.projects.bac.candidates import scan_candidates

        return list(
            scan_candidates(
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
    for c in candidates:
        flow_ids = getattr(c, "flow_ids", None) or []
        flow_total += len(flow_ids)
        if getattr(c, "attacker_role_name", None):
            attacker_roles.add(c.attacker_role_name)
        if getattr(c, "target_role_name", None):
            target_roles.add(c.target_role_name)
        if getattr(c, "module_name", None):
            modules.add(c.module_name)
    return {
        "candidate_count": len(candidates),
        "flow_count": flow_total,
        "attacker_roles": sorted(attacker_roles),
        "target_roles": sorted(target_roles),
        "modules": sorted(modules),
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
def bac_techniques():
    """
    Known BAC technique metadata for UI pickers (matches CLI subcommands).
    """
    meta = _load_bac_technique_meta()
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
    technique_meta = _load_bac_technique_meta()
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

    return {
        "counts": counts,
        "candidates": cand_summary,
        "total_variants": total_variants,
        "estimated_jobs_all": estimated_jobs_all,
        "jobs": jobs,
        "jobs_pending": pending,
        "jobs_running": running,
        "auth": auth,
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
