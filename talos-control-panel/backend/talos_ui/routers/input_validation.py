"""
Control Panel Input Validation routes (IV workspace revamp).

Purpose:
    Read-side APIs for IV status, profiles, candidates, multi-level
    intelligence, and overview — plus mutation wrappers that shell out to
    ``talos input-validation …``.

    Candidate scores are prioritization only — not confirmed vulnerabilities.

Dependencies: FastAPI, talos_ui.db/cli/config, talos.input_validation (read).
Data flow: HTTP → read-only SQLite / core helpers, or CLI subprocess for writes.
Side effects: Writes only via CLI subprocess.
"""

from __future__ import annotations

import sys
from typing import Any
from urllib.parse import unquote

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from .. import cli, config, db

router = APIRouter(prefix="/api/input-validation", tags=["input-validation"])

# Must match talos.input_validation.cli._PHASE_NAMES (config + phase shortcuts).
# Parser probes are planner-driven (Module 8), not a separate CLI phase toggle.
PHASES = [
    "baseline",
    "multiprobe",
    "identifier",
    "characters",
    "length",
    "types",
    "transformations",
    "reflection",
    "validation",
]

PRIORITIZATION_NOTE = (
    "Candidate scores are prioritization only, not confirmed vulnerabilities. "
    "Stored/cross-page reflection is data-flow evidence, not XSS confirmation."
)

# Dedicated attack engines that can consume IV candidates (param + flows).
# CLI tokens match `talos attack <module> run`. Burp tree uses engine.
RUNNABLE_CANDIDATE_ATTACKS: dict[str, dict[str, str]] = {
    "xss": {
        "cli": "xss",
        "label": "XSS",
        "workspace": "/testing/xss",
        "burp_engine": "xss",
        "burp_label": "XSS",
    },
    "sqli": {
        "cli": "sqli",
        "label": "SQLi",
        "workspace": "/testing/sqli",
        "burp_engine": "sqli",
        "burp_label": "SQL Injection",
    },
    "path_traversal": {
        "cli": "path-traversal",
        "label": "Path Traversal",
        "workspace": "/testing/path-traversal",
        "burp_engine": "path-traversal",
        "burp_label": "Path Traversal",
    },
    "ssrf": {
        "cli": "ssrf",
        "label": "SSRF",
        "workspace": "/testing/ssrf",
        "burp_engine": "ssrf",
        "burp_label": "SSRF",
    },
    "open_redirect": {
        "cli": "open-redirect",
        "label": "Open Redirect",
        "workspace": "/testing/open-redirect",
        "burp_engine": "open-redirect",
        "burp_label": "Open Redirect",
    },
}

DEFAULT_CANDIDATE_RUN_LIMIT = 6
DEFAULT_FLOWS_PER_PARAM = 2
MAX_CANDIDATE_RUN_LIMIT = 12
MAX_FLOWS_PER_PARAM = 5


def _ensure_talos_on_path() -> None:
    root = str(config.TALOS_ROOT)
    if root not in sys.path:
        sys.path.insert(0, root)


def _db_path(project_id: str):
    record = db.get_project_record(project_id)
    return config.project_db_path(project_id, record)


def _top_candidate(cands: list[Any] | None) -> dict[str, Any] | None:
    if not cands:
        return None
    best = None
    best_score = -1
    for c in cands:
        if not isinstance(c, dict):
            continue
        try:
            score = int(c.get("score") or 0)
        except (TypeError, ValueError):
            score = 0
        if score > best_score:
            best_score = score
            best = c
    return best


def _slim_param_profile(p: dict[str, Any]) -> dict[str, Any]:
    """Table-friendly profile row with intelligence summary fields."""
    observed = p.get("observed") if isinstance(p.get("observed"), dict) else {}
    reflection = observed.get("reflection") if isinstance(observed.get("reflection"), dict) else {}
    length = observed.get("length") if isinstance(observed.get("length"), dict) else {}
    types = observed.get("types") if isinstance(observed.get("types"), dict) else {}
    url_features = (
        observed.get("url_features")
        if isinstance(observed.get("url_features"), dict)
        else {}
    )
    url_sink = (
        observed.get("url_sink") if isinstance(observed.get("url_sink"), dict) else {}
    )
    primary_type = ""
    if isinstance(types.get("_summary"), dict):
        primary_type = str(types["_summary"].get("primary") or "")
    if not primary_type and isinstance(types.get("primary"), dict):
        primary_type = str(types["primary"].get("state") or types["primary"].get("outcome") or "")
    caps = p.get("capabilities") or []
    cands = p.get("candidates") or []
    if not isinstance(caps, list):
        caps = []
    if not isinstance(cands, list):
        cands = []
    top = _top_candidate(cands)
    name = p.get("name") or p.get("param_name")
    location = p.get("location")
    try:
        url_score = int(url_features.get("score") or 0)
    except (TypeError, ValueError):
        url_score = 0
    try:
        us_conf = int(url_sink.get("confidence") or 0)
    except (TypeError, ValueError):
        us_conf = 0
    return {
        "param_uuid": p.get("param_uuid"),
        "host": p.get("host"),
        "location": location,
        "name": name,
        "schema_version": p.get("schema_version"),
        "engine_version": p.get("engine_version"),
        "profile_version": p.get("profile_version"),
        "updated_at": p.get("updated_at"),
        "capabilities": caps,
        "candidates": cands,
        "candidate_count": len(cands),
        "capability_count": len(caps),
        "requests_used": p.get("requests_used"),
        "budget_tier": p.get("budget_tier"),
        "reflection_state": reflection.get("state") or "unknown",
        "reflection_confidence": reflection.get("confidence") or 0,
        "length_state": length.get("state") or "unknown",
        "max_accepted_length": length.get("max_accepted"),
        "primary_type": primary_type or None,
        "top_candidate": (
            {
                "attack": top.get("attack"),
                "score": top.get("score"),
                "confidence": top.get("confidence"),
            }
            if top
            else None
        ),
        # URL Sink Discovery (passive + active characterization) — prioritization only
        "url_score": url_score,
        "possible_network_resource": bool(url_features.get("possible_network_resource")),
        "name_category": url_features.get("name_category"),
        "url_sink_confidence": us_conf if us_conf > 0 else None,
        "has_network_resource_sink": "network_resource_sink" in caps,
        "inventory_only": (
            str(location or "") == "response"
            or str(name or "").startswith("jwt.")
        ),
    }


def _match_profile_filters(
    row: dict[str, Any],
    *,
    location: str | None,
    capability: str | None,
    has_candidates: bool | None,
    search: str | None,
    min_reflection_confidence: int,
) -> bool:
    if location and str(row.get("location") or "") != location:
        return False
    caps = row.get("capabilities") or []
    if capability and capability not in caps:
        return False
    cands = row.get("candidates") or []
    if has_candidates is True and not cands:
        return False
    if has_candidates is False and cands:
        return False
    try:
        refl_conf = int(row.get("reflection_confidence") or 0)
    except (TypeError, ValueError):
        refl_conf = 0
    if min_reflection_confidence and refl_conf < min_reflection_confidence:
        return False
    if search:
        q = search.lower().strip()
        blob = " ".join(
            str(row.get(k) or "")
            for k in ("name", "host", "location", "param_uuid", "primary_type")
        ).lower()
        if q not in blob:
            return False
    return True


# ------------------------------------------------------------------ #
# Config / status                                                      #
# ------------------------------------------------------------------ #


@router.get("/config")
def get_config(project_id: str):
    record = db.get_project_record(project_id)
    db_path = config.project_db_path(project_id, record)
    row = db.query_one(db_path, "SELECT * FROM input_validation_config WHERE id='default'")
    if row:
        row["excluded_hosts"] = db.safe_json(row.get("excluded_hosts"), [])
        row["excluded_endpoints"] = db.safe_json(row.get("excluded_endpoints"), [])
    return {"config": row, "phases": PHASES}


@router.get("/status")
def get_status(project_id: str):
    """
    Full IV status via core get_iv_status (budget, requests_used, plan queue,
    confidence buckets, candidate counts). Falls back to legacy cache counts
    if core import fails.
    """
    record = db.get_project_record(project_id)
    db_path = config.project_db_path(project_id, record)
    try:
        _ensure_talos_on_path()
        from talos.input_validation.db import get_iv_status

        status = get_iv_status(db_path)
        param_counts = db.query_all(
            db_path, "SELECT status, COUNT(*) AS n FROM iv_param_cache GROUP BY status"
        )
        reflection_counts = db.query_all(
            db_path,
            "SELECT status, COUNT(*) AS n FROM iv_reflection_cache GROUP BY status",
        )
        probe_counts = db.query_all(
            db_path, "SELECT status, COUNT(*) AS n FROM iv_probe_results GROUP BY status"
        )
        status["param_cache"] = {r["status"]: r["n"] for r in param_counts}
        status["reflection_cache"] = {r["status"]: r["n"] for r in reflection_counts}
        status["probe_results"] = {r["status"]: r["n"] for r in probe_counts}
        return status
    except Exception:
        param_counts = db.query_all(
            db_path, "SELECT status, COUNT(*) AS n FROM iv_param_cache GROUP BY status"
        )
        reflection_counts = db.query_all(
            db_path,
            "SELECT status, COUNT(*) AS n FROM iv_reflection_cache GROUP BY status",
        )
        probe_counts = db.query_all(
            db_path, "SELECT status, COUNT(*) AS n FROM iv_probe_results GROUP BY status"
        )
        return {
            "param_cache": {r["status"]: r["n"] for r in param_counts},
            "reflection_cache": {r["status"]: r["n"] for r in reflection_counts},
            "probe_results": {r["status"]: r["n"] for r in probe_counts},
        }


@router.get("/overview")
def get_overview(project_id: str, top_n: int = Query(10, ge=1, le=50)):
    """
    One-shot Overview payload: status + top candidates + empty-state flags.
    """
    status = get_status(project_id)
    top: list[dict[str, Any]] = []
    try:
        db_path = _db_path(project_id)
        _ensure_talos_on_path()
        from talos.input_validation.candidates import list_candidates

        top = list_candidates(
            db_path,
            min_score=60,
            limit=top_n,
            recompute=False,
        )
    except Exception:
        top = []

    conf = status.get("confidence") if isinstance(status, dict) else {}
    conf = conf if isinstance(conf, dict) else {}
    probes = 0
    if isinstance(status, dict):
        pr = status.get("probe_results") or {}
        if isinstance(pr, dict):
            probes = sum(int(v or 0) for v in pr.values())
        probes = max(probes, int(status.get("params_probed") or 0))

    return {
        "status": status,
        "top_candidates": top,
        "empty_state": {
            "no_probes": probes == 0 and int(status.get("params_probed") or 0) == 0,
            "no_profiles": int(status.get("profiles") or 0) == 0,
            "no_candidates_ge_60": len(top) == 0,
            "has_jobs": (
                int(status.get("running") or 0) + int(status.get("queued") or 0)
            )
            > 0,
        },
        "note": PRIORITIZATION_NOTE,
    }


class IvConfigBody(BaseModel):
    enable: bool | None = None
    disable: bool | None = None
    auto_run: bool | None = None
    workers: int | None = None
    analysis_off: str | None = None
    analysis_on: str | None = None
    probe_strategy: str | None = None
    budget: str | None = None
    max_requests_per_param: int | None = None
    include_auth_artifacts: bool | None = None
    skip_auth_artifacts: bool | None = None


@router.post("/config")
def set_config(project_id: str, body: IvConfigBody):
    args = ["input-validation", "config"]
    if body.enable:
        args.append("--enable")
    if body.disable:
        args.append("--disable")
    if body.auto_run is True:
        args += ["--auto-run", "on"]
    elif body.auto_run is False:
        args += ["--auto-run", "off"]
    if body.workers is not None:
        args += ["--workers", str(body.workers)]
    if body.analysis_off:
        args += ["--analysis-off", body.analysis_off]
    if body.analysis_on:
        args += ["--analysis-on", body.analysis_on]
    tier = body.budget or body.probe_strategy
    if tier:
        args += ["--probe-strategy", tier]
    if body.max_requests_per_param is not None:
        args += ["--max-requests-per-param", str(body.max_requests_per_param)]
    if body.include_auth_artifacts:
        args.append("--include-auth-artifacts")
    if body.skip_auth_artifacts:
        args.append("--skip-auth-artifacts")
    results = cli.run_scoped(project_id, args)
    return {"steps": [r.to_dict() for r in results]}


class ScopeBody(BaseModel):
    host: str | None = None
    endpoint: str | None = None
    parameter: str | None = None
    param_uuid: str | None = None
    flows: list[str] | None = None
    ignore_cache: bool = False
    force: bool = False
    budget: str | None = None
    include_auth_artifacts: bool = False


def _scope_args(
    body: ScopeBody,
    include_ignore_cache: bool = False,
    include_force: bool = False,
    include_budget: bool = False,
) -> list[str]:
    args: list[str] = []
    flow_ids = [f.strip() for f in (body.flows or []) if f and f.strip()]
    if flow_ids:
        for fid in flow_ids:
            args += ["--flow", fid]
    elif body.host:
        args += ["--host", body.host]
    elif body.endpoint:
        args += ["--endpoint", body.endpoint]
    elif body.parameter:
        args += ["--parameter", body.parameter]
    if include_ignore_cache and body.ignore_cache:
        args.append("--ignore-cache")
    if include_force and body.force:
        args.append("--force")
    if include_budget and body.budget:
        args += ["--budget", body.budget]
    if body.include_auth_artifacts:
        args.append("--include-auth-artifacts")
    return args


@router.post("/run")
def run_iv(project_id: str, body: ScopeBody):
    args = ["input-validation", "run"] + _scope_args(
        body, include_ignore_cache=True, include_budget=True
    )
    results = cli.run_scoped(project_id, args)
    return {"steps": [r.to_dict() for r in results]}


@router.post("/resume")
def resume_iv(project_id: str, body: ScopeBody):
    args = ["input-validation", "resume"] + _scope_args(body)
    results = cli.run_scoped(project_id, args)
    return {"steps": [r.to_dict() for r in results]}


@router.post("/clear-cache")
def clear_cache(project_id: str, body: ScopeBody):
    args = ["input-validation", "clear-cache"] + _scope_args(body)
    if "--force" not in args:
        args.append("--force")
    results = cli.run_scoped(project_id, args)
    return {"steps": [r.to_dict() for r in results]}


@router.post("/phase/{phase}")
def run_phase(project_id: str, phase: str, body: ScopeBody):
    if phase not in PHASES:
        return {"error": f"unknown phase '{phase}'", "phases": PHASES}
    args = ["input-validation", phase] + _scope_args(
        body, include_ignore_cache=True, include_force=True
    )
    results = cli.run_scoped(project_id, args)
    return {"steps": [r.to_dict() for r in results]}


@router.post("/synthesize")
def synthesize_iv(project_id: str, body: ScopeBody):
    args = ["input-validation", "synthesize"]
    if body.param_uuid:
        args += ["--param-uuid", body.param_uuid]
    elif body.host:
        args += ["--host", body.host]
    results = cli.run_scoped(project_id, args)
    return {"steps": [r.to_dict() for r in results]}


@router.post("/exclude/endpoint/{endpoint_id}")
def exclude_endpoint(project_id: str, endpoint_id: str):
    results = cli.run_scoped(
        project_id, ["input-validation", "exclude", "endpoint", endpoint_id]
    )
    return {"steps": [r.to_dict() for r in results]}


@router.post("/exclude/host/{host}")
def exclude_host(project_id: str, host: str):
    results = cli.run_scoped(project_id, ["input-validation", "exclude", "host", host])
    return {"steps": [r.to_dict() for r in results]}


@router.post("/include/endpoint/{endpoint_id}")
def include_endpoint(project_id: str, endpoint_id: str):
    results = cli.run_scoped(
        project_id, ["input-validation", "include", "endpoint", endpoint_id]
    )
    return {"steps": [r.to_dict() for r in results]}


@router.post("/include/host/{host}")
def include_host(project_id: str, host: str):
    results = cli.run_scoped(project_id, ["input-validation", "include", "host", host])
    return {"steps": [r.to_dict() for r in results]}


# ------------------------------------------------------------------ #
# Profiles & candidates (read)                                         #
# ------------------------------------------------------------------ #


@router.get("/parameters")
def list_iv_parameters(project_id: str, host: str | None = None, limit: int = 300):
    """Parameter-level cache rows, one per (host, location, param_name, phase)."""
    record = db.get_project_record(project_id)
    db_path = config.project_db_path(project_id, record)
    where = "WHERE host = ?" if host else ""
    params = (host, limit) if host else (limit,)
    rows = db.query_all(
        db_path,
        f"SELECT * FROM iv_param_cache {where} ORDER BY host, param_name, phase LIMIT ?",
        params,
    )
    return {"rows": rows}


@router.get("/profiles")
def list_profiles(
    project_id: str,
    host: str | None = None,
    location: str | None = None,
    capability: str | None = None,
    has_candidates: bool | None = None,
    search: str | None = None,
    min_reflection_confidence: int = Query(0, ge=0, le=100),
    limit: int = Query(200, ge=1, le=2000),
):
    """List parameter intelligence profiles with optional filters + summary fields."""
    db_path = _db_path(project_id)
    fetch_limit = min(2000, max(limit * 4, limit))
    profiles: list[dict[str, Any]] = []
    try:
        _ensure_talos_on_path()
        from talos.input_validation.db import list_param_profiles

        profiles = list_param_profiles(db_path, host=host, limit=fetch_limit)
    except Exception:
        rows = db.query_all(
            db_path,
            "SELECT param_uuid, host, location, param_name, profile, "
            "updated_at FROM iv_param_profiles "
            + ("WHERE host = ? " if host else "")
            + "ORDER BY updated_at DESC LIMIT ?",
            (host, fetch_limit) if host else (fetch_limit,),
        )
        for r in rows:
            prof = db.safe_json(r.get("profile"), {})
            if not isinstance(prof, dict):
                prof = {}
            prof.setdefault("param_uuid", r.get("param_uuid"))
            prof.setdefault("host", r.get("host"))
            prof.setdefault("location", r.get("location"))
            prof.setdefault("name", r.get("param_name"))
            prof.setdefault("updated_at", r.get("updated_at"))
            profiles.append(prof)

    slim: list[dict[str, Any]] = []
    for p in profiles:
        if not isinstance(p, dict):
            continue
        row = _slim_param_profile(p)
        if not _match_profile_filters(
            row,
            location=location,
            capability=capability,
            has_candidates=has_candidates,
            search=search,
            min_reflection_confidence=min_reflection_confidence,
        ):
            continue
        slim.append(row)
        if len(slim) >= limit:
            break
    return {"profiles": slim, "count": len(slim)}


@router.get("/profiles/{param_uuid}")
def get_profile(project_id: str, param_uuid: str, recompute: bool = False):
    """
    Full parameter intelligence via get_param_intelligence.
    Includes capabilities + candidates (prioritization only).
    """
    db_path = _db_path(project_id)
    try:
        _ensure_talos_on_path()
        from talos.input_validation.candidates import get_param_intelligence

        intel = get_param_intelligence(
            db_path, param_uuid, recompute=bool(recompute)
        )
        if intel is None:
            return {"error": "not_found", "param_uuid": param_uuid}
        return {
            "intelligence": intel,
            "note": PRIORITIZATION_NOTE,
        }
    except Exception as exc:
        return {"error": str(exc), "param_uuid": param_uuid}


@router.get("/candidates")
def get_candidates(
    project_id: str,
    attack: str | None = None,
    min_score: int = Query(0, ge=0, le=100),
    min_confidence: int = Query(0, ge=0, le=100),
    host: str | None = None,
    capability: str | None = None,
    search: str | None = None,
    limit: int = Query(100, ge=1, le=1000),
    recompute: bool = False,
):
    """Project-wide attack candidate list (prioritization only)."""
    db_path = _db_path(project_id)
    try:
        _ensure_talos_on_path()
        from talos.input_validation.candidates import list_candidates

        fetch_limit = min(1000, limit * 3) if search else limit
        rows = list_candidates(
            db_path,
            attack=attack,
            min_score=min_score,
            min_confidence=min_confidence,
            host=host,
            capability=capability,
            limit=fetch_limit,
            recompute=recompute,
        )
        if search:
            q = search.lower().strip()
            rows = [
                r
                for r in rows
                if q
                in " ".join(
                    str(r.get(k) or "")
                    for k in ("name", "host", "location", "param_uuid", "attack")
                ).lower()
            ][:limit]
        return {
            "candidates": rows,
            "count": len(rows),
            "note": PRIORITIZATION_NOTE,
        }
    except Exception as exc:
        return {"candidates": [], "count": 0, "error": str(exc)}


class CandidateRunTarget(BaseModel):
    """One IV candidate the operator wants to turn into an attack run."""

    param_uuid: str | None = None
    name: str | None = None
    location: str | None = None
    attack: str | None = None
    score: int | None = None
    evidence_flow_ids: list[str] | None = None


class CandidateRunBody(BaseModel):
    """
    Enqueue a dedicated attack engine against a few good IV candidates.

    Targets those parameter names on ranked 2xx proxy_capture flows.
    Probe traffic is tagged for the Talos Burp extension under burp_engine.
    """

    attack: str
    candidates: list[CandidateRunTarget] | None = None
    min_score: int = Field(60, ge=0, le=100)
    host: str | None = None
    max_candidates: int = Field(DEFAULT_CANDIDATE_RUN_LIMIT, ge=1, le=MAX_CANDIDATE_RUN_LIMIT)
    max_flows_per_param: int = Field(DEFAULT_FLOWS_PER_PARAM, ge=1, le=MAX_FLOWS_PER_PARAM)
    high_priority: bool = True


def _normalize_attack_key(raw: str | None) -> str:
    return (raw or "").strip().lower().replace("-", "_")


def _inventory_only_surface(location: str | None, name: str | None) -> bool:
    loc = (location or "").strip().lower()
    nm = (name or "").strip()
    return loc == "response" or nm.startswith("jwt.")


def _param_spec(location: str | None, name: str) -> str:
    loc = (location or "").strip()
    return f"{loc}:{name}" if loc else name


def _lookup_param_row(db_path, param_uuid: str) -> dict[str, Any] | None:
    if not param_uuid:
        return None
    try:
        return db.query_one(
            db_path,
            "SELECT id, endpoint_id, name, location FROM parameters WHERE id = ?",
            (param_uuid,),
        )
    except Exception:
        return None


def _list_candidates_for_run(
    db_path,
    *,
    attack: str,
    min_score: int,
    host: str | None,
    limit: int,
) -> list[dict[str, Any]]:
    _ensure_talos_on_path()
    from talos.input_validation.candidates import list_candidates

    return list_candidates(
        db_path,
        attack=attack,
        min_score=min_score,
        host=host,
        limit=limit,
    )


def _flows_for_param(
    db_path,
    *,
    endpoint_id: str | None,
    max_flows: int,
) -> list[str]:
    """Ranked 2xx proxy_capture baselines for the parameter's endpoint."""
    if not endpoint_id:
        return []
    try:
        from talos.projects.flow_scope import select_test_flows_for_endpoints

        refs, _skipped = select_test_flows_for_endpoints(
            db_path,
            [endpoint_id],
            limit_per_endpoint=max_flows,
        )
    except Exception:
        return []
    return [ref.flow_id for ref in refs if getattr(ref, "flow_id", None)]


@router.post("/candidates/run")
def run_candidate_attack(project_id: str, body: CandidateRunBody):
    """
    Purpose:
        Turn IV prioritization candidates into a targeted attack enqueue.
        Picks a few good candidates of one attack family, binds each to
        ranked captured flows on that parameter's endpoint, and runs the
        matching engine with --param (not every field on the request).
    Output:
        CLI steps plus target/skip summary. Probes appear in Burp under
        the engine node (XSS, SQLi, Path Traversal, SSRF, Open Redirect).
    """
    attack = _normalize_attack_key(body.attack)
    spec = RUNNABLE_CANDIDATE_ATTACKS.get(attack)
    if spec is None:
        raise HTTPException(
            400,
            f"No dedicated attack runner for '{body.attack}'. "
            f"Use one of: {', '.join(sorted(RUNNABLE_CANDIDATE_ATTACKS))}.",
        )

    db_path = _db_path(project_id)
    cap = min(max(int(body.max_candidates), 1), MAX_CANDIDATE_RUN_LIMIT)
    flow_cap = min(max(int(body.max_flows_per_param), 1), MAX_FLOWS_PER_PARAM)

    supplied = [c for c in (body.candidates or []) if isinstance(c, CandidateRunTarget)]
    rows: list[dict[str, Any]] = []
    if supplied:
        for item in supplied:
            item_attack = _normalize_attack_key(item.attack) or attack
            if item_attack != attack:
                continue
            rows.append({
                "param_uuid": (item.param_uuid or "").strip(),
                "name": (item.name or "").strip(),
                "location": (item.location or "").strip(),
                "attack": attack,
                "score": int(item.score or 0),
                "evidence_flow_ids": list(item.evidence_flow_ids or []),
            })
            if len(rows) >= cap:
                break
    else:
        try:
            rows = _list_candidates_for_run(
                db_path,
                attack=attack,
                min_score=int(body.min_score),
                host=body.host or None,
                limit=cap,
            )
        except Exception as exc:
            raise HTTPException(500, f"Could not load candidates: {exc}") from exc

    if not rows:
        raise HTTPException(
            400,
            f"No {spec['label']} candidates to run. "
            "Raise the table first, or lower min score.",
        )

    skipped: list[dict[str, Any]] = []
    targets: list[dict[str, Any]] = []
    # flow_id → ordered unique param specs
    by_flow: dict[str, list[str]] = {}

    for row in rows:
        name = str(row.get("name") or "").strip()
        location = str(row.get("location") or "").strip()
        param_uuid = str(row.get("param_uuid") or "").strip()
        meta = _lookup_param_row(db_path, param_uuid) if param_uuid else None
        if meta:
            name = name or str(meta.get("name") or "").strip()
            location = location or str(meta.get("location") or "").strip()
            endpoint_id = str(meta.get("endpoint_id") or "").strip() or None
        else:
            endpoint_id = None

        if _inventory_only_surface(location, name):
            skipped.append({
                "param_uuid": param_uuid,
                "name": name,
                "reason": "inventory-only surface (response / jwt claim)",
            })
            continue
        if not name:
            skipped.append({
                "param_uuid": param_uuid,
                "name": name,
                "reason": "missing parameter name",
            })
            continue

        flow_ids = _flows_for_param(
            db_path, endpoint_id=endpoint_id, max_flows=flow_cap
        )
        if not flow_ids:
            skipped.append({
                "param_uuid": param_uuid,
                "name": name,
                "location": location,
                "reason": "no 2xx captured flow on this parameter's endpoint",
            })
            continue

        spec_name = _param_spec(location, name)
        targets.append({
            "param_uuid": param_uuid,
            "name": name,
            "location": location,
            "param": spec_name,
            "score": int(row.get("score") or 0),
            "flow_ids": flow_ids,
        })
        for fid in flow_ids:
            bucket = by_flow.setdefault(fid, [])
            if spec_name not in bucket:
                bucket.append(spec_name)

    if not by_flow:
        raise HTTPException(
            400,
            "None of the selected candidates have a usable captured flow "
            "to replay. Capture in-scope traffic for those endpoints first.",
        )

    # One CLI call per identical param-set (params must exist on every --flow).
    groups: dict[tuple[str, ...], list[str]] = {}
    for fid, params in by_flow.items():
        key = tuple(params)
        groups.setdefault(key, []).append(fid)

    all_steps: list[dict[str, Any]] = []
    for params, flow_ids in groups.items():
        args = ["attack", spec["cli"], "run"]
        for fid in flow_ids:
            args += ["--flow", fid]
        for param in params:
            args += ["--param", param]
        if body.high_priority:
            args.append("--high-priority")
        else:
            args.append("--no-high-priority")
        results = cli.run_scoped(project_id, args)
        all_steps.extend(r.to_dict() for r in results)

    return {
        "steps": all_steps,
        "attack": attack,
        "label": spec["label"],
        "workspace": spec["workspace"],
        "burp_engine": spec["burp_engine"],
        "burp_label": spec["burp_label"],
        "targets": targets,
        "skipped": skipped,
        "candidate_count": len(targets),
        "flow_count": len(by_flow),
        "note": (
            f"Enqueued {spec['label']} on {len(targets)} parameter(s) / "
            f"{len(by_flow)} flow(s). Probes appear in the Talos Burp "
            f"extension under {spec['burp_label']}."
        ),
    }


@router.get("/show/{parameter_uuid}")
def show_parameter(project_id: str, parameter_uuid: str, recompute: bool = False):
    """
    Parameter dossier payload: probes + full intelligence profile.
    """
    record = db.get_project_record(project_id)
    db_path = config.project_db_path(project_id, record)
    try:
        probes = db.query_all(
            db_path,
            "SELECT * FROM iv_probe_results WHERE param_uuid=? "
            "ORDER BY analysis, payload_index",
            (parameter_uuid,),
        )
    except Exception:
        probes = db.query_all(
            db_path,
            "SELECT * FROM iv_probe_results WHERE param_uuid=? ORDER BY analysis",
            (parameter_uuid,),
        )
    intel = None
    summary_lines: list[str] = []
    try:
        _ensure_talos_on_path()
        from talos.input_validation.candidates import get_param_intelligence
        from talos.input_validation.synthesize import format_profile_summary_lines

        intel = get_param_intelligence(
            db_path, parameter_uuid, recompute=bool(recompute)
        )
        profile = (intel or {}).get("profile") if intel else None
        if profile:
            summary_lines = format_profile_summary_lines(profile)
    except Exception:
        intel = None

    return {
        "probes": probes,
        "intelligence": intel,
        "profile": (intel or {}).get("profile") if intel else None,
        "capabilities": (intel or {}).get("capabilities") if intel else [],
        "candidates": (intel or {}).get("candidates") if intel else [],
        "summary_lines": summary_lines,
        "note": PRIORITIZATION_NOTE,
    }


@router.post("/show/{parameter_uuid}/cli")
def show_parameter_cli(project_id: str, parameter_uuid: str):
    results = cli.run_scoped(
        project_id, ["input-validation", "show", parameter_uuid]
    )
    return {"steps": [r.to_dict() for r in results]}


# ------------------------------------------------------------------ #
# Multi-level (endpoint / host)                                        #
# ------------------------------------------------------------------ #


@router.get("/endpoints")
def list_iv_endpoints(
    project_id: str,
    host: str | None = None,
    limit: int = Query(200, ge=1, le=1000),
):
    """List endpoint-level intelligence profiles."""
    db_path = _db_path(project_id)
    rows: list[dict[str, Any]] = []
    try:
        _ensure_talos_on_path()
        from talos.input_validation.db import list_endpoint_profiles

        profiles = list_endpoint_profiles(db_path, host=host, limit=limit)
        for p in profiles:
            if not isinstance(p, dict):
                continue
            tested = p.get("tested") if isinstance(p.get("tested"), dict) else {}
            caps = p.get("capabilities") or []
            parser = p.get("parser") if isinstance(p.get("parser"), dict) else {}
            if not parser and isinstance(p.get("observed"), dict):
                parser = p["observed"].get("parser") or {}
            rows.append({
                "endpoint_id": p.get("endpoint_id"),
                "host": p.get("host"),
                "method": p.get("method"),
                "path": p.get("path"),
                "schema_version": p.get("schema_version"),
                "capabilities": caps if isinstance(caps, list) else [],
                "capability_count": len(caps) if isinstance(caps, list) else 0,
                "tested_count": len(tested),
                "parser_known": bool(parser),
                "updated_at": p.get("updated_at"),
            })
    except Exception as exc:
        return {"endpoints": [], "count": 0, "error": str(exc)}
    return {"endpoints": rows, "count": len(rows)}


@router.get("/endpoints/{endpoint_id}")
def get_iv_endpoint(project_id: str, endpoint_id: str):
    """Endpoint intelligence dossier: profile + child param summaries."""
    db_path = _db_path(project_id)
    try:
        _ensure_talos_on_path()
        from talos.input_validation.db import (
            get_endpoint_meta,
            get_endpoint_profile,
            list_param_profiles_for_endpoint,
        )
        from talos.input_validation.learning import format_endpoint_intel_lines

        profile = get_endpoint_profile(db_path, endpoint_id)
        meta = get_endpoint_meta(db_path, endpoint_id)
        children = list_param_profiles_for_endpoint(db_path, endpoint_id)
        slim_children = [_slim_param_profile(c) for c in children if isinstance(c, dict)]
        return {
            "endpoint_id": endpoint_id,
            "meta": meta,
            "profile": profile,
            "summary_lines": format_endpoint_intel_lines(profile),
            "parameters": slim_children,
            "parameter_count": len(slim_children),
            "note": PRIORITIZATION_NOTE,
        }
    except Exception as exc:
        return {"error": str(exc), "endpoint_id": endpoint_id}


@router.get("/hosts")
def list_iv_hosts(
    project_id: str,
    limit: int = Query(200, ge=1, le=1000),
):
    """List application/host intelligence profiles."""
    db_path = _db_path(project_id)
    rows: list[dict[str, Any]] = []
    try:
        _ensure_talos_on_path()
        from talos.input_validation.db import list_app_profiles, list_endpoint_profiles

        apps = list_app_profiles(db_path, limit=limit)
        for p in apps:
            if not isinstance(p, dict):
                continue
            host = p.get("host") or ""
            tested = p.get("tested") if isinstance(p.get("tested"), dict) else {}
            caps = p.get("capabilities") or []
            ep_count = 0
            try:
                ep_count = len(list_endpoint_profiles(db_path, host=host, limit=500))
            except Exception:
                ep_count = 0
            rows.append({
                "host": host,
                "schema_version": p.get("schema_version"),
                "capabilities": caps if isinstance(caps, list) else [],
                "capability_count": len(caps) if isinstance(caps, list) else 0,
                "tested_count": len(tested),
                "endpoint_profile_count": ep_count,
                "updated_at": p.get("updated_at"),
            })
    except Exception as exc:
        return {"hosts": [], "count": 0, "error": str(exc)}
    return {"hosts": rows, "count": len(rows)}


@router.get("/hosts/{host}")
def get_iv_host(project_id: str, host: str):
    """Application/host intelligence dossier."""
    host_key = unquote(host)
    db_path = _db_path(project_id)
    try:
        _ensure_talos_on_path()
        from talos.input_validation.candidates import list_candidates
        from talos.input_validation.db import (
            get_app_profile,
            list_endpoint_profiles,
            list_param_profiles_for_host,
        )
        from talos.input_validation.learning import format_app_intel_lines

        profile = get_app_profile(db_path, host_key)
        endpoints = list_endpoint_profiles(db_path, host=host_key, limit=100)
        params = list_param_profiles_for_host(db_path, host_key, limit=100)
        cands = list_candidates(db_path, host=host_key, min_score=40, limit=50)
        ep_slim = []
        for p in endpoints:
            if not isinstance(p, dict):
                continue
            ep_slim.append({
                "endpoint_id": p.get("endpoint_id"),
                "host": p.get("host"),
                "method": p.get("method"),
                "path": p.get("path"),
                "updated_at": p.get("updated_at"),
                "capabilities": p.get("capabilities") or [],
            })
        return {
            "host": host_key,
            "profile": profile,
            "summary_lines": format_app_intel_lines(profile),
            "endpoints": ep_slim,
            "parameters": [_slim_param_profile(p) for p in params if isinstance(p, dict)],
            "candidates": cands,
            "note": PRIORITIZATION_NOTE,
        }
    except Exception as exc:
        return {"error": str(exc), "host": host_key}


# ------------------------------------------------------------------ #
# Export                                                               #
# ------------------------------------------------------------------ #


class ExportBody(BaseModel):
    parameter_uuid: str | None = None
    host: str | None = None
    format: str | None = None


@router.post("/export/parameter")
def export_parameter(project_id: str, body: ExportBody):
    args = [
        "input-validation",
        "export",
        "parameter",
        body.parameter_uuid or "",
    ]
    if body.format:
        args += ["--format", body.format]
    results = cli.run_scoped(project_id, args)
    return {"steps": [r.to_dict() for r in results]}


@router.post("/export/host")
def export_host(project_id: str, body: ExportBody):
    args = ["input-validation", "export", "host", body.host or ""]
    if body.format:
        args += ["--format", body.format]
    results = cli.run_scoped(project_id, args)
    return {"steps": [r.to_dict() for r in results]}


@router.post("/export/csv")
def export_csv(project_id: str):
    results = cli.run_scoped(project_id, ["input-validation", "export", "csv"])
    return {"steps": [r.to_dict() for r in results]}


@router.get("/export/parameter/{param_uuid}/json")
def export_parameter_json(project_id: str, param_uuid: str):
    """
    Browser-downloadable parameter intelligence JSON (no CLI write required).
    """
    db_path = _db_path(project_id)
    try:
        _ensure_talos_on_path()
        from talos.input_validation.candidates import get_param_intelligence

        intel = get_param_intelligence(db_path, param_uuid, recompute=False)
        if intel is None:
            return {"error": "not_found", "param_uuid": param_uuid}
        profile = intel.get("profile") or {}
        return {
            "format": "json",
            "param_uuid": param_uuid,
            "schema_version": profile.get("schema_version"),
            "engine_version": profile.get("engine_version"),
            "profile_version": profile.get("profile_version"),
            "profile": profile,
            "capabilities": intel.get("capabilities") or profile.get("capabilities") or [],
            "candidates": intel.get("candidates") or profile.get("candidates") or [],
            "note": PRIORITIZATION_NOTE,
        }
    except Exception as exc:
        return {"error": str(exc), "param_uuid": param_uuid}


@router.get("/export/host/{host}/json")
def export_host_json(project_id: str, host: str):
    """Browser-downloadable host intelligence JSON."""
    host_key = unquote(host)
    payload = get_iv_host(project_id, host_key)
    if payload.get("error") and not payload.get("profile"):
        return payload
    return {
        "format": "json",
        "host": host_key,
        "profile": payload.get("profile"),
        "endpoints": payload.get("endpoints") or [],
        "parameters": payload.get("parameters") or [],
        "candidates": payload.get("candidates") or [],
        "schema_version": (payload.get("profile") or {}).get("schema_version"),
        "note": PRIORITIZATION_NOTE,
    }
