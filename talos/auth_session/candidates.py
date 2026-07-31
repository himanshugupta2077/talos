"""
Module: talos.auth_session.candidates

Purpose:
    Generate auth-session attack candidates from bindings + baseline flows.
    Implements design generate rules:

      - insert-if-absent on (binding_id, test_id, baseline_flow_id)
      - --force-refresh only for pending|rejected
      - default skip non-safe methods unless include_unsafe_methods
      - baseline order: --flow → endpoint baseline / best → JWT-bearing prefer
      - skip when token not detectable; endpoint policy gates testable set

    Phase 2: no HTTP, no scheduler jobs.

Dependencies: json, logging, pathlib; db, config, extract, types, suite
Data flow: CLI generate → generate_candidates → auth_session_candidates rows
Side effects: DB writes for new/refreshed candidates.
"""

from __future__ import annotations

import logging
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from talos.auth_session import db as as_db
from talos.auth_session.config import is_safe_method, suite_config_from_binding
from talos.auth_session.extract import extract_token_context
from talos.auth_session.models import (
    STATUS_PENDING,
    STATUS_REJECTED,
    AuthSessionBinding,
    AuthSessionCandidate,
    TestCaseDef,
    TokenContext,
)
from talos.auth_session.types import get_analyzer
from talos.projects.db import migrate_project_db
from talos.replay import db as replay_db

log = logging.getLogger("talos.auth_session")


@dataclass
class GenerateStats:
    """Aggregate counts from one generate invocation."""

    created: int = 0
    skipped_existing: int = 0
    refreshed: int = 0
    skipped_no_token: int = 0
    skipped_unsafe_method: int = 0
    skipped_no_baseline: int = 0
    skipped_not_testable: int = 0
    skipped_test_filter: int = 0
    bindings_processed: int = 0
    flows_processed: int = 0
    skip_reasons: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "created": self.created,
            "skipped_existing": self.skipped_existing,
            "refreshed": self.refreshed,
            "skipped_no_token": self.skipped_no_token,
            "skipped_unsafe_method": self.skipped_unsafe_method,
            "skipped_no_baseline": self.skipped_no_baseline,
            "skipped_not_testable": self.skipped_not_testable,
            "skipped_test_filter": self.skipped_test_filter,
            "bindings_processed": self.bindings_processed,
            "flows_processed": self.flows_processed,
            "skip_reasons": list(self.skip_reasons),
        }


@dataclass
class BaselineSelection:
    """One baseline flow chosen for candidate generation."""

    flow_id: str
    endpoint_id: Optional[str]
    method: str
    source: str  # explicit_flow | baseline_policy | best_flow | jwt_bearing_flow
    flow: dict[str, Any]


def _flow_row_to_dict(row: sqlite3.Row | dict) -> dict[str, Any]:
    if isinstance(row, dict):
        return row
    return dict(row)


def load_flow(db_path: Path, flow_id: str) -> Optional[dict[str, Any]]:
    """Load a full flow for extract / method checks."""
    return replay_db.get_flow_for_replay(db_path, flow_id)


def _flow_has_detectable_token(
    flow: dict[str, Any],
    binding: AuthSessionBinding,
) -> bool:
    """True when binding field on the flow yields a detectible auth token."""
    ctx, _ = extract_token_context(flow, binding)
    return ctx is not None


def _scan_jwt_bearing_flows(
    db_path: Path,
    project_id: str,
    endpoint_id: str,
    binding: AuthSessionBinding,
    *,
    role_id: Optional[str] = None,
    limit: int = 25,
) -> Optional[dict[str, Any]]:
    """
    Recent 2xx proxy_capture flows on endpoint; return first with detectable
    token for the binding. Optional role_id filter (prefer, not require —
    callers fall back without role).
    """
    migrate_project_db(db_path)
    sql = """
        SELECT id, method, url, host, path, query,
               request_headers, request_cookies,
               status_code, endpoint_id, role_id, module_id, source
        FROM flows
        WHERE project_id = ?
          AND endpoint_id = ?
          AND source = 'proxy_capture'
          AND status_code BETWEEN 200 AND 299
    """
    params: list[Any] = [project_id, endpoint_id]
    if role_id:
        sql += " AND role_id = ?"
        params.append(role_id)
    sql += " ORDER BY captured_at DESC LIMIT ?"
    params.append(int(limit))

    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(sql, params).fetchall()

    for row in rows:
        flow = _flow_row_to_dict(row)
        full = load_flow(db_path, flow["id"]) or flow
        if _flow_has_detectable_token(full, binding):
            return full
    return None


def _prefer_jwt_bearing_flow(
    db_path: Path,
    project_id: str,
    endpoint_id: str,
    binding: AuthSessionBinding,
    preferred_role_id: Optional[str],
    primary: Optional[dict[str, Any]],
) -> tuple[Optional[dict[str, Any]], str]:
    """
    Choose a baseline that actually carries a detectable token for the binding.

    Priority (design: role preference is prefer-not-require; never return a
    flow that fails token detection):

      1. JWT-bearing flow for preferred role (binding.role_id / CLI --role)
      2. primary baseline when it already has a detectable token
      3. any recent JWT-bearing 2xx proxy_capture on the endpoint
      4. None (caller records no_baseline / no_token)
    """
    # 1. Preferred role first (even when primary already has a token).
    if preferred_role_id:
        found = _scan_jwt_bearing_flows(
            db_path,
            project_id,
            endpoint_id,
            binding,
            role_id=preferred_role_id,
        )
        if found is not None:
            return found, "role_preferred"

    # 2. Policy / best-flow baseline when it is JWT-bearing.
    if primary is not None and _flow_has_detectable_token(primary, binding):
        if primary.get("_baseline_source") == "baseline_policy":
            return primary, "baseline_policy"
        return primary, primary.get("_baseline_source") or "best_flow"

    # 3. Any role: recent JWT-bearing flow on this endpoint.
    found = _scan_jwt_bearing_flows(
        db_path, project_id, endpoint_id, binding, role_id=None
    )
    if found is not None:
        return found, "jwt_bearing_flow"

    # 4. Do not return a non-JWT primary — generate would only skip_no_token.
    return None, "none"


def select_baselines_for_binding(
    db_path: Path,
    project_id: str,
    binding: AuthSessionBinding,
    *,
    flow_id: Optional[str] = None,
    endpoint_id: Optional[str] = None,
    module_id: Optional[str] = None,
    role_id: Optional[str] = None,
    include_unsafe_methods: bool = False,
    stats: Optional[GenerateStats] = None,
) -> list[BaselineSelection]:
    """
    Purpose:
        Resolve baseline flows for generate per design priority order.
    Input:
        flow_id — explicit baseline (single)
        endpoint_id / module_id — scope (mutually exclusive with each other
            when both provided → ValueError)
        role_id — CLI override; else binding.role_id
    Output:
        list of BaselineSelection
    Side effects: May append to stats.skip_reasons.
    """
    if endpoint_id is not None and module_id is not None:
        raise ValueError("endpoint_id and module_id are mutually exclusive")

    stats = stats or GenerateStats()
    preferred_role = role_id or binding.role_id
    selections: list[BaselineSelection] = []

    # 1. Explicit --flow
    if flow_id:
        flow = load_flow(db_path, flow_id)
        if flow is None:
            stats.skipped_no_baseline += 1
            stats.skip_reasons.append(f"flow_not_found:{flow_id}")
            return []
        method = str(flow.get("method") or "")
        if not include_unsafe_methods and not is_safe_method(method):
            stats.skipped_unsafe_method += 1
            stats.skip_reasons.append(
                f"unsafe_method:{method}:{flow_id} (use --include-unsafe-methods)"
            )
            return []
        ep = flow.get("endpoint_id")
        selections.append(
            BaselineSelection(
                flow_id=flow_id,
                endpoint_id=str(ep) if ep else None,
                method=method,
                source="explicit_flow",
                flow=flow,
            )
        )
        return selections

    # 2/3. Testable endpoints in scope
    from talos.projects.policy import get_testable_endpoints

    testable = get_testable_endpoints(
        db_path,
        project_id,
        endpoint_id=endpoint_id,
        module_id=module_id,
    )
    if not testable:
        stats.skipped_not_testable += 1
        stats.skip_reasons.append("no_testable_endpoints")
        return []

    for ep in testable:
        ep_id = ep["id"]
        primary: Optional[dict[str, Any]] = None
        source = "best_flow"

        baseline_id = ep.get("baseline_flow_id")
        if baseline_id:
            primary = load_flow(db_path, baseline_id)
            if primary is not None:
                primary = dict(primary)
                primary["_baseline_source"] = "baseline_policy"
                source = "baseline_policy"

        if primary is None:
            primary = replay_db.get_best_flow_for_endpoint(db_path, ep_id)
            if primary is not None:
                primary = dict(primary)
                source = "best_flow"

        chosen, chosen_source = _prefer_jwt_bearing_flow(
            db_path,
            project_id,
            ep_id,
            binding,
            preferred_role,
            primary,
        )
        if chosen is None:
            stats.skipped_no_baseline += 1
            stats.skip_reasons.append(f"no_baseline:{ep_id}")
            continue

        method = str(chosen.get("method") or "")
        if not include_unsafe_methods and not is_safe_method(method):
            stats.skipped_unsafe_method += 1
            stats.skip_reasons.append(
                f"unsafe_method:{method}:{chosen.get('id')} "
                f"(endpoint {ep_id}; use --include-unsafe-methods)"
            )
            continue

        # Prefer role: if preferred_role set and chosen has different role,
        # still use chosen (jwt-bearing preference already applied).
        selections.append(
            BaselineSelection(
                flow_id=str(chosen["id"]),
                endpoint_id=ep_id,
                method=method,
                source=chosen_source or source,
                flow=chosen,
            )
        )

    return selections


def _mutation_summary_for_case(
    ctx: TokenContext,
    case: TestCaseDef,
    config: dict[str, Any],
    auth_type: str,
) -> str:
    """
    Produce mutation_summary via analyzer.apply (stdlib-only, no HTTP).
    Falls back to catalog description on apply failure.
    """
    try:
        analyzer = get_analyzer(auth_type)
        mutated = analyzer.apply(ctx, case.test_id, config)
        return mutated.mutation_summary or case.description
    except Exception:
        return case.description


def generate_for_binding_baseline(
    db_path: Path,
    binding: AuthSessionBinding,
    selection: BaselineSelection,
    *,
    force_refresh: bool = False,
    test_ids: Optional[list[str]] = None,
    families: Optional[list[str]] = None,
    stats: Optional[GenerateStats] = None,
) -> list[AuthSessionCandidate]:
    """
    Purpose:
        Generate candidates for one binding × one baseline flow.
    Side effects: DB inserts / force-refresh updates.
    """
    stats = stats or GenerateStats()
    stats.flows_processed += 1

    ctx, skip_reason = extract_token_context(selection.flow, binding)
    if ctx is None:
        stats.skipped_no_token += 1
        stats.skip_reasons.append(
            f"{skip_reason or 'token_not_detectable'}:"
            f"{binding.location}:{binding.name}:{selection.flow_id}"
        )
        return []

    config = suite_config_from_binding(binding.config_json)
    try:
        analyzer = get_analyzer(binding.auth_type)
    except KeyError:
        stats.skip_reasons.append(f"unsupported_auth_type:{binding.auth_type}")
        return []

    cases = analyzer.list_test_cases(ctx, config)
    test_id_filter = set(test_ids) if test_ids else None
    family_filter = set(families) if families else None

    fp = as_db.token_fingerprint(ctx.raw_token)
    created_rows: list[AuthSessionCandidate] = []

    for case in cases:
        if test_id_filter is not None and case.test_id not in test_id_filter:
            stats.skipped_test_filter += 1
            continue
        if family_filter is not None and case.family not in family_filter:
            stats.skipped_test_filter += 1
            continue

        existing = as_db.get_candidate_by_key(
            db_path, binding.id, case.test_id, selection.flow_id
        )
        summary = _mutation_summary_for_case(
            ctx, case, config, binding.auth_type
        )
        meta = {
            "baseline_source": selection.source,
            "observed_alg": ctx.header.get("alg"),
            "location": binding.location,
            "name": binding.name,
            "method": selection.method,
        }

        if existing is None:
            row = as_db.insert_candidate(
                db_path,
                binding_id=binding.id,
                baseline_flow_id=selection.flow_id,
                auth_type=binding.auth_type,
                test_id=case.test_id,
                test_family=case.family,
                title=case.title,
                mutation_summary=summary,
                endpoint_id=selection.endpoint_id,
                token_fingerprint=fp,
                risk_hint=case.risk_hint,
                status=STATUS_PENDING,
                meta=meta,
            )
            stats.created += 1
            created_rows.append(row)
            continue

        if force_refresh and existing.status in (STATUS_PENDING, STATUS_REJECTED):
            refreshed = as_db.force_refresh_candidate(
                db_path,
                existing.id,
                title=case.title,
                mutation_summary=summary,
                risk_hint=case.risk_hint,
                test_family=case.family,
                token_fingerprint=fp,
                meta=meta,
            )
            if refreshed is not None:
                stats.refreshed += 1
                created_rows.append(refreshed)
            else:
                stats.skipped_existing += 1
            continue

        # Default: skip any existing status (pending/rejected/approved/…).
        stats.skipped_existing += 1

    return created_rows


def generate_candidates(
    db_path: Path,
    project_id: str,
    *,
    binding_id: Optional[str] = None,
    flow_id: Optional[str] = None,
    endpoint_id: Optional[str] = None,
    module_id: Optional[str] = None,
    role_id: Optional[str] = None,
    test_ids: Optional[list[str]] = None,
    families: Optional[list[str]] = None,
    force_refresh: bool = False,
    include_unsafe_methods: bool = False,
) -> GenerateStats:
    """
    Purpose:
        Top-level generate entry: all bindings or one binding × scope.
    Output:
        GenerateStats
    Side effects: DB writes.
    """
    if endpoint_id is not None and module_id is not None:
        raise ValueError("endpoint_id and module_id are mutually exclusive")

    stats = GenerateStats()
    if binding_id:
        binding = as_db.get_binding(db_path, binding_id)
        if binding is None:
            stats.skip_reasons.append(f"binding_not_found:{binding_id}")
            return stats
        bindings = [binding]
    else:
        bindings = as_db.list_bindings(db_path)

    if not bindings:
        stats.skip_reasons.append("no_bindings")
        return stats

    for binding in bindings:
        stats.bindings_processed += 1
        try:
            selections = select_baselines_for_binding(
                db_path,
                project_id,
                binding,
                flow_id=flow_id,
                endpoint_id=endpoint_id,
                module_id=module_id,
                role_id=role_id,
                include_unsafe_methods=include_unsafe_methods,
                stats=stats,
            )
        except ValueError as exc:
            stats.skip_reasons.append(str(exc))
            continue

        for selection in selections:
            generate_for_binding_baseline(
                db_path,
                binding,
                selection,
                force_refresh=force_refresh,
                test_ids=test_ids,
                families=families,
                stats=stats,
            )

    log.info(
        "auth_session generate: created=%s refreshed=%s skipped_existing=%s "
        "no_token=%s unsafe=%s",
        stats.created,
        stats.refreshed,
        stats.skipped_existing,
        stats.skipped_no_token,
        stats.skipped_unsafe_method,
    )
    return stats
