"""
Module: talos.projects.bac.candidates

Purpose:
    Scan the access matrix and flows to produce BAC test candidates.

    A BacCandidate represents a testable (target_role, attacker_role, module) triple
    where the attacker role should NOT have access but the target role does.

    Candidate generation rules (manual access map):
        target_role:   server_expected = 'ALLOW' for the module.
        attacker_role: server_expected IN ('DENY', 'UNKNOWN') for the same module,
                       OR server_expected IS NULL with client_allowed = 'DENY'.
        target_role != attacker_role.
        At least one successful 2xx proxy_capture flow exists for
        (target_role, module) on a testable (qualified, non-excluded) endpoint.

    Candidate generation rules (privilege-diff, automatic):
        Roles carry an integer privilege rank (0 = highest).
        Same rank = peer accounts (no automatic pair).
        attacker.privilege > target.privilege (attacker is weaker).
        Built-in 'global' is excluded from automatic pairing.
        Endpoints with 2xx proxy_capture under the target role and none
        under the attacker role become candidates, replayed as the attacker.

    Endpoint Policy is the single authority for inclusion:
        - Only flows whose endpoint_id is in get_testable_endpoints() are used.
        - Excluded, unqualified, logout, and dangerous endpoints never produce
          BAC candidates (qualified=0 covers logout/dangerous).

    Execution scopes (mutually exclusive — at most one of endpoint_id / module_id):
        neither      — project scope: all testable endpoints
        endpoint_id  — single endpoint (policy lookup is O(1))
        module_id    — endpoints/flows inside one module

    The returned flow_ids are the candidate flows the attacker should attempt to
    access using their own lower-privilege session token.

Dependencies: sqlite3, pathlib, talos.projects.policy
Data flow:
    bac.cli → scan_candidates → get_testable_endpoints + project SQLite DB
Side effects: None (read-only).
"""

import sqlite3
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Optional


SOURCE_ACCESS_MAP = "access_map"
SOURCE_PRIVILEGE_DIFF = "privilege_diff"
SOURCE_BOTH = "both"
SOURCE_ALL = "all"
VALID_SOURCES = (SOURCE_ALL, SOURCE_ACCESS_MAP, SOURCE_PRIVILEGE_DIFF)


@dataclass
class BacCandidate:
    """
    Purpose:
        Represents a single testable BAC opportunity.

    Fields:
        target_role_id       — UUID of the role that legitimately has access.
        target_role_name     — Display name of the target role.
        attacker_role_id     — UUID of the role attempting unauthorized access.
        attacker_role_name   — Display name of the attacker role.
        module_id            — UUID of the module under test.
        module_name          — Display name of the module.
        flow_ids             — UUIDs of successful 2xx proxy_capture flows.
        source               — access_map | privilege_diff | both.
        target_privilege     — Target role rank when known.
        attacker_privilege   — Attacker role rank when known.
        endpoint_ids         — Endpoint UUIDs represented by flow_ids.
    """

    target_role_id: str
    target_role_name: str
    attacker_role_id: str
    attacker_role_name: str
    module_id: str
    module_name: str
    flow_ids: list[str] = field(default_factory=list)
    source: str = SOURCE_ACCESS_MAP
    target_privilege: Optional[int] = None
    attacker_privilege: Optional[int] = None
    endpoint_ids: list[str] = field(default_factory=list)


@dataclass
class PrivilegeGapEndpoint:
    """One endpoint present for the higher-privilege role and absent for the lower."""

    endpoint_id: str
    method: str
    host: str
    path: str
    module_id: str
    module_name: str
    flow_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "endpoint_id": self.endpoint_id,
            "method": self.method,
            "host": self.host,
            "path": self.path,
            "module_id": self.module_id,
            "module_name": self.module_name,
            "flow_ids": list(self.flow_ids),
        }


@dataclass
class PrivilegeGap:
    """Endpoints a weaker role never mapped that a stronger role did."""

    target_role_id: str
    target_role_name: str
    target_privilege: int
    attacker_role_id: str
    attacker_role_name: str
    attacker_privilege: int
    endpoints: list[PrivilegeGapEndpoint] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "target_role_id": self.target_role_id,
            "target_role_name": self.target_role_name,
            "target_privilege": self.target_privilege,
            "attacker_role_id": self.attacker_role_id,
            "attacker_role_name": self.attacker_role_name,
            "attacker_privilege": self.attacker_privilege,
            "endpoint_count": len(self.endpoints),
            "endpoints": [ep.to_dict() for ep in self.endpoints],
        }


def restrict_candidates_to_flows(
    candidates: list[BacCandidate],
    flow_ids: list[str],
) -> list[BacCandidate]:
    """
    Purpose:
        Keep only the operator-selected flow UUIDs on each BAC candidate.
        Candidates with no remaining flows are dropped.
    Input:
        candidates — scan_candidates() output.
        flow_ids   — operator `--flow` values (repeatable / comma-separated).
    Output:
        New BacCandidate list; flow_ids follow operator order.
    """
    from talos.projects.flow_scope import normalize_flow_ids

    wanted = normalize_flow_ids(flow_ids)
    if not wanted:
        return list(candidates)
    order = {fid: i for i, fid in enumerate(wanted)}
    wanted_set = set(wanted)
    out: list[BacCandidate] = []
    for candidate in candidates:
        kept = [fid for fid in candidate.flow_ids if fid in wanted_set]
        if not kept:
            continue
        kept.sort(key=lambda fid: order.get(fid, 10_000))
        out.append(replace(candidate, flow_ids=kept))
    return out


def exclude_endpoints_from_candidates(
    candidates: list[BacCandidate],
    endpoint_ids: list[str],
    db_path: Path,
) -> list[BacCandidate]:
    """
    Purpose:
        Drop operator-excluded endpoints from each BAC candidate for this
        run only. Matching flows are removed; candidates with no remaining
        flows are dropped.
    Input:
        candidates   — scan_candidates() / collect_bac_candidates() output.
        endpoint_ids — operator `--exclude-endpoint` values (repeatable /
                       comma-separated).
        db_path      — project talos.db, used to map flow_id → endpoint_id.
    Output:
        New BacCandidate list; remaining flow_ids keep original order.
    """
    from talos.projects.flow_scope import lookup_flows, normalize_flow_ids

    skip = set(normalize_flow_ids(endpoint_ids))
    if not skip:
        return list(candidates)

    all_flow_ids: list[str] = []
    seen_flows: set[str] = set()
    for candidate in candidates:
        for fid in candidate.flow_ids:
            if fid not in seen_flows:
                seen_flows.add(fid)
                all_flow_ids.append(fid)

    blocked_flows: set[str] = set()
    if all_flow_ids:
        refs, _missing = lookup_flows(db_path, all_flow_ids)
        for ref in refs:
            if ref.endpoint_id and ref.endpoint_id in skip:
                blocked_flows.add(ref.flow_id)

    out: list[BacCandidate] = []
    for candidate in candidates:
        kept_flows = [fid for fid in candidate.flow_ids if fid not in blocked_flows]
        if not kept_flows:
            continue
        kept_eps = [eid for eid in candidate.endpoint_ids if eid not in skip]
        out.append(replace(candidate, flow_ids=kept_flows, endpoint_ids=kept_eps))
    return out


def scan_candidates(
    db_path: Path,
    project_id: str,
    attacker_role_id: Optional[str] = None,
    endpoint_id: Optional[str] = None,
    module_id: Optional[str] = None,
) -> list[BacCandidate]:
    """
    Purpose:
        Scan the access matrix for BAC candidates, restricted to testable
        endpoints from the Endpoint Policy layer.
    Input:
        db_path          — Path to the project's talos.db.
        project_id       — Project identifier; scopes flow queries.
        attacker_role_id — When provided, only return candidates where the attacker
                           is this specific role.  None returns all role pairs.
        endpoint_id      — When provided, only generate candidates for this endpoint.
                           Mutually exclusive with module_id.
        module_id        — When provided, only generate candidates for this module.
                           Mutually exclusive with endpoint_id.
    Output:
        List of BacCandidate objects with flow_ids populated.
        Returns an empty list when no candidates exist.
    Side effects: None (read-only).
    Raises:
        ValueError when both endpoint_id and module_id are provided.
    """
    if not db_path.exists():
        return []

    if endpoint_id is not None and module_id is not None:
        raise ValueError(
            "endpoint_id and module_id are mutually exclusive execution scopes"
        )

    # Resolve testable endpoints via the Policy layer, scoped to the request.
    # endpoint_id → O(1) single-row lookup; module_id → module-local set;
    # neither → full project (existing behaviour).
    from talos.projects.policy import get_testable_endpoints

    testable = get_testable_endpoints(
        db_path,
        project_id,
        endpoint_id=endpoint_id,
        module_id=module_id,
    )
    testable_ids: set[str] = {ep["id"] for ep in testable}

    if not testable_ids:
        return []

    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row

        # (role_id, module_id) pairs where server_expected = 'ALLOW'
        allow_sql = """
            SELECT am.role_id, r.name AS role_name,
                   am.module_id, m.name AS module_name
            FROM access_map am
            JOIN roles  r ON r.id = am.role_id
            JOIN modules m ON m.id = am.module_id
            WHERE am.server_expected = 'ALLOW'
        """
        allow_params: list = []
        if module_id is not None:
            allow_sql += " AND am.module_id = ?"
            allow_params.append(module_id)

        allow_rows = conn.execute(allow_sql, allow_params).fetchall()

        # (role_id, module_id) pairs where access is restricted or uncertain.
        # Matches: server_expected DENY or UNKNOWN; or NULL server with client DENY.
        deny_sql = """
            SELECT am.role_id, r.name AS role_name, am.module_id
            FROM access_map am
            JOIN roles r ON r.id = am.role_id
            WHERE (
                   am.server_expected IN ('DENY', 'UNKNOWN')
                OR (am.server_expected IS NULL AND am.client_allowed = 'DENY')
            )
        """
        deny_params: list = []
        if module_id is not None:
            deny_sql += " AND am.module_id = ?"
            deny_params.append(module_id)

        deny_rows = conn.execute(deny_sql, deny_params).fetchall()

        # Build lookup: module_id → {attacker_role_id: role_name}
        deny_map: dict[str, dict[str, str]] = {}
        for row in deny_rows:
            if attacker_role_id is not None and row["role_id"] != attacker_role_id:
                continue
            deny_map.setdefault(row["module_id"], {})[row["role_id"]] = row["role_name"]

        candidates: list[BacCandidate] = []
        id_list = list(testable_ids)

        for allow_row in allow_rows:
            mod_id = allow_row["module_id"]
            tgt_role_id = allow_row["role_id"]

            attackers = deny_map.get(mod_id, {})
            for attk_role_id, attk_role_name in attackers.items():
                if attk_role_id == tgt_role_id:
                    # Skip self-pairing — same role can't attack itself.
                    continue

                # Find successful 2xx proxy_capture flows for (target_role, module)
                # restricted to testable (non-excluded) endpoints only.
                flow_ids = _select_testable_flow_ids(
                    conn,
                    project_id=project_id,
                    role_id=tgt_role_id,
                    module_id=mod_id,
                    testable_endpoint_ids=id_list,
                    endpoint_id=endpoint_id,
                )

                if not flow_ids:
                    # No observable testable flows to attack — skip.
                    continue

                candidates.append(
                    BacCandidate(
                        target_role_id=tgt_role_id,
                        target_role_name=allow_row["role_name"],
                        attacker_role_id=attk_role_id,
                        attacker_role_name=attk_role_name,
                        module_id=mod_id,
                        module_name=allow_row["module_name"],
                        flow_ids=flow_ids,
                        source=SOURCE_ACCESS_MAP,
                    )
                )

        return candidates


def _select_testable_flow_ids(
    conn: sqlite3.Connection,
    project_id: str,
    role_id: str,
    module_id: str,
    testable_endpoint_ids: list[str],
    endpoint_id: Optional[str] = None,
    limit: int = 100,
) -> list[str]:
    """
    Purpose:
        Select distinct successful 2xx proxy_capture flow IDs for a
        (role, module) pair, restricted to endpoints that are testable under
        Endpoint Policy. Matches qualification: status_code BETWEEN 200 AND 299.
    Input:
        conn                   — Open SQLite connection with Row factory.
        project_id             — Project identifier.
        role_id                — Target role UUID.
        module_id              — Module UUID.
        testable_endpoint_ids  — Endpoint IDs returned by get_testable_endpoints.
        endpoint_id            — Optional single-endpoint scope (already validated).
        limit                  — Max flows to return (newest first).
    Output:
        List of flow UUID strings (may be empty).
    Side effects: None.
    """
    if not testable_endpoint_ids:
        return []

    # Single-endpoint scope is a fast path (one bound param, no chunking).
    if endpoint_id is not None:
        rows = conn.execute(
            """
            SELECT DISTINCT f.id
            FROM flows f
            WHERE f.project_id  = ?
              AND f.role_id     = ?
              AND f.module_id   = ?
              AND f.endpoint_id = ?
              AND f.source      = 'proxy_capture'
              AND f.status_code BETWEEN 200 AND 299
            ORDER BY f.captured_at DESC
            LIMIT ?
            """,
            (project_id, role_id, module_id, endpoint_id, limit),
        ).fetchall()
        return [r["id"] for r in rows]

    # Chunk IN-list to stay under SQLite's default bound-parameter limit (~999).
    # Reserve a few slots for the fixed WHERE params.
    chunk_size = 900
    collected: list[str] = []
    seen: set[str] = set()

    for i in range(0, len(testable_endpoint_ids), chunk_size):
        chunk = testable_endpoint_ids[i : i + chunk_size]
        placeholders = ",".join("?" * len(chunk))
        remaining = limit - len(collected)
        if remaining <= 0:
            break
        rows = conn.execute(
            f"""
            SELECT DISTINCT f.id
            FROM flows f
            WHERE f.project_id  = ?
              AND f.role_id     = ?
              AND f.module_id   = ?
              AND f.endpoint_id IN ({placeholders})
              AND f.source      = 'proxy_capture'
              AND f.status_code BETWEEN 200 AND 299
            ORDER BY f.captured_at DESC
            LIMIT ?
            """,
            (project_id, role_id, module_id, *chunk, remaining),
        ).fetchall()
        for r in rows:
            fid = r["id"]
            if fid not in seen:
                seen.add(fid)
                collected.append(fid)
                if len(collected) >= limit:
                    return collected

    return collected


def _normalize_source(source: Optional[str]) -> str:
    """Normalize --source to all | access_map | privilege_diff."""
    value = (source or SOURCE_ALL).strip().lower().replace("-", "_")
    if value not in VALID_SOURCES:
        raise ValueError(
            f"Unknown candidate source '{source}'. "
            "Use all, access_map, or privilege_diff."
        )
    return value


def collect_bac_candidates(
    db_path: Path,
    project_id: str,
    attacker_role_id: Optional[str] = None,
    endpoint_id: Optional[str] = None,
    module_id: Optional[str] = None,
    source: str = SOURCE_ALL,
) -> list[BacCandidate]:
    """
    Purpose:
        Merge manual access-map candidates with automatic privilege-diff
        candidates. Identity (cookie session vs NTLM profile) is chosen later
        by the attacker role — this scan is auth-mode agnostic.
    """
    kind = _normalize_source(source)
    collected: list[BacCandidate] = []
    if kind in (SOURCE_ALL, SOURCE_ACCESS_MAP):
        collected.extend(
            scan_candidates(
                db_path,
                project_id,
                attacker_role_id=attacker_role_id,
                endpoint_id=endpoint_id,
                module_id=module_id,
            )
        )
    if kind in (SOURCE_ALL, SOURCE_PRIVILEGE_DIFF):
        collected.extend(
            scan_privilege_candidates(
                db_path,
                project_id,
                attacker_role_id=attacker_role_id,
                endpoint_id=endpoint_id,
                module_id=module_id,
            )
        )
    return _merge_candidates(collected)


def _merge_candidates(candidates: list[BacCandidate]) -> list[BacCandidate]:
    """Collapse identical (target, attacker, module) triples and union flows."""
    index: dict[tuple[str, str, str], BacCandidate] = {}
    order: list[tuple[str, str, str]] = []
    for cand in candidates:
        key = (cand.target_role_id, cand.attacker_role_id, cand.module_id)
        existing = index.get(key)
        if existing is None:
            index[key] = replace(
                cand,
                flow_ids=list(cand.flow_ids),
                endpoint_ids=list(cand.endpoint_ids),
            )
            order.append(key)
            continue
        seen_flows = set(existing.flow_ids)
        for fid in cand.flow_ids:
            if fid not in seen_flows:
                existing.flow_ids.append(fid)
                seen_flows.add(fid)
        seen_eps = set(existing.endpoint_ids)
        for eid in cand.endpoint_ids:
            if eid not in seen_eps:
                existing.endpoint_ids.append(eid)
                seen_eps.add(eid)
        if existing.source != cand.source:
            existing.source = SOURCE_BOTH
        if existing.target_privilege is None:
            existing.target_privilege = cand.target_privilege
        if existing.attacker_privilege is None:
            existing.attacker_privilege = cand.attacker_privilege
    return [index[k] for k in order]


def list_privilege_gaps(
    db_path: Path,
    project_id: str,
    attacker_role_id: Optional[str] = None,
    endpoint_id: Optional[str] = None,
    module_id: Optional[str] = None,
) -> list[PrivilegeGap]:
    """
    Purpose:
        Endpoints observed (2xx proxy_capture, testable) under a higher
        privilege role and never under a lower privilege role.
    """
    if not db_path.exists():
        return []
    if endpoint_id is not None and module_id is not None:
        raise ValueError(
            "endpoint_id and module_id are mutually exclusive execution scopes"
        )

    from talos.projects.db import migrate_project_db
    from talos.projects.policy import get_testable_endpoints

    migrate_project_db(db_path)

    testable = get_testable_endpoints(
        db_path,
        project_id,
        endpoint_id=endpoint_id,
        module_id=module_id,
    )
    testable_ids: set[str] = {ep["id"] for ep in testable}
    if not testable_ids:
        return []

    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        roles = conn.execute(
            """
            SELECT id, name, COALESCE(privilege, 0) AS privilege
            FROM roles
            WHERE name != 'global'
            ORDER BY privilege ASC, name ASC
            """
        ).fetchall()
        observed: dict[str, dict[str, dict]] = {}
        for role in roles:
            observed[role["id"]] = _observed_role_endpoints(
                conn,
                project_id=project_id,
                role_id=role["id"],
                testable_ids=testable_ids,
                endpoint_id=endpoint_id,
                module_id=module_id,
            )

    gaps: list[PrivilegeGap] = []
    for target in roles:
        target_eps = observed.get(target["id"], {})
        if not target_eps:
            continue
        for attacker in roles:
            if attacker["id"] == target["id"]:
                continue
            if attacker_role_id is not None and attacker["id"] != attacker_role_id:
                continue
            if int(attacker["privilege"]) <= int(target["privilege"]):
                # Attacker is not strictly weaker (peer or stronger).
                continue
            missing_ids = set(target_eps) - set(observed.get(attacker["id"], {}))
            if not missing_ids:
                continue
            endpoints = [
                PrivilegeGapEndpoint(
                    endpoint_id=eid,
                    method=target_eps[eid]["method"],
                    host=target_eps[eid]["host"],
                    path=target_eps[eid]["path"],
                    module_id=target_eps[eid]["module_id"],
                    module_name=target_eps[eid]["module_name"],
                    flow_ids=list(target_eps[eid]["flow_ids"]),
                )
                for eid in sorted(
                    missing_ids,
                    key=lambda x: (
                        target_eps[x]["method"],
                        target_eps[x]["host"],
                        target_eps[x]["path"],
                    ),
                )
            ]
            gaps.append(
                PrivilegeGap(
                    target_role_id=target["id"],
                    target_role_name=target["name"],
                    target_privilege=int(target["privilege"]),
                    attacker_role_id=attacker["id"],
                    attacker_role_name=attacker["name"],
                    attacker_privilege=int(attacker["privilege"]),
                    endpoints=endpoints,
                )
            )
    return gaps


def scan_privilege_candidates(
    db_path: Path,
    project_id: str,
    attacker_role_id: Optional[str] = None,
    endpoint_id: Optional[str] = None,
    module_id: Optional[str] = None,
) -> list[BacCandidate]:
    """
    Purpose:
        Turn privilege-diff gaps into BacCandidate rows grouped by module.
    """
    gaps = list_privilege_gaps(
        db_path,
        project_id,
        attacker_role_id=attacker_role_id,
        endpoint_id=endpoint_id,
        module_id=module_id,
    )
    candidates: list[BacCandidate] = []
    for gap in gaps:
        by_module: dict[str, BacCandidate] = {}
        for ep in gap.endpoints:
            if not ep.flow_ids:
                continue
            existing = by_module.get(ep.module_id)
            if existing is None:
                by_module[ep.module_id] = BacCandidate(
                    target_role_id=gap.target_role_id,
                    target_role_name=gap.target_role_name,
                    attacker_role_id=gap.attacker_role_id,
                    attacker_role_name=gap.attacker_role_name,
                    module_id=ep.module_id,
                    module_name=ep.module_name,
                    flow_ids=list(ep.flow_ids),
                    source=SOURCE_PRIVILEGE_DIFF,
                    target_privilege=gap.target_privilege,
                    attacker_privilege=gap.attacker_privilege,
                    endpoint_ids=[ep.endpoint_id],
                )
            else:
                seen = set(existing.flow_ids)
                for fid in ep.flow_ids:
                    if fid not in seen:
                        existing.flow_ids.append(fid)
                        seen.add(fid)
                if ep.endpoint_id not in existing.endpoint_ids:
                    existing.endpoint_ids.append(ep.endpoint_id)
        candidates.extend(by_module.values())
    return candidates


def _observed_role_endpoints(
    conn: sqlite3.Connection,
    project_id: str,
    role_id: str,
    testable_ids: set[str],
    endpoint_id: Optional[str] = None,
    module_id: Optional[str] = None,
    limit_per_endpoint: int = 20,
) -> dict[str, dict]:
    """
    Purpose:
        Map endpoint_id → latest 2xx proxy_capture metadata for one role.
    Output:
        {endpoint_id: {method, host, path, module_id, module_name, flow_ids}}
    """
    sql = """
        SELECT f.endpoint_id, f.module_id, m.name AS module_name,
               e.method, e.host, e.normalized_path AS path,
               f.id AS flow_id, f.captured_at
        FROM flows f
        JOIN endpoints e ON e.id = f.endpoint_id
        JOIN modules m ON m.id = f.module_id
        WHERE f.project_id = ?
          AND f.role_id = ?
          AND f.source = 'proxy_capture'
          AND f.status_code BETWEEN 200 AND 299
          AND f.endpoint_id IS NOT NULL
    """
    params: list = [project_id, role_id]
    if endpoint_id is not None:
        sql += " AND f.endpoint_id = ?"
        params.append(endpoint_id)
    if module_id is not None:
        sql += " AND f.module_id = ?"
        params.append(module_id)
    sql += " ORDER BY f.captured_at DESC"

    observed: dict[str, dict] = {}
    for row in conn.execute(sql, params):
        eid = row["endpoint_id"]
        if eid not in testable_ids:
            continue
        entry = observed.get(eid)
        if entry is None:
            observed[eid] = {
                "method": row["method"],
                "host": row["host"],
                "path": row["path"],
                "module_id": row["module_id"],
                "module_name": row["module_name"],
                "flow_ids": [row["flow_id"]],
            }
        elif len(entry["flow_ids"]) < limit_per_endpoint:
            if row["flow_id"] not in entry["flow_ids"]:
                entry["flow_ids"].append(row["flow_id"])
    return observed
