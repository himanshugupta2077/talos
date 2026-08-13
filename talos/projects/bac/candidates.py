"""
Module: talos.projects.bac.candidates

Purpose:
    Scan the access matrix and flows to produce BAC test candidates.

    A BacCandidate represents a testable (target_role, attacker_role, module) triple
    where the attacker role should NOT have access but the target role does.

    Candidate generation rules:
        target_role:   server_expected = 'ALLOW' for the module.
        attacker_role: server_expected IN ('DENY', 'UNKNOWN') for the same module,
                       OR server_expected IS NULL with client_allowed = 'DENY'.
        target_role != attacker_role.
        At least one successful 2xx proxy_capture flow exists for
        (target_role, module) on a testable (qualified, non-excluded) endpoint.

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


@dataclass
class BacCandidate:
    """
    Purpose:
        Represents a single testable BAC opportunity derived from the access matrix.

    Fields:
        target_role_id     — UUID of the role that legitimately has access.
        target_role_name   — Display name of the target role.
        attacker_role_id   — UUID of the role attempting unauthorized access.
        attacker_role_name — Display name of the attacker role.
        module_id          — UUID of the module under test.
        module_name        — Display name of the module.
        flow_ids           — UUIDs of successful 2xx proxy_capture flows for
                             (target_role, module) on testable endpoints only.
    """

    target_role_id: str
    target_role_name: str
    attacker_role_id: str
    attacker_role_name: str
    module_id: str
    module_name: str
    flow_ids: list[str] = field(default_factory=list)


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
