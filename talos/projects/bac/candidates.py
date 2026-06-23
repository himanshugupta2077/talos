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
        At least one 200 OK proxy_capture flow exists for (target_role, module).

    The returned flow_ids are the candidate flows the attacker should attempt to
    access using their own lower-privilege session token.

Dependencies: sqlite3, pathlib
Data flow:
    bac.cli → scan_candidates → project SQLite DB
Side effects: None (read-only).
"""

import sqlite3
from dataclasses import dataclass, field
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
        flow_ids           — UUIDs of 200 OK proxy_capture flows for (target_role, module).
    """

    target_role_id: str
    target_role_name: str
    attacker_role_id: str
    attacker_role_name: str
    module_id: str
    module_name: str
    flow_ids: list[str] = field(default_factory=list)


def scan_candidates(
    db_path: Path,
    project_id: str,
    attacker_role_id: Optional[str] = None,
) -> list[BacCandidate]:
    """
    Purpose:
        Scan the access matrix for BAC candidates.
    Input:
        db_path          — Path to the project's talos.db.
        project_id       — Project identifier; scopes flow queries.
        attacker_role_id — When provided, only return candidates where the attacker
                           is this specific role.  None returns all role pairs.
    Output:
        List of BacCandidate objects with flow_ids populated.
        Returns an empty list when no candidates exist.
    Side effects: None (read-only).
    """
    if not db_path.exists():
        return []

    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row

        # (role_id, module_id) pairs where server_expected = 'ALLOW'
        allow_rows = conn.execute(
            """
            SELECT am.role_id, r.name AS role_name,
                   am.module_id, m.name AS module_name
            FROM access_map am
            JOIN roles  r ON r.id = am.role_id
            JOIN modules m ON m.id = am.module_id
            WHERE am.server_expected = 'ALLOW'
            """
        ).fetchall()

        # (role_id, module_id) pairs where access is restricted or uncertain.
        # Matches: server_expected DENY or UNKNOWN; or NULL server with client DENY.
        deny_rows = conn.execute(
            """
            SELECT am.role_id, r.name AS role_name, am.module_id
            FROM access_map am
            JOIN roles r ON r.id = am.role_id
            WHERE am.server_expected IN ('DENY', 'UNKNOWN')
               OR (am.server_expected IS NULL AND am.client_allowed = 'DENY')
            """
        ).fetchall()

        # Build lookup: module_id → {attacker_role_id: role_name}
        deny_map: dict[str, dict[str, str]] = {}
        for row in deny_rows:
            if attacker_role_id is not None and row["role_id"] != attacker_role_id:
                continue
            deny_map.setdefault(row["module_id"], {})[row["role_id"]] = row["role_name"]

        candidates: list[BacCandidate] = []

        for allow_row in allow_rows:
            mod_id = allow_row["module_id"]
            tgt_role_id = allow_row["role_id"]

            attackers = deny_map.get(mod_id, {})
            for attk_role_id, attk_role_name in attackers.items():
                if attk_role_id == tgt_role_id:
                    # Skip self-pairing — same role can't attack itself.
                    continue

                # Find 200 OK proxy_capture flows for (target_role, module).
                flow_rows = conn.execute(
                    """
                    SELECT DISTINCT f.id
                    FROM flows f
                    WHERE f.project_id = ?
                      AND f.role_id    = ?
                      AND f.module_id  = ?
                      AND f.source     = 'proxy_capture'
                      AND f.status_code = 200
                    ORDER BY f.captured_at DESC
                    LIMIT 100
                    """,
                    (project_id, tgt_role_id, mod_id),
                ).fetchall()

                if not flow_rows:
                    # No observable flows to attack — skip.
                    continue

                candidates.append(
                    BacCandidate(
                        target_role_id=tgt_role_id,
                        target_role_name=allow_row["role_name"],
                        attacker_role_id=attk_role_id,
                        attacker_role_name=attk_role_name,
                        module_id=mod_id,
                        module_name=allow_row["module_name"],
                        flow_ids=[r["id"] for r in flow_rows],
                    )
                )

        return candidates
