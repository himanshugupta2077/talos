"""
Module: talos.projects.exclude_results

Purpose:
    Exclude endpoints (and optionally a path rule) and purge already-queued
    or already-recorded results for the same selector:

        - pending/paused scheduler jobs
        - findings (Talos DB)
        - Burp extension snapshot rows (~/.talos/burp/<project>.jsonl)

    Selectors: flow UUID, endpoint UUID(s), path glob/prefix, or regex.

    Scheduler resume also calls skip_excluded_queue_jobs() so jobs for
    endpoints excluded while the queue was paused never run.

Dependencies: re, sqlite3, dataclasses, urllib.parse
              talos.projects.policy, talos.scheduler.db, talos.findings.db,
              talos.burp.snapshot
Data flow:
    CLI / Control Panel → exclude_and_purge() → policy + scheduler + findings
        + burp snapshot
    scheduler resume → skip_excluded_queue_jobs()
Side effects:
    Marks endpoints excluded; may add a path rule; skips queue jobs;
    deletes findings; rewrites the Burp JSONL snapshot.
"""

from __future__ import annotations

import json
import re
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Optional
from urllib.parse import urlparse

from talos.burp.snapshot import finding_record_id, remove_matching_records
from talos.findings.db import delete_findings
from talos.projects.db import migrate_project_db
from talos.projects.policy import (
    bulk_set_excluded,
    get_effective_policy,
    list_path_rules,
    path_matches_pattern,
    set_path_rule,
)
from talos.scheduler import db as sched_db
from talos.scheduler.job import STATUS_PAUSED, STATUS_PENDING


VALID_KINDS = ("flow", "endpoint", "path", "regex")


class ExcludeResultsError(ValueError):
    """Selector could not be resolved (unknown flow/endpoint, bad regex)."""


@dataclass
class ExclusionMatch:
    """Resolved targets for one exclude-results selector."""

    kind: str
    selector: str
    endpoint_ids: list[str] = field(default_factory=list)
    flow_ids: list[str] = field(default_factory=list)
    path_pred: Optional[Callable[[str], bool]] = None


@dataclass
class ExcludeResultsOutcome:
    """Counts returned to CLI / Control Panel after a purge."""

    action: str = "exclude-results"
    kind: str = ""
    selector: str = ""
    endpoint_ids: list[str] = field(default_factory=list)
    endpoints_excluded: int = 0
    path_rule_id: Optional[str] = None
    jobs_skipped: int = 0
    findings_deleted: int = 0
    burp_records_removed: int = 0

    def to_dict(self) -> dict:
        return {
            "action": self.action,
            "kind": self.kind,
            "selector": self.selector,
            "endpoint_ids": list(self.endpoint_ids),
            "affected": self.endpoints_excluded,
            "count": self.endpoints_excluded,
            "endpoints_excluded": self.endpoints_excluded,
            "path_rule_id": self.path_rule_id,
            "jobs_skipped": self.jobs_skipped,
            "findings_deleted": self.findings_deleted,
            "burp_records_removed": self.burp_records_removed,
        }


def _connect(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    return conn


def _compile_regex(pattern: str) -> re.Pattern[str]:
    try:
        return re.compile(pattern, re.IGNORECASE)
    except re.error as exc:
        raise ExcludeResultsError(f"Invalid regex '{pattern}': {exc}") from exc


def _regex_pred(pattern: str) -> Callable[[str], bool]:
    compiled = _compile_regex(pattern)

    def _match(text: str) -> bool:
        return bool(text) and compiled.search(text) is not None

    return _match


def _path_pred(pattern: str) -> Callable[[str], bool]:
    def _match(text: str) -> bool:
        return bool(text) and path_matches_pattern(text, pattern)

    return _match


def _collapse_dot_segments(text: str) -> str:
    """Turn `/tap-ui/./chunk-X.js` into `/tap-ui/chunk-X.js`."""
    prev = text
    while True:
        nxt = prev.replace("/./", "/")
        if nxt == prev:
            return nxt
        prev = nxt


def location_texts(
    *,
    path: str = "",
    host: str = "",
    url: str = "",
    extra: Optional[Iterable[str]] = None,
) -> list[str]:
    """
    Strings a path/URL regex should be tested against.

    Testers often paste a full-URL regex (`https://host/…/chunk-X.js`) into
    a path field. Matching only `normalized_path` (`/…/chunk-X.js`) misses
    those. Include path, host+path, full URL, and collapsed `/./` variants.
    """
    texts: list[str] = []
    seen: set[str] = set()

    def add(raw: str) -> None:
        value = (raw or "").strip()
        if not value or value in seen:
            return
        seen.add(value)
        texts.append(value)
        collapsed = _collapse_dot_segments(value)
        if collapsed != value and collapsed not in seen:
            seen.add(collapsed)
            texts.append(collapsed)

    add(path)
    add(url)
    add(host)
    parsed_path = ""
    if url:
        parsed = urlparse(url)
        parsed_path = parsed.path or ""
        add(parsed_path)
        if parsed.netloc:
            add(parsed.netloc + parsed_path)
            if parsed.scheme:
                add(f"{parsed.scheme}://{parsed.netloc}{parsed_path}")
    resolved_path = path or parsed_path
    if host and resolved_path:
        host_clean = host.rstrip("/")
        suffix = (
            resolved_path
            if resolved_path.startswith("/")
            else f"/{resolved_path}"
        )
        if "://" in host_clean:
            add(host_clean + suffix)
        else:
            add("https://" + host_clean + suffix)
            add("http://" + host_clean + suffix)
    for item in extra or []:
        add(str(item))
    return texts


def _pred_hits(pred: Callable[[str], bool], texts: Iterable[str]) -> bool:
    return any(pred(text) for text in texts if text)


def resolve_match(
    db_path: Path,
    project_id: str,
    kind: str,
    selector: str,
    extra_endpoint_ids: Optional[list[str]] = None,
) -> ExclusionMatch:
    """
    Purpose:
        Turn a flow / endpoint / path / regex selector into endpoint and
        flow ids plus an optional path predicate.
    """
    kind = (kind or "").strip().lower()
    selector = (selector or "").strip()
    if kind not in VALID_KINDS:
        raise ExcludeResultsError(
            f"Unknown selector kind '{kind}'. Use flow, endpoint, path, or regex."
        )
    if kind != "endpoint" and not selector:
        raise ExcludeResultsError(f"{kind} selector must not be empty.")

    migrate_project_db(db_path)
    endpoint_ids: list[str] = []
    flow_ids: list[str] = []
    pred: Optional[Callable[[str], bool]] = None

    if kind == "flow":
        with _connect(db_path) as conn:
            row = conn.execute(
                """
                SELECT id, endpoint_id, path FROM flows WHERE id = ?
                """,
                (selector,),
            ).fetchone()
        if row is None:
            raise ExcludeResultsError(f"Flow '{selector}' not found.")
        flow_ids.append(row["id"])
        if row["endpoint_id"]:
            endpoint_ids.append(str(row["endpoint_id"]))
        path = str(row["path"] or "")
        if path:
            pred = lambda p, target=path.lower(): (p or "").lower() == target

    elif kind == "endpoint":
        ids = list(extra_endpoint_ids or [])
        if selector:
            ids.append(selector)
        ids = list(dict.fromkeys(i.strip() for i in ids if i and i.strip()))
        if not ids:
            raise ExcludeResultsError("At least one endpoint UUID is required.")
        missing = _missing_endpoints(db_path, ids)
        if missing:
            raise ExcludeResultsError(
                "Endpoint(s) not found: " + ", ".join(missing)
            )
        endpoint_ids = ids

    elif kind == "path":
        pred = _path_pred(selector)
        endpoint_ids = _endpoints_matching(db_path, pred)

    elif kind == "regex":
        pred = _regex_pred(selector)
        endpoint_ids = _endpoints_matching(db_path, pred)

    if endpoint_ids:
        flow_ids.extend(_flow_ids_for_endpoints(db_path, endpoint_ids))
        flow_ids = list(dict.fromkeys(flow_ids))

    return ExclusionMatch(
        kind=kind,
        selector=selector,
        endpoint_ids=endpoint_ids,
        flow_ids=flow_ids,
        path_pred=pred,
    )


def _missing_endpoints(db_path: Path, ids: list[str]) -> list[str]:
    with _connect(db_path) as conn:
        placeholders = ",".join("?" * len(ids))
        rows = conn.execute(
            f"SELECT id FROM endpoints WHERE id IN ({placeholders})",
            ids,
        ).fetchall()
    have = {r[0] for r in rows}
    return [eid for eid in ids if eid not in have]


def _endpoints_matching(
    db_path: Path, pred: Callable[[str], bool]
) -> list[str]:
    with _connect(db_path) as conn:
        rows = conn.execute(
            "SELECT id, path, normalized_path, host FROM endpoints"
        ).fetchall()
    matched: list[str] = []
    for row in rows:
        texts = location_texts(
            path=str(row["normalized_path"] or row["path"] or ""),
            host=str(row["host"] or ""),
            extra=[str(row["path"] or "")],
        )
        if _pred_hits(pred, texts):
            matched.append(str(row["id"]))
    return matched


def _flow_ids_for_endpoints(db_path: Path, endpoint_ids: list[str]) -> list[str]:
    if not endpoint_ids:
        return []
    with _connect(db_path) as conn:
        placeholders = ",".join("?" * len(endpoint_ids))
        rows = conn.execute(
            f"SELECT id FROM flows WHERE endpoint_id IN ({placeholders})",
            endpoint_ids,
        ).fetchall()
    return [str(r[0]) for r in rows]


def _endpoint_path_map(db_path: Path) -> dict[str, str]:
    with _connect(db_path) as conn:
        rows = conn.execute(
            "SELECT id, path, normalized_path FROM endpoints"
        ).fetchall()
    return {
        str(r["id"]): str(r["normalized_path"] or r["path"] or "")
        for r in rows
    }


def _excluded_endpoint_ids(db_path: Path, project_id: str) -> set[str]:
    """Endpoint ids whose effective policy is excluded (flag or path rule)."""
    paths = _endpoint_path_map(db_path)
    excluded: set[str] = set()
    with _connect(db_path) as conn:
        for row in conn.execute(
            "SELECT endpoint_id FROM endpoint_policy WHERE excluded = 1"
        ):
            excluded.add(str(row[0]))
    for eid, path in paths.items():
        if eid in excluded:
            continue
        policy = get_effective_policy(db_path, project_id, eid, path or "/")
        if policy.excluded:
            excluded.add(eid)
    return excluded


def _job_rows(db_path: Path) -> list[sqlite3.Row]:
    with _connect(db_path) as conn:
        return list(
            conn.execute(
                """
                SELECT sj.job_id, sj.endpoint_id, sj.flow_id,
                       f.endpoint_id AS flow_endpoint_id,
                       f.path AS flow_path,
                       f.host AS flow_host,
                       f.url AS flow_url,
                       e.normalized_path AS endpoint_path,
                       e.host AS endpoint_host,
                       ef.normalized_path AS flow_endpoint_path,
                       ef.host AS flow_endpoint_host
                FROM scheduler_jobs sj
                LEFT JOIN flows f ON f.id = sj.flow_id
                LEFT JOIN endpoints e ON e.id = sj.endpoint_id
                LEFT JOIN endpoints ef ON ef.id = f.endpoint_id
                WHERE sj.status IN (?, ?)
                """,
                (STATUS_PENDING, STATUS_PAUSED),
            ).fetchall()
        )


def _job_matches_exclusion(row: sqlite3.Row, match: ExclusionMatch) -> bool:
    ep = str(row["endpoint_id"] or row["flow_endpoint_id"] or "")
    if ep and ep in set(match.endpoint_ids):
        return True
    flow_id = str(row["flow_id"] or "")
    if flow_id and flow_id in set(match.flow_ids):
        return True
    if match.path_pred is None:
        return False
    texts = location_texts(
        path=str(
            row["endpoint_path"]
            or row["flow_endpoint_path"]
            or row["flow_path"]
            or ""
        ),
        host=str(
            row["endpoint_host"]
            or row["flow_endpoint_host"]
            or row["flow_host"]
            or ""
        ),
        url=str(row["flow_url"] or ""),
        extra=[
            str(row["flow_path"] or ""),
            str(row["endpoint_path"] or ""),
            str(row["flow_endpoint_path"] or ""),
        ],
    )
    return _pred_hits(match.path_pred, texts)


def skip_jobs_for_match(db_path: Path, match: ExclusionMatch) -> int:
    """Skip pending/paused jobs that belong to the resolved match."""
    job_ids = [
        str(row["job_id"])
        for row in _job_rows(db_path)
        if _job_matches_exclusion(row, match)
    ]
    return sched_db.skip_jobs(db_path, job_ids, "endpoint_excluded")


def skip_excluded_queue_jobs(db_path: Path, project_id: str) -> int:
    """
    Purpose:
        Drop pending/paused scheduler jobs whose resolved endpoint is
        excluded by endpoint_policy or a matching path rule.
        Called on scheduler resume/play and after exclude mutations.
    Output:
        Number of jobs marked skipped.
    """
    migrate_project_db(db_path)
    excluded = _excluded_endpoint_ids(db_path, project_id)
    rules = [
        r for r in list_path_rules(db_path, project_id) if r.get("excluded")
    ]
    job_ids: list[str] = []
    for row in _job_rows(db_path):
        ep = str(row["endpoint_id"] or row["flow_endpoint_id"] or "")
        if ep and ep in excluded:
            job_ids.append(str(row["job_id"]))
            continue
        path = str(
            row["endpoint_path"]
            or row["flow_endpoint_path"]
            or row["flow_path"]
            or ""
        )
        if path and any(
            path_matches_pattern(path, r["pattern"]) for r in rules
        ):
            job_ids.append(str(row["job_id"]))
    return sched_db.skip_jobs(db_path, job_ids, "endpoint_excluded")


def job_is_excluded(db_path: Path, project_id: str, endpoint_id: Optional[str], path: str = "") -> bool:
    """True when the job's endpoint (or path) is excluded by effective policy."""
    if endpoint_id:
        policy = get_effective_policy(
            db_path, project_id, endpoint_id, path or "/"
        )
        return bool(policy.excluded)
    if not path:
        return False
    return any(
        r.get("excluded") and path_matches_pattern(path, r["pattern"])
        for r in list_path_rules(db_path, project_id)
    )


def _urls_from_evidence_data(raw: object) -> list[str]:
    if raw is None:
        return []
    if isinstance(raw, (bytes, bytearray)):
        raw = raw.decode("utf-8", errors="replace")
    parsed: object = raw
    if isinstance(raw, str):
        text = raw.strip()
        if not text:
            return []
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            return [text] if ("://" in text or text.startswith("/")) else []
    if not isinstance(parsed, dict):
        return []
    out: list[str] = []
    for key in ("url", "path", "host"):
        value = parsed.get(key)
        if value:
            out.append(str(value))
    return out


def _finding_ids_for_match(db_path: Path, match: ExclusionMatch) -> list[str]:
    ids: list[str] = []
    with _connect(db_path) as conn:
        if match.endpoint_ids:
            placeholders = ",".join("?" * len(match.endpoint_ids))
            rows = conn.execute(
                f"SELECT id FROM findings WHERE endpoint_id IN ({placeholders})",
                match.endpoint_ids,
            ).fetchall()
            ids.extend(str(r[0]) for r in rows)
        if match.flow_ids:
            ph = ",".join("?" * len(match.flow_ids))
            rows = conn.execute(
                f"""
                SELECT DISTINCT finding_id FROM finding_evidence
                WHERE reference_id IN ({ph})
                """,
                match.flow_ids,
            ).fetchall()
            ids.extend(str(r[0]) for r in rows)
        if match.path_pred is not None:
            pred = match.path_pred
            rows = conn.execute(
                """
                SELECT f.id, f.title, e.host, e.path, e.normalized_path
                FROM findings f
                LEFT JOIN endpoints e ON e.id = f.endpoint_id
                """
            ).fetchall()
            for row in rows:
                texts = location_texts(
                    path=str(row["normalized_path"] or row["path"] or ""),
                    host=str(row["host"] or ""),
                    extra=[str(row["title"] or ""), str(row["path"] or "")],
                )
                if _pred_hits(pred, texts):
                    ids.append(str(row["id"]))
            ev_rows = conn.execute(
                """
                SELECT ev.finding_id, ev.data, fl.url, fl.host, fl.path
                FROM finding_evidence ev
                LEFT JOIN flows fl ON fl.id = ev.reference_id
                """
            ).fetchall()
            for row in ev_rows:
                extras = _urls_from_evidence_data(row["data"])
                texts = location_texts(
                    path=str(row["path"] or ""),
                    host=str(row["host"] or ""),
                    url=str(row["url"] or ""),
                    extra=extras,
                )
                if _pred_hits(pred, texts):
                    ids.append(str(row["finding_id"]))
            try:
                occ_rows = conn.execute(
                    """
                    SELECT ev.finding_id, so.url, so.host, so.path
                    FROM finding_evidence ev
                    JOIN source_occurrences so ON so.id = ev.reference_id
                    """
                ).fetchall()
            except sqlite3.OperationalError:
                occ_rows = []
            for row in occ_rows:
                texts = location_texts(
                    path=str(row["path"] or ""),
                    host=str(row["host"] or ""),
                    url=str(row["url"] or ""),
                )
                if _pred_hits(pred, texts):
                    ids.append(str(row["finding_id"]))
    return list(dict.fromkeys(ids))


def exclude_and_purge(
    db_path: Path,
    project_id: str,
    kind: str,
    selector: str,
    extra_endpoint_ids: Optional[list[str]] = None,
) -> ExcludeResultsOutcome:
    """
    Purpose:
        Exclude matching endpoints (and a path rule when kind=path) then
        remove matching scheduler jobs, findings, and Burp snapshot rows.
    """
    match = resolve_match(
        db_path, project_id, kind, selector, extra_endpoint_ids
    )
    outcome = ExcludeResultsOutcome(
        kind=match.kind,
        selector=match.selector,
        endpoint_ids=list(match.endpoint_ids),
    )

    if match.endpoint_ids:
        result = bulk_set_excluded(db_path, match.endpoint_ids, True)
        outcome.endpoints_excluded = int(result.get("affected") or 0)

    if match.kind == "path":
        existing_priority = None
        for rule in list_path_rules(db_path, project_id):
            if rule["pattern"] == match.selector:
                existing_priority = rule["priority"]
                break
        outcome.path_rule_id = set_path_rule(
            db_path,
            project_id,
            match.selector,
            priority=existing_priority,
            excluded=True,
        )

    outcome.jobs_skipped = skip_jobs_for_match(db_path, match)

    finding_ids = _finding_ids_for_match(db_path, match)
    outcome.findings_deleted = delete_findings(db_path, finding_ids)

    record_ids = {finding_record_id(fid) for fid in finding_ids}
    outcome.burp_records_removed = remove_matching_records(
        project_id,
        record_ids=record_ids,
        endpoint_ids=set(match.endpoint_ids),
        path_pred=match.path_pred,
    )
    return outcome
