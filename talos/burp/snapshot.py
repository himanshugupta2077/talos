"""
Module: talos.burp.snapshot

Purpose:
    Per-Talos-project snapshot of Burp-tree rows. The extension hydrates
    from these files so the tab survives Community (temp Burp projects)
    and Burp project switches.

    Layout (always under ~/.talos, matching burp-ingest.port)::

        ~/.talos/burp/<project_id>.jsonl

    Each file starts with a meta line, then flat record lines. Values are
    strings so the Burp extension's JSON parser can read them.

Dependencies: json, os, pathlib; talos.burp.trace;
    talos.proxy.runtime.lock, talos.proxy.runtime.atomic_io
Data flow: maybe_apply_burp_headers / prepare_send_headers → record_request
Side effects: Appends (and occasionally compacts) files under ~/.talos/burp/.
"""

from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Optional
from urllib.parse import urlparse

from talos.burp.trace import BurpTrace, normalize_host
from talos.proxy.runtime.atomic_io import atomic_write_text
from talos.proxy.runtime.lock import RuntimeLock

logger = logging.getLogger(__name__)

KIND_META = "meta"
KIND_RECORD = "record"
KIND_RESPONSE = "response"
MAX_RECORDS = 2000
MAX_REQUEST_HTTP = 32_768
MAX_RESPONSE_HTTP = 65_536
_SAFE_ID = re.compile(r"[^A-Za-z0-9._-]+")


def snapshot_root() -> Path:
    """
    Purpose:
        Directory that holds per-project JSONL snapshots.
    Output:
        TALOS_BURP_DIR when set, else ~/.talos/burp.
    Side effects: None.
    """
    raw = (os.environ.get("TALOS_BURP_DIR") or "").strip()
    if raw:
        return Path(raw).expanduser()
    return Path.home() / ".talos" / "burp"


def safe_project_id(project_id: str) -> str:
    """
    Purpose:
        Keep a project id filesystem-safe (no path traversal).
    Output:
        Sanitized slug, or empty when nothing remains.
    """
    cleaned = _SAFE_ID.sub("", (project_id or "").strip())[:128]
    if not cleaned or cleaned in {".", ".."} or cleaned.startswith("."):
        return ""
    return cleaned


def ensure_project_snapshot(project_id: str, project_name: str = "") -> Optional[Path]:
    """
    Purpose:
        Create ~/.talos/burp/<id>.jsonl (meta line only) so the Burp
        picker lists the project before any test has run.
    Output:
        Snapshot path, or None when the id is unsafe/empty.
    Side effects: Creates the burp directory and a meta-only file.
    """
    pid = safe_project_id(project_id)
    path = snapshot_path(pid)
    if path is None:
        return None
    name = (project_name or "").strip() or pid
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_suffix(path.suffix + ".lock")
    try:
        with RuntimeLock(lock_path):
            if path.exists() and path.stat().st_size > 0:
                return path
            path.write_text(_line(_meta_row(pid, name)), encoding="utf-8")
    except OSError as exc:
        logger.debug("burp snapshot ensure failed: %s", exc)
        return None
    return path


def remove_project_snapshot(project_id: str) -> None:
    """Remove the snapshot file when a project is deleted."""
    path = snapshot_path(project_id)
    if path is None:
        return
    for target in (path, path.with_suffix(path.suffix + ".lock")):
        try:
            target.unlink(missing_ok=True)
        except OSError:
            pass


def rename_project_snapshot(old_id: str, new_id: str, new_name: str = "") -> None:
    """Move/rename a snapshot when the Talos project id or name changes."""
    old_path = snapshot_path(old_id)
    new_path = snapshot_path(new_id)
    if new_path is None:
        return
    if old_path is not None and old_path.exists() and old_path != new_path:
        try:
            new_path.parent.mkdir(parents=True, exist_ok=True)
            old_path.replace(new_path)
        except OSError as exc:
            logger.debug("burp snapshot rename failed: %s", exc)
    ensure_project_snapshot(new_id, new_name)


def record_from_flow(
    *,
    project_id: str,
    engine: str,
    flow: Mapping[str, Any],
    extras: Optional[Mapping[str, Any]] = None,
    project_name: str = "",
    record_id: str = "",
    status: int = 0,
    endpoint_id: str = "",
    tree_label: str = "",
) -> Optional[Path]:
    """
    Purpose:
        Snapshot one result that has a stored flow (passive, errors,
        findings, or an active test that did not go through
        prepare_send_headers).
    """
    from talos.burp.trace import attach_burp_trace, trace_from_flow_meta

    pid, pname = resolve_project_identity(
        project_id=project_id,
        project_name=project_name,
    )
    if not pid:
        return None
    ensure_project_snapshot(pid, pname)
    meta: dict[str, Any] = {}
    attach_burp_trace(
        meta,
        engine=engine,
        flow=flow,
        extras=extras,
        project_id=pid,
        project_name=pname,
        record_id=record_id,
        endpoint_id=str(endpoint_id or flow.get("endpoint_id") or ""),
        host=str(flow.get("host") or ""),
        tree_label=tree_label,
    )
    trace = trace_from_flow_meta(meta)
    if trace is None:
        return None
    path_out = record_request(
        trace,
        method=str(flow.get("method") or ""),
        host=normalize_host(flow.get("host") or ""),
        path=str(flow.get("path") or ""),
        url=str(flow.get("url") or ""),
        headers=flow.get("request_headers"),
        body=flow.get("request_body"),
        status=status,
    )
    if path_out is not None and (status or flow.get("response_headers") or flow.get("response_body")):
        record_http_response(
            {"burp": {"record_id": trace.record_id, "project_id": pid}},
            project_id=pid,
            status=status or _as_int(flow.get("status_code")),
            headers=flow.get("response_headers"),
            body=flow.get("response_body"),
        )
    return path_out


def record_http_response(
    flow_meta: Optional[Mapping[str, Any]],
    *,
    project_id: str = "",
    status: int = 0,
    headers: Any = None,
    body: Any = None,
    reason: str = "",
) -> Optional[Path]:
    """
    Purpose:
        Append a response line for an existing snapshot record so Burp
        can show status + body after a test completes.
    """
    burp = flow_meta.get("burp") if isinstance(flow_meta, Mapping) else None
    if not isinstance(burp, Mapping):
        return None
    record_id = str(burp.get("record_id") or "").strip()
    pid = safe_project_id(project_id or str(burp.get("project_id") or ""))
    if not record_id or not pid:
        return None
    path_out = snapshot_path(pid)
    if path_out is None:
        return None
    raw = build_response_http(status=status, headers=headers, body=body, reason=reason)
    _append_row(
        path_out,
        pid,
        str(burp.get("project_name") or pid),
        {
            "kind": KIND_RESPONSE,
            "id": record_id,
            "record_id": record_id,
            "status": str(int(status or 0)),
            "response_http": raw,
            "project_id": pid,
        },
    )
    return path_out


def record_send_response(flow_meta: Optional[Mapping[str, Any]], project_id: str, resp: Any) -> None:
    """Best-effort snapshot of an httpx response. Never raises."""
    try:
        record_http_response(
            flow_meta,
            project_id=project_id,
            status=int(getattr(resp, "status_code", 0) or 0),
            headers=getattr(resp, "headers", None),
            body=getattr(resp, "content", None),
            reason=str(getattr(resp, "reason_phrase", "") or ""),
        )
    except Exception:
        logger.debug("burp response snapshot failed", exc_info=True)


def record_send_failure(
    flow_meta: Optional[Mapping[str, Any]],
    project_id: str,
    error: str,
) -> None:
    """Snapshot a failed send so the Burp tab is not left request-only."""
    try:
        text = (error or "request failed").strip() or "request failed"
        record_http_response(
            flow_meta,
            project_id=project_id,
            status=502,
            headers={"Content-Type": "text/plain"},
            body=text,
            reason="Bad Gateway",
        )
    except Exception:
        logger.debug("burp failure snapshot failed", exc_info=True)


def backfill_responses_from_db(project_id: str, db_path: Path) -> int:
    """
    Purpose:
        Write missing response lines from stored flows so the Burp tab
        can show status/body for tests that ran before responses were
        snapshotted (or that failed without a live Burp pair).
    Output:
        Number of response lines appended.
    """
    pid = safe_project_id(project_id)
    if not pid or db_path is None:
        return 0
    records = load_records(pid)
    missing = [
        row
        for row in records
        if not (row.get("response_http") or "").strip()
    ]
    if not missing:
        return 0
    wanted = {
        (row.get("record_id") or row.get("id") or "").strip()
        for row in missing
    }
    wanted.discard("")
    if not wanted:
        return 0
    by_id: dict[str, dict[str, Any]] = {}
    try:
        import sqlite3

        with sqlite3.connect(str(db_path)) as conn:
            conn.row_factory = sqlite3.Row
            for item in conn.execute(
                """
                SELECT status_code, response_headers, response_body,
                       replay_error, flow_meta
                FROM flows
                WHERE flow_meta IS NOT NULL
                """
            ):
                meta = _parse_flow_meta(item["flow_meta"])
                burp = meta.get("burp") if isinstance(meta.get("burp"), Mapping) else None
                if not isinstance(burp, Mapping):
                    continue
                rid = str(burp.get("record_id") or "").strip()
                if rid not in wanted or rid in by_id:
                    continue
                by_id[rid] = {
                    "status": _as_int(item["status_code"]),
                    "headers": item["response_headers"],
                    "body": item["response_body"],
                    "error": str(item["replay_error"] or "").strip(),
                    "project_name": str(burp.get("project_name") or ""),
                }
    except Exception:
        logger.debug("burp response backfill read failed", exc_info=True)
        return 0
    written = 0
    for rid, payload in by_id.items():
        status = payload["status"]
        body = payload["body"]
        headers = payload["headers"]
        if not status and not body and payload["error"]:
            status = 502
            headers = {"Content-Type": "text/plain"}
            body = payload["error"]
        if not status and not body:
            continue
        path = record_http_response(
            {
                "burp": {
                    "record_id": rid,
                    "project_id": pid,
                    "project_name": payload["project_name"],
                }
            },
            project_id=pid,
            status=status,
            headers=headers,
            body=body,
            reason="Bad Gateway" if status == 502 and payload["error"] else "",
        )
        if path is not None:
            written += 1
    return written


def _parse_flow_meta(raw: Any) -> dict[str, Any]:
    if raw is None:
        return {}
    if isinstance(raw, Mapping):
        return dict(raw)
    if isinstance(raw, (bytes, bytearray)):
        raw = raw.decode("utf-8", errors="replace")
    if isinstance(raw, str):
        text = raw.strip()
        if not text:
            return {}
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


def record_module_hit(
    *,
    project_id: str,
    engine: str,
    extras: Optional[Mapping[str, Any]] = None,
    record_id: str = "",
    status: int = 0,
    db_path: Optional[Path] = None,
    flow_id: str = "",
    url: str = "",
    host: str = "",
    path: str = "",
    endpoint_id: str = "",
    method: str = "",
) -> None:
    """
    Purpose:
        Best-effort snapshot for passive / error-intel (never raises).
    """
    try:
        flow: dict[str, Any] = {}
        if db_path is not None and flow_id:
            flow = _load_flow_lite(db_path, flow_id) or {}
        if url:
            flow.setdefault("url", url)
        if host:
            flow.setdefault("host", normalize_host(host) or host)
        if path:
            flow.setdefault("path", path)
        if endpoint_id:
            flow.setdefault("endpoint_id", endpoint_id)
        if method:
            flow.setdefault("method", method)
        if not flow.get("url") and not flow.get("path"):
            return
        code = status
        if not code:
            try:
                code = int(flow.get("status_code") or 0)
            except (TypeError, ValueError):
                code = 0
        record_from_flow(
            project_id=project_id,
            engine=engine,
            flow=flow,
            extras=extras,
            record_id=record_id,
            status=code,
        )
    except Exception:
        logger.debug("burp module hit record failed", exc_info=True)


FINDING_RECORD_PREFIX = "finding:"
_FLOW_EVIDENCE_TYPES = (
    "replay_flow",
    "original_flow",
    "unauth_result",
    "bac_result",
    "auth_test_result",
    "auth_session_result",
    "cors_result",
)


def finding_record_id(finding_id: str) -> str:
    """Stable snapshot row id for one finding."""
    return f"{FINDING_RECORD_PREFIX}{(finding_id or '').strip()}"


def record_finding(
    *,
    project_id: str,
    finding_id: str,
    db_path: Optional[Path] = None,
    attack_type: str = "",
    title: str = "",
    flow_id: str = "",
    project_name: str = "",
) -> Optional[Path]:
    """
    Purpose:
        Snapshot one finding under Findings → <attack type> so the Burp
        tab can show the attack request like other engines.
    Output:
        Snapshot path when written, else None. Never raises.
    """
    try:
        return _record_finding(
            project_id=project_id,
            finding_id=finding_id,
            db_path=db_path,
            attack_type=attack_type,
            title=title,
            flow_id=flow_id,
            project_name=project_name,
        )
    except Exception:
        logger.debug("burp finding snapshot failed", exc_info=True)
        return None


def _record_finding(
    *,
    project_id: str,
    finding_id: str,
    db_path: Optional[Path],
    attack_type: str,
    title: str,
    flow_id: str,
    project_name: str,
) -> Optional[Path]:
    from talos.burp.trace import ENGINE_FINDINGS
    from talos.findings.model import ATTACK_DISPLAY

    fid = (finding_id or "").strip()
    if not fid:
        return None
    module = (attack_type or "").strip()
    heading = (title or "").strip()
    resolved_flow = (flow_id or "").strip()
    if db_path is not None and (not module or not heading or not resolved_flow):
        try:
            import talos.findings.db as findings_db

            row = findings_db.get_finding(db_path, fid)
            if row:
                module = module or str(row.get("attack_type") or "")
                heading = heading or str(row.get("title") or "")
            if not resolved_flow:
                resolved_flow = _flow_id_for_finding(db_path, fid)
        except Exception:
            logger.debug("burp finding lookup failed", exc_info=True)
    if not resolved_flow or db_path is None:
        return None
    flow = _load_flow_lite(db_path, resolved_flow) or {}
    if not flow.get("url") and not flow.get("path"):
        return None
    group = ATTACK_DISPLAY.get(module, module.replace("_", " ").title() or "Finding")
    extras = {
        "technique": module,
        "detail": heading or group,
    }
    status = _as_int(flow.get("status_code"))
    return record_from_flow(
        project_id=project_id,
        engine=ENGINE_FINDINGS,
        flow=flow,
        extras=extras,
        project_name=project_name,
        record_id=finding_record_id(fid),
        status=status,
        endpoint_id=module or "finding",
        tree_label=group,
    )


def backfill_findings_from_db(project_id: str, db_path: Path) -> int:
    """
    Purpose:
        Write missing Findings tree rows from the findings table so the
        Burp tab shows existing findings after a project open.
    Output:
        Number of finding records appended. Never raises.
    """
    pid = safe_project_id(project_id)
    if not pid or db_path is None:
        return 0
    try:
        import talos.findings.db as findings_db

        findings = findings_db.list_findings(db_path, project_id)
    except Exception:
        logger.debug("burp findings backfill list failed", exc_info=True)
        return 0
    have = {
        (row.get("record_id") or row.get("id") or "").strip()
        for row in load_records(pid)
    }
    have.discard("")
    written = 0
    for finding in findings:
        fid = str(finding.get("id") or "").strip()
        if not fid:
            continue
        rid = finding_record_id(fid)
        if rid in have:
            continue
        path = record_finding(
            project_id=pid,
            finding_id=fid,
            db_path=db_path,
            attack_type=str(finding.get("attack_type") or ""),
            title=str(finding.get("title") or ""),
        )
        if path is not None:
            written += 1
            have.add(rid)
    return written


def _flow_id_for_finding(db_path: Path, finding_id: str) -> str:
    try:
        import talos.findings.db as findings_db

        evidence = findings_db.list_evidence(db_path, finding_id)
    except Exception:
        return ""
    by_type: dict[str, str] = {}
    for item in evidence:
        kind = str(item.get("evidence_type") or "")
        ref = str(item.get("reference_id") or "").strip()
        if kind and ref and kind not in by_type:
            by_type[kind] = ref
    for kind in _FLOW_EVIDENCE_TYPES:
        if by_type.get(kind):
            return by_type[kind]
    return ""


def _load_flow_lite(db_path: Path, flow_id: str) -> Optional[dict[str, Any]]:
    import sqlite3

    try:
        with sqlite3.connect(str(db_path)) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                """
                SELECT method, url, host, path, query, request_headers,
                       request_body, status_code, endpoint_id,
                       response_headers, response_body
                FROM flows WHERE id = ?
                """,
                (flow_id,),
            ).fetchone()
        return dict(row) if row else None
    except sqlite3.Error:
        return None


def snapshot_path(project_id: str) -> Optional[Path]:
    """
    Purpose:
        Resolve the JSONL path for one Talos project.
    Output:
        Path, or None when the id is empty after sanitizing.
    """
    pid = safe_project_id(project_id)
    if not pid:
        return None
    return snapshot_root() / f"{pid}.jsonl"


def resolve_project_identity(
    *,
    project_id: str = "",
    project_name: str = "",
    db_path: Optional[Path] = None,
    project_data_dir: Optional[Path] = None,
) -> tuple[str, str]:
    """
    Purpose:
        Resolve (project_id, project_name) for a snapshot / ingest tag.
    Input:
        project_id       — explicit id when the caller already has it.
        project_name     — explicit display name.
        db_path          — project talos.db (parent is the project dir).
        project_data_dir — project directory (parent of talos.db).
    Output:
        (id, name). Either may be empty when identity cannot be trusted.
    Side effects: May read <projects_root>/registry.json.
    """
    pid = (project_id or "").strip()
    pname = (project_name or "").strip()
    project_dir: Optional[Path] = None
    if db_path is not None:
        project_dir = Path(db_path).parent
    elif project_data_dir is not None:
        project_dir = Path(project_data_dir)
    registry = _load_registry(project_dir)
    if not pid and project_dir is not None and registry is not None:
        candidate = project_dir.name
        if candidate in registry:
            pid = candidate
    if pid and not pname:
        if registry and pid in registry:
            raw_name = registry[pid].get("name") if isinstance(registry[pid], dict) else ""
            pname = str(raw_name or "").strip()
        pname = pname or pid
    return pid, pname


def record_request(
    trace: BurpTrace,
    *,
    method: str = "",
    host: str = "",
    path: str = "",
    url: str = "",
    headers: Any = None,
    body: Any = None,
    status: int = 0,
) -> Optional[Path]:
    """
    Purpose:
        Append one tree row to the project's snapshot.
    Input:
        trace   — grouping + project identity + record_id.
        method / host / path / url / headers / body — enough to rebuild
        a request in Burp. The response is written separately after the
        test completes.
    Output:
        Snapshot path when written, else None.
    Side effects: Creates ~/.talos/burp/ and appends a JSONL line.
    """
    pid = safe_project_id(trace.project_id)
    if not pid:
        return None
    path_out = snapshot_path(pid)
    if path_out is None:
        return None
    parsed = urlparse(url) if url else None
    resolved_host = normalize_host(
        host or trace.host or (parsed.netloc if parsed else "")
    )
    secure = bool(parsed and parsed.scheme == "https")
    port = 0
    if parsed is not None and parsed.port:
        port = int(parsed.port)
    elif resolved_host.count(":") == 1 and not resolved_host.startswith("["):
        maybe_port = resolved_host.rsplit(":", 1)[1]
        if maybe_port.isdigit():
            port = int(maybe_port)
    if not port:
        port = 443 if secure else 80
    request_http = build_request_http(
        method=method or _method_from_label(trace.endpoint_label),
        url=url,
        path=path,
        host=resolved_host,
        headers=headers,
        body=body,
    )
    row = {
        "kind": KIND_RECORD,
        "id": trace.record_id or "",
        "captured_at": "",
        "engine": trace.engine,
        "group": trace.group or "endpoints",
        "endpoint": trace.endpoint_label,
        "endpoint_id": trace.endpoint_id,
        "host": resolved_host,
        "param": trace.extras.get("param", ""),
        "location": trace.extras.get("location", ""),
        "analysis": trace.extras.get("analysis", ""),
        "payload_type": trace.extras.get("payload_type", ""),
        "technique": trace.extras.get("technique", ""),
        "variant": trace.extras.get("variant", ""),
        "detail": trace.extras.get("detail", ""),
        "method": (method or _method_from_label(trace.endpoint_label)).upper(),
        "url": url or _url_from_parts(resolved_host, path or "/", secure),
        "path": (path or (parsed.path if parsed else "") or "/"),
        "secure": "1" if secure else "0",
        "port": str(port),
        "request_http": request_http,
        "status": str(int(status or 0)),
        "project_id": pid,
        "project_name": (trace.project_name or pid).strip(),
        "record_id": trace.record_id or "",
    }
    from time import time

    row["captured_at"] = str(int(time() * 1000))
    _append_row(path_out, pid, row["project_name"], row)
    return path_out


def list_projects() -> list["SnapshotProject"]:
    """
    Purpose:
        Enumerate snapshot files for the Burp project picker.
    Output:
        Projects sorted by name then id. Missing/corrupt files skipped.
    Side effects: Reads ~/.talos/burp/*.jsonl.
    """
    root = snapshot_root()
    if not root.is_dir():
        return []
    found: list[SnapshotProject] = []
    for path in sorted(root.glob("*.jsonl")):
        meta = _read_meta(path)
        if meta is None:
            continue
        found.append(meta)
    found.sort(key=lambda item: (item.name.lower(), item.project_id))
    return found


def _as_int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def build_response_http(
    *,
    status: int,
    headers: Any,
    body: Any,
    reason: str = "",
) -> str:
    """Build a raw HTTP/1.1 response for the extension to rehydrate."""
    phrase = (reason or "").strip() or _reason_for(status)
    lines = [f"HTTP/1.1 {int(status or 0)} {phrase}"]
    for name, value in _iter_headers(headers):
        if name.lower().startswith("x-talos-"):
            continue
        lines.append(f"{name}: {value}")
    raw = "\r\n".join(lines) + "\r\n\r\n"
    blob = _body_text(body)
    if blob:
        raw += blob
    if len(raw) > MAX_RESPONSE_HTTP:
        return raw[:MAX_RESPONSE_HTTP]
    return raw


def _reason_for(status: int) -> str:
    return {
        200: "OK",
        201: "Created",
        204: "No Content",
        301: "Moved Permanently",
        302: "Found",
        304: "Not Modified",
        400: "Bad Request",
        401: "Unauthorized",
        403: "Forbidden",
        404: "Not Found",
        405: "Method Not Allowed",
        500: "Internal Server Error",
        502: "Bad Gateway",
        503: "Service Unavailable",
    }.get(int(status or 0), "")


def load_records(project_id: str) -> list[dict[str, str]]:
    """
    Purpose:
        Load snapshot rows for one project (extension / tests).
    Output:
        Flat string dicts, oldest first. Empty when missing.
    Side effects: Reads the JSONL file.
    """
    path = snapshot_path(project_id)
    if path is None or not path.is_file():
        return []
    records: list[dict[str, str]] = []
    by_id: dict[str, dict[str, str]] = {}
    try:
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                row = _parse_line(line)
                if row is None:
                    continue
                kind = row.get("kind")
                if kind == KIND_RECORD:
                    records.append(row)
                    key = row.get("record_id") or row.get("id") or ""
                    if key:
                        by_id[key] = row
                elif kind == KIND_RESPONSE:
                    key = row.get("record_id") or row.get("id") or ""
                    target = by_id.get(key)
                    if target is None:
                        continue
                    if row.get("response_http"):
                        target["response_http"] = row["response_http"]
                    if row.get("status"):
                        target["status"] = row["status"]
    except OSError as exc:
        logger.debug("burp snapshot read failed: %s", exc)
        return []
    return records


def build_request_http(
    *,
    method: str,
    url: str,
    path: str,
    host: str,
    headers: Any,
    body: Any,
) -> str:
    """
    Purpose:
        Build a raw HTTP/1.1 request the extension can rehydrate.
    Output:
        CRLF request, truncated to MAX_REQUEST_HTTP. No X-Talos-* headers.
    """
    parsed = urlparse(url) if url else None
    target = (path or "").strip() or "/"
    if parsed is not None:
        target = parsed.path or "/"
        if parsed.query:
            target = f"{target}?{parsed.query}"
    if not target.startswith("/"):
        target = "/" + target
    verb = (method or "GET").strip().upper() or "GET"
    resolved_host = (host or (parsed.netloc if parsed else "")).strip()
    hdrs = list(_iter_headers(headers))
    if resolved_host and not any(name.lower() == "host" for name, _ in hdrs):
        hdrs.insert(0, ("Host", resolved_host))
    lines = [f"{verb} {target} HTTP/1.1"]
    for name, value in hdrs:
        if name.lower().startswith("x-talos-"):
            continue
        lines.append(f"{name}: {value}")
    raw = "\r\n".join(lines) + "\r\n\r\n"
    blob = _body_text(body)
    if blob:
        raw += blob
    else:
        # Two blank lines after a bodyless header block. Burp Repeater
        # rejects a missing terminator, especially when the last header
        # is empty (e.g. Authorization: after an unauth strip).
        raw += "\r\n"
    if len(raw) > MAX_REQUEST_HTTP:
        raw = raw[:MAX_REQUEST_HTTP]
        if not blob:
            raw = _ensure_bodyless_terminator(raw)
    return raw


def _ensure_bodyless_terminator(raw: str) -> str:
    """Force two trailing blank lines on a bodyless request."""
    text = raw.rstrip(" \t")
    while text.endswith("\r\n"):
        text = text[: -2]
    while text.endswith("\n"):
        text = text[:-1]
    return text + "\r\n\r\n\r\n"


@dataclass(frozen=True)
class SnapshotProject:
    """One Talos project that has a Burp snapshot on disk."""

    project_id: str
    name: str
    records: int


def _append_row(path: Path, project_id: str, project_name: str, row: Mapping[str, str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_suffix(path.suffix + ".lock")
    try:
        with RuntimeLock(lock_path):
            created = not path.exists() or path.stat().st_size == 0
            with path.open("a", encoding="utf-8") as handle:
                if created:
                    handle.write(_line(_meta_row(project_id, project_name)))
                handle.write(_line(row))
            _maybe_compact(path, project_id, project_name)
    except OSError as exc:
        logger.debug("burp snapshot write failed: %s", exc)


def _maybe_compact(path: Path, project_id: str, project_name: str) -> None:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return
    record_lines = [line for line in lines if _line_is_record(line)]
    if len(record_lines) <= MAX_RECORDS:
        return
    kept = record_lines[-MAX_RECORDS:]
    keep_ids: set[str] = set()
    for line in kept:
        row = _parse_line(line)
        if row:
            key = row.get("record_id") or row.get("id") or ""
            if key:
                keep_ids.add(key)
    extras = [
        line
        for line in lines
        if _line_is_response(line) and _line_record_id(line) in keep_ids
    ]
    payload = _line(_meta_row(project_id, project_name)) + "".join(
        (line if line.endswith("\n") else line + "\n") for line in kept + extras
    )
    try:
        atomic_write_text(path, payload, prefix=f".{path.name}.", suffix=".tmp")
    except OSError as exc:
        logger.debug("burp snapshot compact failed: %s", exc)


def _meta_row(project_id: str, project_name: str) -> dict[str, str]:
    return {
        "kind": KIND_META,
        "project_id": project_id,
        "project_name": project_name or project_id,
    }


def _line(row: Mapping[str, str]) -> str:
    flat = {str(key): "" if value is None else str(value) for key, value in row.items()}
    return json.dumps(flat, ensure_ascii=False, separators=(",", ":")) + "\n"


def _parse_line(line: str) -> Optional[dict[str, str]]:
    text = line.strip()
    if not text:
        return None
    try:
        raw = json.loads(text)
    except json.JSONDecodeError:
        return None
    if not isinstance(raw, dict):
        return None
    return {str(key): "" if value is None else str(value) for key, value in raw.items()}


def _line_is_record(line: str) -> bool:
    row = _parse_line(line)
    return bool(row and row.get("kind") == KIND_RECORD)


def _line_is_response(line: str) -> bool:
    row = _parse_line(line)
    return bool(row and row.get("kind") == KIND_RESPONSE)


def _line_record_id(line: str) -> str:
    row = _parse_line(line)
    if not row:
        return ""
    return row.get("record_id") or row.get("id") or ""


def _read_meta(path: Path) -> Optional[SnapshotProject]:
    pid = path.stem
    name = pid
    count = 0
    try:
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                row = _parse_line(line)
                if row is None:
                    continue
                if row.get("kind") == KIND_META:
                    pid = row.get("project_id") or pid
                    name = row.get("project_name") or name
                elif row.get("kind") == KIND_RECORD:
                    count += 1
    except OSError:
        return None
    pid = safe_project_id(pid)
    if not pid:
        return None
    return SnapshotProject(project_id=pid, name=name or pid, records=count)


def _load_registry(project_dir: Optional[Path]) -> Optional[dict[str, Any]]:
    if project_dir is None:
        return None
    registry_path = Path(project_dir).parent / "registry.json"
    if not registry_path.is_file():
        return None
    try:
        raw = json.loads(registry_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return raw if isinstance(raw, dict) else None


def _iter_headers(headers: Any) -> Iterable[tuple[str, str]]:
    if headers is None:
        return []
    raw = headers
    if isinstance(headers, str):
        try:
            parsed = json.loads(headers)
        except json.JSONDecodeError:
            return []
        raw = parsed
    if isinstance(raw, Mapping):
        out: list[tuple[str, str]] = []
        for name, value in raw.items():
            if isinstance(value, list):
                out.extend((str(name), str(item)) for item in value)
            else:
                out.append((str(name), str(value)))
        return out
    if isinstance(raw, (list, tuple)):
        pairs: list[tuple[str, str]] = []
        for item in raw:
            if isinstance(item, (list, tuple)) and len(item) == 2:
                pairs.append((str(item[0]), str(item[1])))
        return pairs
    return []


def _body_text(body: Any) -> str:
    if body is None:
        return ""
    if isinstance(body, bytes):
        return body.decode("utf-8", errors="replace")
    return str(body)


def _method_from_label(label: str) -> str:
    token = (label or "").strip().split(" ", 1)[0]
    return token or "GET"


def _url_from_parts(host: str, path: str, secure: bool) -> str:
    if not host:
        return path or "/"
    scheme = "https" if secure else "http"
    route = path if path.startswith("/") else f"/{path}"
    return f"{scheme}://{host}{route}"
