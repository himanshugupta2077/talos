"""
Module: talos.ai.tools.scope_policy

Purpose:
    Live Basic Scope + outscope checks and annotation matrix helpers for
    Phase D HTTP / enqueue tools. Used by PolicyValidator (pre-seal) and
    optionally re-checked by handlers (defense in depth).

Dependencies:
    talos.proxy.scope, talos.projects.outscope, talos.projects.annotations,
    talos.projects.manager (live scope list), send draft helpers.
Data flow:
    PolicyValidator / handlers → check_url_in_scope / resolve_flow_target
Side effects: read-only (DB/registry reads).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from talos.projects.annotations import get_annotations
from talos.projects.outscope import load_prefix_set
from talos.proxy.scope import is_url_in_scope
from talos.replay import db as replay_db
from talos.send import db as send_db


# Tools that produce HTTP right-now or resolve a URL that will be sent.
HTTP_SCOPE_TOOLS: frozenset[str] = frozenset(
    {
        "send.once",
        "replay.flow",
    }
)

# Tools that must honor the annotation matrix (logout / dangerous).
ANNOTATION_TOOLS: frozenset[str] = frozenset(
    {
        "send.once",
        "replay.flow",
        "iv.run",
        "attack.unauth.run",
        "attack.bac.run",
        "intruder.session.run",
        "passive.rescan",
    }
)


def load_live_scope(
    manager: Any,
    project_id: str,
    db_path: Path,
) -> tuple[list[str], list[str]]:
    """
    Purpose:
        Load current Basic Scope prefixes + outscope prefixes for a project.
    Output:
        (in_scope_prefixes, outscope_prefixes). Empty in-scope ⇒ deny-all.
    """
    project = manager.get(project_id)
    in_scope = list(project.scope or []) if project is not None else []
    outscope = list(load_prefix_set(db_path))
    return in_scope, outscope


def parse_scope_snapshot(
    scope_snapshot_json: Optional[str],
) -> Optional[dict[str, Any]]:
    if not scope_snapshot_json:
        return None
    try:
        data = json.loads(scope_snapshot_json)
    except (TypeError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def check_url_allowed(
    effective_url: str,
    *,
    live_in_scope: list[str] | tuple[str, ...] | frozenset[str],
    live_outscope: list[str] | tuple[str, ...] | frozenset[str] | None,
    scope_snapshot: Optional[dict[str, Any]] = None,
) -> tuple[bool, str, dict[str, Any]]:
    """
    Purpose:
        Dual scope check: live Basic Scope+outscope, plus fail-closed
        intersection with session snapshot when present.
    Output:
        (allowed, reject_code_or_empty, meta).
    """
    meta: dict[str, Any] = {
        "effective_url": effective_url,
        "live_in_scope": list(live_in_scope),
        "live_outscope": list(live_outscope or []),
    }

    if not live_in_scope:
        meta["decision"] = "empty_in_scope"
        return False, "scope_denied", meta

    live_ok = is_url_in_scope(effective_url, live_in_scope, live_outscope)
    meta["live_allowed"] = live_ok
    if not live_ok:
        meta["decision"] = "live_out_of_scope"
        return False, "scope_denied", meta

    if scope_snapshot is not None:
        snap_scope = list(scope_snapshot.get("scope") or [])
        snap_out = list(scope_snapshot.get("outscope") or [])
        meta["snapshot_scope"] = snap_scope
        meta["snapshot_outscope"] = snap_out
        # Snapshot is an additional constraint only when it has rules.
        # Live remains authoritative for allow; both must allow when snap present.
        if snap_scope:
            snap_ok = is_url_in_scope(effective_url, snap_scope, snap_out or None)
            meta["snapshot_allowed"] = snap_ok
            if not snap_ok:
                meta["decision"] = "snapshot_out_of_scope"
                return False, "scope_denied", meta
        else:
            # Empty snapshot scope would deny-all if applied — treat as missing.
            meta["snapshot_allowed"] = True

    meta["decision"] = "allowed"
    return True, "", meta


def resolve_flow_target(
    db_path: Path,
    *,
    flow_id: Optional[str] = None,
    parent_flow_id: Optional[str] = None,
) -> Optional[dict[str, Any]]:
    """
    Purpose:
        Load a flow for scope/annotation checks (send or replay path).
    Output:
        Flow dict with at least url/endpoint_id, or None if missing.
    """
    fid = (flow_id or parent_flow_id or "").strip()
    if not fid:
        return None
    flow = send_db.get_flow_for_send(db_path, fid)
    if flow is None:
        flow = replay_db.get_flow_for_replay(db_path, fid)
    return flow


def annotations_for_endpoint(
    db_path: Path, endpoint_id: Optional[str]
) -> frozenset[str]:
    if not endpoint_id:
        return frozenset()
    return get_annotations(db_path, endpoint_id)


def apply_send_edits_to_url(base_url: str, edits: list[dict[str, Any]] | None) -> str:
    """
    Purpose:
        Compute effective_url after send.once edit ops (query/path/host only).
        Header/cookie/body edits do not change the request URL.
    """
    if not edits:
        return base_url

    parsed = urlparse(base_url or "")
    scheme, netloc, path, params, query, fragment = (
        parsed.scheme,
        parsed.netloc,
        parsed.path,
        parsed.params,
        parsed.query,
        parsed.fragment,
    )
    q = list(parse_qsl(query, keep_blank_values=True))

    for edit in edits:
        if not isinstance(edit, dict):
            continue
        op = str(edit.get("op") or "").strip()
        target = str(edit.get("target") or "").strip()
        key = edit.get("key")
        value = edit.get("value")

        if target == "query":
            k = str(key or "")
            if op == "set" and k:
                # Replace first occurrence of key; append if missing.
                found = False
                for i, (qk, qv) in enumerate(q):
                    if qk == k:
                        q[i] = (k, str(value if value is not None else ""))
                        found = True
                        break
                if not found:
                    q.append((k, str(value if value is not None else "")))
            elif op == "remove" and k:
                q = [(qk, qv) for qk, qv in q if qk != k]
        elif target == "path" and op == "set" and value is not None:
            path = str(value)
        elif target == "host" and op == "set" and value is not None:
            # value may be host or host:port
            netloc = str(value)

    new_query = urlencode(q, doseq=True)
    return urlunparse((scheme, netloc, path, params, new_query, fragment))


def edits_to_send_kwargs(edits: list[dict[str, Any]] | None) -> dict[str, Any]:
    """
    Purpose:
        Map send.once TTP edit ops to send_once structured kwargs.
    """
    if not edits:
        return {}

    headers: list[tuple[str, str]] = []
    remove_headers: list[str] = []
    query_params: list[tuple[str, str]] = []
    remove_query: list[str] = []
    cookies: list[tuple[str, str]] = []
    remove_cookies: list[str] = []
    json_sets: list[tuple[str, str]] = []
    path: Optional[str] = None
    host: Optional[str] = None
    url: Optional[str] = None

    for edit in edits:
        if not isinstance(edit, dict):
            continue
        op = str(edit.get("op") or "").strip()
        target = str(edit.get("target") or "").strip()
        key = edit.get("key")
        value = edit.get("value")

        if target == "query":
            k = str(key or "")
            if op == "set" and k:
                query_params.append((k, str(value if value is not None else "")))
            elif op == "remove" and k:
                remove_query.append(k)
        elif target == "header":
            k = str(key or "")
            if op == "set" and k:
                headers.append((k, str(value if value is not None else "")))
            elif op == "remove" and k:
                remove_headers.append(k)
        elif target == "cookie":
            k = str(key or "")
            if op == "set" and k:
                cookies.append((k, str(value if value is not None else "")))
            elif op == "remove" and k:
                remove_cookies.append(k)
        elif target == "body_json_path":
            k = str(key or "")
            if op == "set" and k:
                json_sets.append((k, str(value if value is not None else "")))
            # remove body_json_path not supported by send draft; ignore at map
        elif target == "path" and op == "set" and value is not None:
            path = str(value)
        elif target == "host" and op == "set" and value is not None:
            host = str(value)
        elif target == "url" and op == "set" and value is not None:
            url = str(value)

    kwargs: dict[str, Any] = {}
    if headers:
        kwargs["headers"] = headers
    if remove_headers:
        kwargs["remove_headers"] = remove_headers
    if query_params:
        kwargs["query_params"] = query_params
    if remove_query:
        kwargs["remove_query"] = remove_query
    if cookies:
        kwargs["cookies"] = cookies
    if remove_cookies:
        kwargs["remove_cookies"] = remove_cookies
    if json_sets:
        kwargs["json_sets"] = json_sets
    if path is not None:
        kwargs["path"] = path
    if host is not None:
        kwargs["host"] = host
    if url is not None:
        kwargs["url"] = url
    return kwargs


def ai_job_meta(
    *,
    session_id: str,
    suggestion_id: str,
    force_dangerous: bool = False,
    extra: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Standard meta dict for AI-enqueued scheduler jobs."""
    meta: dict[str, Any] = {
        "source": "ai",
        "ai_session_id": session_id,
        "ai_suggestion_id": suggestion_id,
        "ai_force_dangerous": bool(force_dangerous),
    }
    if extra:
        meta.update(extra)
    return meta


def ai_job_priority(*, force_dangerous: bool) -> int:
    from talos.scheduler.job import PRIORITY_AI_AUTO, PRIORITY_AI_MANUAL

    return PRIORITY_AI_MANUAL if force_dangerous else PRIORITY_AI_AUTO
