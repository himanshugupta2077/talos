"""
Talos layered configuration API (Control Panel surface for EffectiveConfig).

Ownership:
    Talos core owns merge, sources, validation, and dual-write. This router only
    invokes `talos config …` and shapes JSON for the UI. It never reads
    scheduler_config / proxy_config / attack_config SQLite tables and never
    writes project.yaml or ~/.talos/config.yaml directly.

Reads:
    talos [--project ID] config show|effective|get|schema --format json
Writes:
    project scope → run_scoped(project_id, ["config", "set|unset", …])
    global scope  → cli.run(["config", "set|unset", …, "--global"])
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Literal, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from .. import cli, config
from ..platform_open import OpenDirectoryError, open_directory

router = APIRouter(prefix="/api/configuration", tags=["configuration"])

ConfigScope = Literal["project", "global"]

# Presentation-only section order (mirrors core CONFIG_SECTIONS).
_SECTIONS = (
    "proxy",
    "capture",
    "scheduler",
    "attack",
    "http",
    "parameter_intel",
    "url_sink",
    "burp",
)


def _parse_json_stdout(stdout: str) -> Any:
    text = (stdout or "").strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def _cli_fail(result: cli.CommandResult, *, what: str) -> HTTPException:
    detail = (result.stderr or result.stdout or f"{what} failed").strip()
    return HTTPException(status_code=400, detail=detail or f"{what} failed")


def _run_config_read(
    args: list[str],
    *,
    project_id: Optional[str] = None,
) -> cli.CommandResult:
    """
    Read config without permanently rewriting the active project when possible.
    Uses `talos --project <id> config …` so registry ACTIVE is unchanged.
    """
    argv = list(args)
    if project_id:
        argv = ["--project", project_id, *argv]
    return cli.run(argv, timeout=30)


def _format_cli_value(value: Any) -> str:
    """
    Serialize a JSON body value into a token accepted by `talos config set`.
    parse_cli_value understands bools, null, numbers, and JSON arrays/objects.
    """
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(value)
    if isinstance(value, str):
        return value
    return json.dumps(value, separators=(",", ":"))


def _dominant_source(sources: dict[str, str], section: str) -> str:
    order = ("cli", "project", "legacy", "global", "default")
    found = {
        src
        for path, src in sources.items()
        if path == section or path.startswith(section + ".")
    }
    for candidate in order:
        if candidate in found:
            return candidate
    return "default"


def _source_counts(sources: dict[str, str]) -> dict[str, int]:
    counts = {k: 0 for k in ("default", "global", "legacy", "project", "cli")}
    for src in sources.values():
        key = str(src or "default").lower()
        if key in counts:
            counts[key] += 1
        else:
            counts[key] = counts.get(key, 0) + 1
    return counts


def _proxy_summary(values: dict[str, Any]) -> str:
    """Compact Overview card for proxy transport."""
    up_enabled = values.get("proxy.upstream.enabled", False)
    up_url = values.get("proxy.upstream.url")
    mode = f"Upstream · {up_url}" if up_enabled and up_url else "Direct"
    http2 = values.get("proxy.http2", True)
    proto = "HTTP/2" if http2 else "HTTP/1.1"
    auth_on = bool(values.get("proxy.platform_auth.enabled", False))
    entries = values.get("proxy.platform_auth.entries") or []
    auth_n = len(entries) if isinstance(entries, list) else 0
    auth = f"NTLM ×{auth_n}" if auth_on and auth_n else "no platform auth"
    return f"{mode} · {proto} · {auth}"


def _section_summaries(values: dict[str, Any], sources: dict[str, str]) -> list[dict]:
    """Human-readable cards for Overview tab."""
    cards: list[dict] = []

    # Proxy
    cards.append(
        {
            "section": "proxy",
            "label": "Proxy",
            "summary": _proxy_summary(values),
            "source": _dominant_source(sources, "proxy"),
        }
    )

    # Capture
    store = values.get("capture.store_bodies", True)
    max_body = values.get("capture.max_body_size", 1048576)
    try:
        mi_b = int(max_body)
        size_label = (
            f"{mi_b // (1024 * 1024)} MiB"
            if mi_b >= 1024 * 1024 and mi_b % (1024 * 1024) == 0
            else f"{mi_b} B"
        )
    except (TypeError, ValueError):
        size_label = str(max_body)
    cards.append(
        {
            "section": "capture",
            "label": "Capture",
            "summary": (
                f"Bodies {'on' if store else 'off'} · {size_label}"
            ),
            "source": _dominant_source(sources, "capture"),
        }
    )

    # Scheduler
    min_d = values.get("scheduler.min_delay", 2)
    max_d = values.get("scheduler.max_delay", 6)
    queue = values.get("scheduler.max_queue_size", 200)
    cards.append(
        {
            "section": "scheduler",
            "label": "Scheduler",
            "summary": f"{min_d}–{max_d} s · queue {queue}",
            "source": _dominant_source(sources, "scheduler"),
        }
    )

    # Attack
    auto = values.get("attack.unauth_auto_run", False)
    cards.append(
        {
            "section": "attack",
            "label": "Attack",
            "summary": f"Unauth auto-run {'on' if auto else 'off'}",
            "source": _dominant_source(sources, "attack"),
        }
    )

    # HTTP Manipulation Engine
    http_on = values.get("http.enabled", True)
    rules = values.get("http.rules") or []
    n_rules = len(rules) if isinstance(rules, list) else 0
    cards.append(
        {
            "section": "http",
            "label": "HTTP",
            "summary": (
                f"{'On' if http_on else 'Off'} · {n_rules} rule"
                f"{'' if n_rules == 1 else 's'}"
            ),
            "source": _dominant_source(sources, "http"),
        }
    )

    # Parameter intelligence (cross-flow value index)
    cf_on = values.get("parameter_intel.cross_flow.enabled", True)
    cards.append(
        {
            "section": "parameter_intel",
            "label": "Parameter intel",
            "summary": f"Cross-flow {'on' if cf_on else 'off'}",
            "source": _dominant_source(sources, "parameter_intel"),
        }
    )

    # URL Sink Discovery
    us_passive = values.get("url_sink.passive.enabled", True)
    us_thr = values.get("url_sink.score_threshold", 45)
    us_iv = values.get("url_sink.iv_probes.enabled", True)
    cards.append(
        {
            "section": "url_sink",
            "label": "URL Sink",
            "summary": (
                f"Passive {'on' if us_passive else 'off'} · thr {us_thr}"
                f" · IV probes {'on' if us_iv else 'off'}"
            ),
            "source": _dominant_source(sources, "url_sink"),
        }
    )

    burp_on = values.get("burp.enabled", True)
    burp_prefix = values.get("burp.header_prefix") or "X-Talos"
    cards.append(
        {
            "section": "burp",
            "label": "Burp Suite",
            "summary": (
                f"Headers {'on' if burp_on else 'off'} · {burp_prefix}"
            ),
            "source": _dominant_source(sources, "burp"),
        }
    )

    return cards


# --------------------------------------------------------------------------- #
# Read APIs                                                                     #
# --------------------------------------------------------------------------- #


@router.get("/context")
def configuration_context(project_id: str | None = None):
    """
    Paths and binding for the configuration workspace (config show + TALOS_HOME).
    """
    result = _run_config_read(
        ["config", "show", "--format", "json"],
        project_id=project_id,
    )
    if not result.ok:
        raise _cli_fail(result, what="config show")

    payload = _parse_json_stdout(result.stdout)
    if not isinstance(payload, dict):
        raise HTTPException(status_code=502, detail="config show returned non-JSON")

    global_info = payload.get("global") or {}
    project_info = payload.get("project") or {}

    return {
        "talos_home": str(config.TALOS_HOME),
        "global_config_path": global_info.get("path"),
        "global_exists": bool(global_info.get("exists")),
        "project_id": project_info.get("project_id") or project_id,
        "project_config_path": project_info.get("path"),
        "project_exists": bool(project_info.get("exists")),
        "project_bound": bool(project_info.get("bound")),
        "precedence": payload.get("precedence")
        or [
            "defaults",
            "global",
            "legacy (SQLite / headers_drop.txt / constraints)",
            "project.yaml",
            "CLI overrides",
        ],
        "sections": payload.get("sections") or list(_SECTIONS),
    }


@router.get("/schema")
def configuration_schema():
    """Machine-readable setting schema from Talos core (`config schema`)."""
    result = cli.run(["config", "schema", "--format", "json"], timeout=30)
    if not result.ok:
        raise _cli_fail(result, what="config schema")
    payload = _parse_json_stdout(result.stdout)
    if not isinstance(payload, dict):
        raise HTTPException(status_code=502, detail="config schema returned non-JSON")
    return payload


@router.get("/effective")
def configuration_effective(
    project_id: str | None = None,
    section: str | None = None,
):
    """
    Fully merged EffectiveConfig leaves + sources from Talos core.
    """
    args = ["config", "effective", "--format", "json"]
    if section:
        if section not in _SECTIONS:
            raise HTTPException(
                status_code=400,
                detail=f"Unknown section '{section}'. Expected one of: {', '.join(_SECTIONS)}",
            )
        args.extend(["--section", section])

    result = _run_config_read(args, project_id=project_id)
    if not result.ok:
        raise _cli_fail(result, what="config effective")

    payload = _parse_json_stdout(result.stdout)
    if not isinstance(payload, dict):
        raise HTTPException(
            status_code=502, detail="config effective returned non-JSON"
        )

    values = payload.get("values") or {}
    sources = payload.get("sources") or {}
    # Normalize source values to lowercase strings.
    sources = {str(k): str(v).lower() for k, v in sources.items()}

    return {
        "values": values,
        "sources": sources,
        "global_path": payload.get("global_path"),
        "project_path": payload.get("project_path"),
        "source_counts": _source_counts(sources),
        "section_cards": _section_summaries(values, sources),
    }


@router.get("/settings")
def configuration_settings(
    project_id: str | None = None,
    section: str | None = None,
):
    """
    Normalized setting rows: key, section, effective value, source, schema type.
    Built from `config effective` + `config schema` (no parallel merge).
    """
    effective = configuration_effective(project_id=project_id, section=None)
    schema = configuration_schema()

    type_by_key: dict[str, dict] = {}
    for sec in schema.get("sections") or []:
        for setting in sec.get("settings") or []:
            key = setting.get("key")
            if key:
                type_by_key[key] = setting

    values = effective.get("values") or {}
    sources = effective.get("sources") or {}

    rows: list[dict] = []
    # Prefer known schema order; append any unexpected leaves after.
    seen: set[str] = set()
    ordered_keys = list(type_by_key.keys()) + [
        k for k in values.keys() if k not in type_by_key
    ]
    for key in ordered_keys:
        if key in seen:
            continue
        seen.add(key)
        sec_id = key.split(".", 1)[0] if "." in key else key
        if section and sec_id != section:
            continue
        meta = type_by_key.get(key) or {}
        # http.rules is edited on the HTTP Rules workspace; still listed in schema.
        rows.append(
            {
                "key": key,
                "section": sec_id,
                "label": meta.get("label") or key,
                "type": meta.get("type") or "string",
                "description": meta.get("description") or "",
                "unit": meta.get("unit"),
                "minimum": meta.get("minimum"),
                "default": meta.get("default"),
                "effective_value": values.get(key),
                "source": sources.get(key, "default"),
            }
        )

    return {
        "settings": rows,
        "source_counts": effective.get("source_counts"),
        "global_path": effective.get("global_path"),
        "project_path": effective.get("project_path"),
    }


@router.get("/get")
def configuration_get(key: str, project_id: str | None = None):
    """Single key via `talos config get`."""
    if not key or not key.strip():
        raise HTTPException(status_code=400, detail="key is required")
    result = _run_config_read(
        ["config", "get", key.strip(), "--format", "json"],
        project_id=project_id,
    )
    if not result.ok:
        raise _cli_fail(result, what="config get")
    payload = _parse_json_stdout(result.stdout)
    if not isinstance(payload, dict):
        raise HTTPException(status_code=502, detail="config get returned non-JSON")
    return payload


# --------------------------------------------------------------------------- #
# Mutations                                                                     #
# --------------------------------------------------------------------------- #


class SetValueBody(BaseModel):
    key: str = Field(..., min_length=1)
    value: Any = None
    scope: ConfigScope = "project"


class UnsetValueBody(BaseModel):
    key: str = Field(..., min_length=1)
    scope: ConfigScope = "project"


@router.post("/value")
def set_configuration_value(body: SetValueBody, project_id: str | None = None):
    """
    Set a config key at project or global scope via Talos CLI.
    Project: talos config set <key> <value>
    Global:  talos config set <key> <value> --global
    """
    key = body.key.strip()
    if not key:
        raise HTTPException(status_code=400, detail="key is required")

    value_token = _format_cli_value(body.value)
    args = ["config", "set", key, value_token]

    if body.scope == "global":
        args.append("--global")
        result = cli.run(args, timeout=30)
        return {"steps": [result.to_dict()]}

    if not project_id:
        raise HTTPException(
            status_code=400,
            detail="project_id is required for project-scoped configuration writes",
        )
    results = cli.run_scoped(project_id, args, timeout=30)
    return {"steps": [r.to_dict() for r in results]}


def _unset_value(body: UnsetValueBody, project_id: str | None) -> dict:
    """Shared unset implementation for POST /unset and DELETE /value."""
    key = body.key.strip()
    if not key:
        raise HTTPException(status_code=400, detail="key is required")

    args = ["config", "unset", key]
    if body.scope == "global":
        args.append("--global")
        result = cli.run(args, timeout=30)
        return {"steps": [result.to_dict()]}

    if not project_id:
        raise HTTPException(
            status_code=400,
            detail="project_id is required for project-scoped configuration writes",
        )
    results = cli.run_scoped(project_id, args, timeout=30)
    return {"steps": [r.to_dict() for r in results]}


@router.post("/unset")
def unset_configuration_value_post(
    body: UnsetValueBody, project_id: str | None = None
):
    """
    Remove a project or global override (inherit lower layer).
    Preferred mutation surface for the SPA (POST body is reliable).
    Project: talos config unset <key>
    Global:  talos config unset <key> --global
    """
    return _unset_value(body, project_id)


@router.delete("/value")
def unset_configuration_value_delete(
    key: str,
    scope: ConfigScope = "project",
    project_id: str | None = None,
):
    """
    Same as POST /unset; accepts key/scope as query params (no DELETE body).
    """
    return _unset_value(UnsetValueBody(key=key, scope=scope), project_id)


# --------------------------------------------------------------------------- #
# Files / open directory                                                        #
# --------------------------------------------------------------------------- #


class OpenConfigDirBody(BaseModel):
    """
    Open the parent directory of a config file path resolved by the backend.
    target: global_config | project_config
    """

    target: Literal["global_config", "project_config"]


@router.post("/open-directory")
def open_config_directory(body: OpenConfigDirBody, project_id: str | None = None):
    """
    OS file-explorer helper for config file parent dirs (not a Talos mutation).
    Paths are resolved via `config show`, never from client-supplied path strings.
    """
    ctx = configuration_context(project_id=project_id)

    if body.target == "global_config":
        path_str = ctx.get("global_config_path")
    else:
        if not project_id and not ctx.get("project_bound"):
            raise HTTPException(
                status_code=400,
                detail="Select a project to open the project configuration directory",
            )
        path_str = ctx.get("project_config_path")

    if not path_str:
        raise HTTPException(status_code=404, detail="Configuration path not available")

    file_path = Path(path_str)
    directory = file_path if file_path.is_dir() else file_path.parent
    try:
        open_directory(directory)
    except OpenDirectoryError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return {
        "ok": True,
        "target": body.target,
        "path": str(directory),
        "message": f"Opened {directory}",
    }
