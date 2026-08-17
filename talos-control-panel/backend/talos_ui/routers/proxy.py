"""
Proxy control and observability API.

Ownership boundary:
    Talos core (ProxyRuntimeManager + CLI) owns proxy lifecycle, restart rules,
    configuration semantics, and runtime state. This router is a thin control
    surface: it invokes `talos proxy …` and exposes runtime snapshots / logs.
    It never decides that a configuration mutation requires a restart.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from .. import cli, config

router = APIRouter(prefix="/api/proxy", tags=["proxy"])

# Proxy start/stop/restart may drain for up to ~30s plus spawn settle.
_PROXY_LIFECYCLE_TIMEOUT_S = 90


def _proxy_log_path() -> Path:
    return Path(config.TALOS_HOME) / "runtime" / "proxy.log"


def _parse_status_stdout(stdout: str) -> dict[str, Any]:
    """
    Purpose:
        Parse `talos proxy status --format json` into a dict.
    Output:
        Status payload or empty dict when stdout is not JSON.
    """
    text = (stdout or "").strip()
    if not text:
        return {}
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def _enrich_status(payload: dict[str, Any]) -> dict[str, Any]:
    """
    Purpose:
        Normalize Talos runtime status for the Control Panel UI.
    Side effects: None. Does not invent lifecycle decisions.
    """
    state = str(payload.get("state") or "stopped").lower()
    running = state == "running"
    transitional = bool(
        payload.get("transitional")
        or state in ("starting", "draining", "stopping")
    )
    out = dict(payload)
    out["state"] = state
    out["running"] = running
    out["transitional"] = transitional
    if not out.get("log_path"):
        out["log_path"] = str(_proxy_log_path())
    return out


def _stopped_status(*, error: Optional[str] = None) -> dict[str, Any]:
    body: dict[str, Any] = {
        "state": "stopped",
        "running": False,
        "transitional": False,
        "pid": None,
        "project_id": None,
        "role_id": None,
        "module_id": None,
        "listen_host": None,
        "listen_port": None,
        "upstream_url": None,
        "startup_time": None,
        "applied_project_id": None,
        "applied_generation": None,
        "restart_pending": False,
        "last_error": error,
        "validation_deferred": False,
        "log_path": str(_proxy_log_path()),
    }
    return body


def _steps_response(result: cli.CommandResult) -> dict[str, Any]:
    return {"steps": [result.to_dict()]}


class ProxyStartBody(BaseModel):
    listen_host: str | None = None
    port: int | None = None


class ProxyKillBody(BaseModel):
    """
    Hard recovery: stop managed proxy and free the listen port
    (`talos proxy kill [--port N] [--force]`).
    """

    listen_host: str | None = None
    port: int | None = None
    force: bool = False


class ProxyConfigBody(BaseModel):
    """
    Persist proxy transport via Talos CLI.
    Upstream: provide upstream_url, or direct=True for Direct mode.
    Origin: http2=false forces HTTP/1.1; keep_alive controls connection reuse.
    """

    upstream_url: str | None = None
    direct: bool = False
    http2: bool | None = None
    keep_alive: bool | None = None


class PlatformAuthBody(BaseModel):
    """
    Add one named platform-auth profile.
    """

    id: str | None = None
    name: str = ""
    host: str
    auth_type: str = "ntlmv2"
    username: str = ""
    password: str = ""
    domain: str = ""
    domain_hostname: str = ""
    spnego: bool = False
    negotiate: bool = False
    enabled: bool = True


class PlatformAuthEditBody(BaseModel):
    """
    Patch an existing profile. Omitted password keeps the stored secret.
    """

    id: str | None = None
    name: str | None = None
    host: str | None = None
    auth_type: str | None = None
    username: str | None = None
    password: str | None = None
    domain: str | None = None
    domain_hostname: str | None = None
    spnego: bool | None = None
    negotiate: bool | None = None
    enabled: bool | None = None


class PlatformAuthIdBody(BaseModel):
    """Enable, disable, or use a profile. Empty id toggles the master switch."""

    id: str | None = None
    host: str | None = None


@router.get("/status")
def proxy_status():
    """
    Purpose:
        Observational snapshot from Talos core (`talos proxy status --format json`).
    """
    result = cli.run(["proxy", "status", "--format", "json"], timeout=15)
    if not result.ok:
        # CLI precondition / failure: still return a stable stopped-shaped body.
        err = (result.stderr or result.stdout or "proxy status failed").strip()
        body = _stopped_status(error=err or None)
        body["cli_ok"] = False
        return body

    parsed = _parse_status_stdout(result.stdout)
    if not parsed:
        return _stopped_status(error="proxy status returned non-JSON output")
    out = _enrich_status(parsed)
    out["cli_ok"] = True
    return out


@router.get("/logs")
def proxy_logs(tail: int = 300):
    """
    Purpose:
        Tail the Talos-managed proxy log file (not a Control Panel process buffer).
    """
    tail = max(1, min(int(tail), 5000))
    path = _proxy_log_path()
    if not path.exists():
        return {"lines": [], "path": str(path)}
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return {"lines": [f"[control panel] failed to read log: {exc}"], "path": str(path)}
    lines = text.splitlines()
    return {"lines": lines[-tail:], "path": str(path)}


@router.post("/start")
def proxy_start(body: ProxyStartBody):
    """
    Purpose:
        Request Talos core to start the managed proxy. Lifecycle is owned by core.
    """
    args = ["proxy", "start"]
    if body.listen_host:
        args.extend(["--listen-host", body.listen_host])
    if body.port is not None:
        args.extend(["--port", str(body.port)])
    result = cli.run(args, timeout=_PROXY_LIFECYCLE_TIMEOUT_S)
    return _steps_response(result)


@router.post("/stop")
def proxy_stop():
    """
    Purpose:
        Request Talos core to stop the managed proxy.
    """
    result = cli.run(["proxy", "stop"], timeout=_PROXY_LIFECYCLE_TIMEOUT_S)
    return _steps_response(result)


@router.post("/restart")
def proxy_restart(body: ProxyStartBody):
    """
    Purpose:
        Operator-initiated restart via Talos core. Not used after config mutations.
    """
    args = ["proxy", "restart"]
    if body.listen_host:
        args.extend(["--listen-host", body.listen_host])
    if body.port is not None:
        args.extend(["--port", str(body.port)])
    result = cli.run(args, timeout=_PROXY_LIFECYCLE_TIMEOUT_S)
    return _steps_response(result)


@router.post("/kill")
def proxy_kill(body: ProxyKillBody):
    """
    Purpose:
        Hard recovery via Talos core (`talos proxy kill`).
        Stops the managed process and reclaims the listen port (orphan mitmdump).
        With force=True, kills any process holding the port (not only mitmdump).
    """
    args = ["proxy", "kill"]
    if body.listen_host:
        args.extend(["--listen-host", body.listen_host])
    if body.port is not None:
        args.extend(["--port", str(body.port)])
    if body.force:
        args.append("--force")
    result = cli.run(args, timeout=_PROXY_LIFECYCLE_TIMEOUT_S)
    return _steps_response(result)


@router.get("/config")
def proxy_config_get():
    """
    Purpose:
        Read effective proxy configuration from Talos (`talos proxy config --format json`).
    """
    result = cli.run(["proxy", "config", "--format", "json"], timeout=15)
    if not result.ok:
        raise HTTPException(
            status_code=400,
            detail=(result.stderr or result.stdout or "proxy config failed").strip(),
        )
    parsed = _parse_status_stdout(result.stdout)
    if not parsed:
        raise HTTPException(status_code=500, detail="proxy config returned non-JSON output")
    return parsed


@router.post("/config")
def proxy_config_set(body: ProxyConfigBody):
    """
    Purpose:
        Persist Direct vs Upstream mode and origin HTTP settings through
        Talos CLI. Core may auto-restart.
    """
    if body.direct and body.upstream_url:
        raise HTTPException(
            status_code=400,
            detail="Provide either direct=true or upstream_url, not both.",
        )
    args = ["proxy", "config"]
    touched = False
    if body.direct:
        args.append("--no-upstream")
        touched = True
    elif body.upstream_url:
        args.extend(["--upstream", body.upstream_url])
        touched = True
    if body.http2 is False:
        args.append("--http1")
        touched = True
    elif body.http2 is True:
        args.append("--http2")
        touched = True
    if body.keep_alive is True:
        args.append("--keep-alive")
        touched = True
    elif body.keep_alive is False:
        args.append("--no-keep-alive")
        touched = True
    if not touched:
        raise HTTPException(
            status_code=400,
            detail="Provide upstream_url, direct, http2, or keep_alive.",
        )
    result = cli.run(args, timeout=_PROXY_LIFECYCLE_TIMEOUT_S)
    return _steps_response(result)


@router.get("/auth")
def proxy_auth_list():
    """
    Purpose:
        List platform-auth rows (`talos proxy auth list --format json`).
    """
    result = cli.run(["proxy", "auth", "list", "--format", "json"], timeout=15)
    if not result.ok:
        raise HTTPException(
            status_code=400,
            detail=(result.stderr or result.stdout or "proxy auth list failed").strip(),
        )
    parsed = _parse_status_stdout(result.stdout)
    if not parsed:
        raise HTTPException(status_code=500, detail="proxy auth list returned non-JSON output")
    return parsed


@router.post("/auth")
def proxy_auth_add(body: PlatformAuthBody):
    """
    Purpose:
        Add a platform-auth profile through Talos CLI.
    """
    args = [
        "proxy",
        "auth",
        "add",
        "--host",
        body.host,
        "--type",
        body.auth_type or "ntlmv2",
        "--username",
        body.username or "",
        "--password",
        body.password or "",
        "--domain",
        body.domain or "",
        "--domain-hostname",
        body.domain_hostname or "",
    ]
    if body.id:
        args.extend(["--id", body.id])
    if body.name:
        args.extend(["--name", body.name])
    if body.spnego:
        args.append("--spnego")
    if body.negotiate:
        args.append("--negotiate")
    if body.enabled is False:
        args.append("--disabled")
    result = cli.run(args, timeout=_PROXY_LIFECYCLE_TIMEOUT_S)
    return _steps_response(result)


@router.post("/auth/edit")
def proxy_auth_edit(body: PlatformAuthEditBody):
    """
    Purpose:
        Update an existing profile (`talos proxy auth edit`).
    """
    if not (body.id or body.host):
        raise HTTPException(status_code=400, detail="id or host is required.")
    args = ["proxy", "auth", "edit"]
    if body.id:
        args.extend(["--id", body.id])
    if body.name is not None:
        args.extend(["--name", body.name])
    if body.host:
        args.extend(["--host", body.host])
    if body.auth_type:
        args.extend(["--type", body.auth_type])
    if body.username is not None:
        args.extend(["--username", body.username])
    if body.password:
        args.extend(["--password", body.password])
    if body.domain is not None:
        args.extend(["--domain", body.domain])
    if body.domain_hostname is not None:
        args.extend(["--domain-hostname", body.domain_hostname])
    if body.spnego is True:
        args.append("--spnego")
    elif body.spnego is False:
        args.append("--no-spnego")
    if body.negotiate is True:
        args.append("--negotiate")
    elif body.negotiate is False:
        args.append("--no-negotiate")
    result = cli.run(args, timeout=_PROXY_LIFECYCLE_TIMEOUT_S)
    return _steps_response(result)


@router.post("/auth/enable")
def proxy_auth_enable(body: PlatformAuthIdBody):
    """
    Purpose:
        Enable a profile, or the master switch when id/host are omitted.
    """
    args = ["proxy", "auth", "enable"]
    if body.id:
        args.extend(["--id", body.id])
    elif body.host:
        args.extend(["--host", body.host])
    result = cli.run(args, timeout=_PROXY_LIFECYCLE_TIMEOUT_S)
    return _steps_response(result)


@router.post("/auth/disable")
def proxy_auth_disable(body: PlatformAuthIdBody):
    """
    Purpose:
        Disable a profile, or the master switch when id/host are omitted.
    """
    args = ["proxy", "auth", "disable"]
    if body.id:
        args.extend(["--id", body.id])
    elif body.host:
        args.extend(["--host", body.host])
    result = cli.run(args, timeout=_PROXY_LIFECYCLE_TIMEOUT_S)
    return _steps_response(result)


@router.post("/auth/use")
def proxy_auth_use(body: PlatformAuthIdBody):
    """
    Purpose:
        Switch to a profile: enable it and disable others for the same host.
    """
    if not (body.id or body.host):
        raise HTTPException(status_code=400, detail="id or host is required.")
    args = ["proxy", "auth", "use"]
    if body.id:
        args.extend(["--id", body.id])
    elif body.host:
        args.extend(["--host", body.host])
    result = cli.run(args, timeout=_PROXY_LIFECYCLE_TIMEOUT_S)
    return _steps_response(result)


@router.delete("/auth")
def proxy_auth_remove(id: str | None = None, host: str | None = None):
    """
    Purpose:
        Remove a profile by id, or by host when that host is unique.
    """
    profile_id = (id or "").strip()
    host_key = (host or "").strip()
    if not profile_id and not host_key:
        raise HTTPException(status_code=400, detail="id or host is required.")
    args = ["proxy", "auth", "remove"]
    if profile_id:
        args.extend(["--id", profile_id])
    else:
        args.extend(["--host", host_key])
    result = cli.run(args, timeout=_PROXY_LIFECYCLE_TIMEOUT_S)
    return _steps_response(result)
