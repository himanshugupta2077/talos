"""
Module: talos.ui.api.proxy

Purpose:
    REST routes for controlling the Talos capture proxy lifecycle.
    Thin wrappers over the ProxyManager singleton on app.state.

Dependencies: fastapi, pydantic, talos.ui.proxy_manager
Data flow:
    POST /api/proxy/start  → ProxyManager.start() → JSON result
    POST /api/proxy/stop   → ProxyManager.stop()  → JSON result
    GET  /api/proxy/status → ProxyManager.status  → JSON
Side effects:
    POST /api/proxy/start — spawns mitmdump subprocess.
    POST /api/proxy/stop  — terminates mitmdump subprocess.

Routes:
    POST /api/proxy/start  → start proxy (optional port/host in body)
    POST /api/proxy/stop   → stop running proxy
    GET  /api/proxy/status → current status and pid
"""

from typing import Optional

from fastapi import APIRouter, Request
from pydantic import BaseModel

from talos.ui.proxy_manager import ProxyManager

router = APIRouter(prefix="/proxy", tags=["proxy"])


def _mgr(request: Request) -> ProxyManager:
    """
    Purpose: Extract the ProxyManager from app.state.
    Input:   request — FastAPI Request carrying app.state.proxy_manager.
    Output:  ProxyManager instance.
    Side effects: None.
    """
    return request.app.state.proxy_manager


class _StartBody(BaseModel):
    """Optional start parameters; defaults match proxy CLI defaults."""
    port: Optional[int] = 8080
    listen_host: Optional[str] = "127.0.0.1"


@router.post("/start")
async def proxy_start(request: Request, body: _StartBody = _StartBody()) -> dict:
    """
    Purpose:
        Start the mitmdump capture proxy for the currently active project.
    Input:   Optional body with port and listen_host.
    Output:  {"ok": bool, "detail": str}
    Side effects:
        Spawns mitmdump subprocess if not already running.
        Returns error dict (ok=false) rather than raising when start fails.
    """
    return await _mgr(request).start(
        port=body.port or 8080,
        listen_host=body.listen_host or "127.0.0.1",
    )


@router.post("/stop")
async def proxy_stop(request: Request) -> dict:
    """
    Purpose:
        Stop the running mitmdump capture proxy.
    Output:  {"ok": bool, "detail": str}
    Side effects:
        Terminates the subprocess; cancels the log reader task.
    """
    return await _mgr(request).stop()


@router.get("/status")
def proxy_status(request: Request) -> dict:
    """
    Purpose:
        Return the current proxy running state and process ID.
    Output:  {"status": "running" | "stopped", "pid": int | null}
    Side effects: None.
    """
    mgr = _mgr(request)
    return {"status": mgr.status, "pid": mgr.pid}
