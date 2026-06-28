"""
Module: talos.ui.app

Purpose:
    FastAPI application for the Talos web UI.
    Renders server-side HTML via Jinja2 templates.
    All routes are GET-only; no mutations are possible.

Dependencies: fastapi, jinja2, talos.ui.db
Data flow:
    HTTP GET → route handler → db layer → template render → HTML response
Side effects: None (read-only storage access).

Routes:
    GET /                                       → projects list
    GET /project/{id}                           → project overview
    GET /project/{id}/flows                     → paginated flow list
    GET /project/{id}/flows/{flow_id}           → flow detail (HTML)
    GET /project/{id}/flows/{flow_id}/json      → flow detail (JSON for inline rendering)
    GET /project/{id}/endpoints                 → endpoint list
    GET /project/{id}/endpoints/{eid}           → endpoint detail
"""

import json
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlencode

from fastapi import APIRouter, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from talos.ui import db as idb
from talos.ui.proxy_manager import ProxyManager
from talos.ui.api import (
    access as api_access,
    attacks as api_attacks,
    auth as api_auth,
    endpoints as api_endpoints,
    flows as api_flows,
    modules as api_modules,
    mutations as api_mutations,
    outscope as api_outscope,
    projects as api_projects,
    proxy as api_proxy,
    replay as api_replay,
    roles as api_roles,
    scheduler as api_scheduler,
    stream as api_stream,
)

# Templates directory is alongside this file.
_TEMPLATES_DIR = Path(__file__).parent / "templates"


def create_app(projects_root: Path) -> FastAPI:
    """
    Purpose:
        Construct and return the configured FastAPI application.
    Input:
        projects_root — Path to the Talos projects directory (contains registry.json).
    Output:
        FastAPI application instance ready for serving.
    Side effects:
        - Binds projects_root and proxy_manager into app state.
        - Registers a lifespan hook that cleans up the proxy process on shutdown.
    """
    @asynccontextmanager
    async def _lifespan(application: FastAPI):
        """
        Purpose:
            Initialise and tear down app-scoped resources.
            On startup: attach ProxyManager to app.state.
            On shutdown: stop any running proxy subprocess to avoid orphan processes.
        Side effects:
            May terminate a mitmdump subprocess on server shutdown.
        """
        application.state.proxy_manager = ProxyManager(projects_root)
        yield
        await application.state.proxy_manager.cleanup()

    app = FastAPI(title="Talos UI", docs_url=None, redoc_url=None, lifespan=_lifespan)
    app.state.projects_root = projects_root
    templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))

    # Map raw DB source values to display labels used in the flows template.
    # iv_scan kept for backward compatibility with older project databases.
    _SOURCE_LABELS: dict[str, str] = {
        "proxy_capture": "proxy",
        "manual_replay": "replay",
        "auto_replay": "auto replay",
        "iv_scan": "iv scan (legacy)",
    }
    templates.env.filters["source_label"] = lambda s: _SOURCE_LABELS.get(s or "", s or "—")

    # ------------------------------------------------------------------ #
    # Template helpers                                                     #
    # ------------------------------------------------------------------ #

    def _render(request: Request, template: str, context: dict) -> HTMLResponse:
        """Render a Jinja2 template with shared base context injected."""
        # Starlette 0.28+: request is the first positional arg, not in context.
        return templates.TemplateResponse(request, template, context)

    def _fmt_bytes(n: int) -> str:
        """Convert byte count to a human-readable string."""
        for unit in ("B", "KB", "MB", "GB"):
            if n < 1024:
                return f"{n:.1f} {unit}"
            n /= 1024
        return f"{n:.1f} TB"

    def _parse_json_field(raw: str | None) -> dict | list:
        """
        Purpose: Safely parse a JSON string from a DB column.
        Returns empty dict/list on failure rather than raising.
        """
        if not raw:
            return {}
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return {}

    def _decode_body(raw: bytes | None, truncated: int) -> tuple[str, bool]:
        """
        Purpose: Decode a binary body blob to a displayable string.
        Input:
            raw       — bytes from DB (may be None).
            truncated — integer flag (1 = body was truncated at capture time).
        Output:
            Tuple of (display_text, is_truncated).
            display_text is the UTF-8 decoded content, or a fallback message.
        """
        is_truncated = bool(truncated)
        if raw is None:
            return ("(no body)", is_truncated)
        try:
            return (raw.decode("utf-8"), is_truncated)
        except UnicodeDecodeError:
            return (f"(binary, {len(raw):,} bytes)", is_truncated)

    def _maybe_pretty_json(text: str) -> str:
        """
        Purpose: Attempt to pretty-print a JSON string. Returns original on failure.
        Side effects: None.
        """
        try:
            return json.dumps(json.loads(text), indent=2, ensure_ascii=False)
        except (json.JSONDecodeError, TypeError, ValueError):
            return text

    def _flatten_headers(headers: dict) -> list[tuple[str, str]]:
        """
        Purpose: Convert a headers dict to a flat list of (name, value) tuples.
        Handles multi-value headers stored as lists.
        Side effects: None.
        """
        result = []
        for k, v in headers.items():
            if isinstance(v, list):
                for item in v:
                    result.append((str(k), str(item)))
            else:
                result.append((str(k), str(v)))
        return result

    # ------------------------------------------------------------------ #
    # A. Projects list                                                     #
    # ------------------------------------------------------------------ #

    @app.get("/", response_class=HTMLResponse)
    async def projects_list(request: Request) -> HTMLResponse:
        """
        Purpose: Render the projects list from registry.json.
        Output:  HTML page listing all projects with status and scope count.
        """
        registry = idb.load_registry(projects_root)
        projects = list(registry.values())
        # Sort: active first, then by id alphabetically.
        projects.sort(key=lambda p: (0 if p.get("status") == "active" else 1, p.get("id", "")))
        return _render(request, "projects.html", {"projects": projects})

    # ------------------------------------------------------------------ #
    # B. Project overview                                                  #
    # ------------------------------------------------------------------ #

    @app.get("/project/{project_id}", response_class=HTMLResponse)
    async def project_overview(request: Request, project_id: str) -> HTMLResponse:
        """
        Purpose: Render overview for a single project.
        Output:  HTML page with scope, constraints, DB stats, archive size.
        """
        project = idb.get_project_record(projects_root, project_id)
        if project is None:
            raise HTTPException(status_code=404, detail="Project not found")

        db_path = Path(project["data_dir"]) / "talos.db"
        archive_dir = Path(project["data_dir"]) / "archive"

        flow_count = idb.get_flow_count(db_path)
        endpoint_count = idb.get_endpoint_count(db_path)
        archive_bytes = idb.get_archive_size_bytes(archive_dir)

        return _render(request, "project.html", {
            "project": project,
            "flow_count": flow_count,
            "endpoint_count": endpoint_count,
            "archive_size": _fmt_bytes(archive_bytes),
            "db_exists": db_path.exists(),
        })

    # ------------------------------------------------------------------ #
    # C. Flows viewer                                                      #
    # ------------------------------------------------------------------ #

    @app.get("/project/{project_id}/flows", response_class=HTMLResponse)
    async def flows_list(
        request: Request,
        project_id: str,
        page: int = 1,
        limit: int = 50,
        source: str | None = None,
        method: str | None = None,
        host: str | None = None,
        status: str | None = None,
        role: str | None = None,
        module: str | None = None,
    ) -> HTMLResponse:
        """
        Purpose: Render paginated flow list for a project, with optional column filters.
        Input:   page (1-based), limit (default 50, capped at 200), optional filters.
        Output:  HTML page with flow rows, filter bar, and pagination controls.
        """
        project = idb.get_project_record(projects_root, project_id)
        if project is None:
            raise HTTPException(status_code=404, detail="Project not found")

        # Cap limit to prevent oversized loads.
        limit = min(max(limit, 1), 200)
        page = max(page, 1)
        offset = (page - 1) * limit

        db_path = Path(project["data_dir"]) / "talos.db"

        # Coerce status to int (form submits empty string for "all statuses").
        status_int: int | None = int(status) if status else None

        # Active filter values (only set entries); used by template for pagination links.
        active_filters: dict[str, str] = {
            k: v for k, v in {
                "source": source or "",
                "method": method or "",
                "host": host or "",
                "status": status if status else "",
                "role": role or "",
                "module": module or "",
            }.items() if v
        }
        filter_qs = ("&" + urlencode(active_filters)) if active_filters else ""
        # Serialise filters to a plain str so Jinja2 | e escapes " → &quot; safely in the attribute.
        active_filters_json = json.dumps(active_filters)

        total = idb.get_flow_count(
            db_path,
            source=source, method=method, host=host,
            status_code=status_int, role=role, module=module,
        )
        flows = idb.list_flows(
            db_path, offset=offset, limit=limit,
            source=source, method=method, host=host,
            status_code=status_int, role=role, module=module,
        )
        filter_opts = idb.get_flow_filter_options(db_path)

        total_pages = max(1, (total + limit - 1) // limit)

        return _render(request, "flows.html", {
            "project": project,
            "flows": flows,
            "page": page,
            "limit": limit,
            "total": total,
            "total_pages": total_pages,
            "filter_opts": filter_opts,
            "active_filters": active_filters,
            "active_filters_json": active_filters_json,
            "filter_qs": filter_qs,
        })

    # ------------------------------------------------------------------ #
    # D. Flow detail                                                       #
    # ------------------------------------------------------------------ #

    @app.get("/project/{project_id}/flows/{flow_id}", response_class=HTMLResponse)
    async def flow_detail(request: Request, project_id: str, flow_id: str) -> HTMLResponse:
        """
        Purpose: Render full detail for a single flow in Burp-style split view.
        Output:  HTML page with request and response panes side by side.
        """
        project = idb.get_project_record(projects_root, project_id)
        if project is None:
            raise HTTPException(status_code=404, detail="Project not found")

        db_path = Path(project["data_dir"]) / "talos.db"
        flow = idb.get_flow_detail(db_path, flow_id)
        if flow is None:
            raise HTTPException(status_code=404, detail="Flow not found")

        req_headers = _parse_json_field(flow.get("request_headers"))
        resp_headers = _parse_json_field(flow.get("response_headers"))

        req_body_text, req_truncated = _decode_body(
            flow.get("request_body"), flow.get("request_body_truncated", 0)
        )
        resp_body_text, resp_truncated = _decode_body(
            flow.get("response_body"), flow.get("response_body_truncated", 0)
        )

        # Pretty-print JSON bodies where detectable.
        content_type = (flow.get("content_type") or "").lower()
        stripped_req = req_body_text.strip()
        if req_body_text != "(no body)" and stripped_req and stripped_req[0] in ("{", "["):
            req_body_text = _maybe_pretty_json(req_body_text)
        if resp_body_text != "(no body)" and "json" in content_type:
            resp_body_text = _maybe_pretty_json(resp_body_text)

        path = flow.get("path", "/")
        query = flow.get("query", "")
        req_path = f"{path}?{query}" if query else path

        sc = flow.get("status_code")
        if sc and 200 <= sc < 300:
            resp_status_class = "status-2xx"
        elif sc and 300 <= sc < 400:
            resp_status_class = "status-3xx"
        elif sc and 400 <= sc < 500:
            resp_status_class = "status-4xx"
        elif sc and sc >= 500:
            resp_status_class = "status-5xx"
        else:
            resp_status_class = "status-null"

        prev_id, next_id = idb.get_adjacent_flows(db_path, flow_id)

        return _render(request, "flow.html", {
            "project": project,
            "flow": flow,
            "prev_id": prev_id,
            "next_id": next_id,
            "req": {
                "first_line": f"{flow['method']} {req_path} HTTP/1.1",
                "headers": _flatten_headers(req_headers),
                "body": req_body_text,
                "truncated": req_truncated,
            },
            "resp": {
                "first_line": f"HTTP/1.1 {sc or '???'}",
                "headers": _flatten_headers(resp_headers),
                "body": resp_body_text,
                "truncated": resp_truncated,
                "status_class": resp_status_class,
            },
        })

    # ------------------------------------------------------------------ #
    # D2. Flow detail — JSON for inline rendering on the flows list page  #
    # ------------------------------------------------------------------ #

    @app.get("/project/{project_id}/flows/{flow_id}/json")
    async def flow_detail_json(
        request: Request, project_id: str, flow_id: str
    ) -> JSONResponse:
        """
        Purpose:
            Return processed flow detail (req/resp headers+body) as JSON.
            Called by the flows list page to render inline without navigation.
        Input:   project_id, flow_id — path parameters.
        Output:  JSON with req, resp, endpoint_id, role_name, module_name, captured_at.
        Side effects: None (read-only).
        Raises:  404 if project or flow not found.
        """
        project = idb.get_project_record(projects_root, project_id)
        if project is None:
            raise HTTPException(status_code=404, detail="Project not found")

        db_path = Path(project["data_dir"]) / "talos.db"
        flow = idb.get_flow_detail(db_path, flow_id)
        if flow is None:
            raise HTTPException(status_code=404, detail="Flow not found")

        req_headers = _parse_json_field(flow.get("request_headers"))
        resp_headers = _parse_json_field(flow.get("response_headers"))

        req_body_text, req_truncated = _decode_body(
            flow.get("request_body"), flow.get("request_body_truncated", 0)
        )
        resp_body_text, resp_truncated = _decode_body(
            flow.get("response_body"), flow.get("response_body_truncated", 0)
        )

        content_type = (flow.get("content_type") or "").lower()
        stripped_req = req_body_text.strip()
        if req_body_text != "(no body)" and stripped_req and stripped_req[0] in ("{", "["):
            req_body_text = _maybe_pretty_json(req_body_text)
        if resp_body_text != "(no body)" and "json" in content_type:
            resp_body_text = _maybe_pretty_json(resp_body_text)

        path = flow.get("path", "/")
        query = flow.get("query", "")
        req_path = f"{path}?{query}" if query else path

        sc = flow.get("status_code")
        if sc and 200 <= sc < 300:
            resp_status_class = "status-2xx"
        elif sc and 300 <= sc < 400:
            resp_status_class = "status-3xx"
        elif sc and 400 <= sc < 500:
            resp_status_class = "status-4xx"
        elif sc and sc >= 500:
            resp_status_class = "status-5xx"
        else:
            resp_status_class = "status-null"

        return JSONResponse({
            "req": {
                "first_line": f"{flow['method']} {req_path} HTTP/1.1",
                "headers": _flatten_headers(req_headers),
                "body": req_body_text,
                "truncated": req_truncated,
            },
            "resp": {
                "first_line": f"HTTP/1.1 {sc or '???'}",
                "headers": _flatten_headers(resp_headers),
                "body": resp_body_text,
                "truncated": resp_truncated,
                "status_class": resp_status_class,
            },
            "endpoint_id": flow.get("endpoint_id"),
            "role_name": flow.get("role_name") or "",
            "module_name": flow.get("module_name") or "",
            "captured_at": flow.get("captured_at") or "",
        })

    # ------------------------------------------------------------------ #
    # E. Endpoints list                                                    #
    # ------------------------------------------------------------------ #

    @app.get("/project/{project_id}/endpoints", response_class=HTMLResponse)
    async def endpoints_list(
        request: Request,
        project_id: str,
        page: int = 1,
        limit: int = 50,
    ) -> HTMLResponse:
        """
        Purpose: Render paginated list of normalized endpoints for a project.
        Input:   page (1-based), limit (default 50, capped at 200).
        Output:  HTML page with method, host, normalized_path, hit count.
        """
        project = idb.get_project_record(projects_root, project_id)
        if project is None:
            raise HTTPException(status_code=404, detail="Project not found")

        limit = min(max(limit, 1), 200)
        page = max(page, 1)
        offset = (page - 1) * limit

        db_path = Path(project["data_dir"]) / "talos.db"
        total = idb.get_endpoint_count(db_path)
        endpoints = idb.list_endpoints(db_path, offset=offset, limit=limit)

        total_pages = max(1, (total + limit - 1) // limit)

        return _render(request, "endpoints.html", {
            "project": project,
            "endpoints": endpoints,
            "page": page,
            "limit": limit,
            "total": total,
            "total_pages": total_pages,
        })

    # ------------------------------------------------------------------ #
    # F. Endpoint detail                                                   #
    # ------------------------------------------------------------------ #

    @app.get("/project/{project_id}/endpoints/{endpoint_id}", response_class=HTMLResponse)
    async def endpoint_detail(
        request: Request, project_id: str, endpoint_id: str
    ) -> HTMLResponse:
        """
        Purpose: Render detail for a single endpoint: parameters and linked flows.
        Output:  HTML page with parameter table and recent flows.
        """
        project = idb.get_project_record(projects_root, project_id)
        if project is None:
            raise HTTPException(status_code=404, detail="Project not found")

        db_path = Path(project["data_dir"]) / "talos.db"
        endpoint = idb.get_endpoint_detail(db_path, endpoint_id)
        if endpoint is None:
            raise HTTPException(status_code=404, detail="Endpoint not found")

        parameters = idb.get_endpoint_parameters(db_path, endpoint_id)
        linked_flows = idb.get_endpoint_flows(db_path, endpoint_id)

        # Parse example_values JSON strings for each parameter.
        for param in parameters:
            raw = param.get("example_values", "[]")
            try:
                param["example_values_parsed"] = json.loads(raw)
            except (json.JSONDecodeError, TypeError):
                param["example_values_parsed"] = []

        endpoint_roles = [
            row["role_name"] for row in idb.list_endpoint_roles(db_path, endpoint_id)
        ]

        prev_id, next_id = idb.get_adjacent_endpoints(db_path, endpoint_id)

        return _render(request, "endpoint.html", {
            "project": project,
            "endpoint": endpoint,
            "endpoint_roles": endpoint_roles,
            "parameters": parameters,
            "linked_flows": linked_flows,
            "prev_id": prev_id,
            "next_id": next_id,
        })

    # ------------------------------------------------------------------ #
    # G. Management pages (shell templates; data loaded via API by JS)    #
    # ------------------------------------------------------------------ #

    @app.get("/project/{project_id}/roles", response_class=HTMLResponse)
    async def roles_page(request: Request, project_id: str) -> HTMLResponse:
        """Purpose: Render shell page for role management. JS fetches /api/roles."""
        project = idb.get_project_record(projects_root, project_id)
        if project is None:
            raise HTTPException(status_code=404, detail="Project not found")
        return _render(request, "roles.html", {"project": project})

    @app.get("/project/{project_id}/modules", response_class=HTMLResponse)
    async def modules_page(request: Request, project_id: str) -> HTMLResponse:
        """Purpose: Render shell page for module management. JS fetches /api/modules."""
        project = idb.get_project_record(projects_root, project_id)
        if project is None:
            raise HTTPException(status_code=404, detail="Project not found")
        return _render(request, "modules.html", {"project": project})

    @app.get("/project/{project_id}/access", response_class=HTMLResponse)
    async def access_page(request: Request, project_id: str) -> HTMLResponse:
        """Purpose: Render shell page for access matrix. JS fetches /api/access."""
        project = idb.get_project_record(projects_root, project_id)
        if project is None:
            raise HTTPException(status_code=404, detail="Project not found")
        return _render(request, "access.html", {"project": project})

    @app.get("/project/{project_id}/replay", response_class=HTMLResponse)
    async def replay_page(request: Request, project_id: str) -> HTMLResponse:
        """Purpose: Render shell page for replay controls. JS fetches /api/flows and triggers replays."""
        project = idb.get_project_record(projects_root, project_id)
        if project is None:
            raise HTTPException(status_code=404, detail="Project not found")
        return _render(request, "replay.html", {"project": project})

    @app.get("/project/{project_id}/scheduler", response_class=HTMLResponse)
    async def scheduler_page(request: Request, project_id: str) -> HTMLResponse:
        """Purpose: Render shell page for scheduler queue and config. JS fetches /api/scheduler."""
        project = idb.get_project_record(projects_root, project_id)
        if project is None:
            raise HTTPException(status_code=404, detail="Project not found")
        return _render(request, "scheduler.html", {"project": project})

    @app.get("/project/{project_id}/mutations", response_class=HTMLResponse)
    async def mutations_page(request: Request, project_id: str) -> HTMLResponse:
        """Purpose: Render shell page for mutation management. JS fetches /api/mutations."""
        project = idb.get_project_record(projects_root, project_id)
        if project is None:
            raise HTTPException(status_code=404, detail="Project not found")
        return _render(request, "mutations.html", {"project": project})

    @app.get("/project/{project_id}/outscope", response_class=HTMLResponse)
    async def outscope_page(request: Request, project_id: str) -> HTMLResponse:
        """Purpose: Render shell page for out-of-scope domain management. JS fetches /api/outscope."""
        project = idb.get_project_record(projects_root, project_id)
        if project is None:
            raise HTTPException(status_code=404, detail="Project not found")
        return _render(request, "outscope.html", {"project": project})

    @app.get("/project/{project_id}/proxy", response_class=HTMLResponse)
    async def proxy_page(request: Request, project_id: str) -> HTMLResponse:
        """Purpose: Render proxy control panel (start/stop, status, live log stream)."""
        project = idb.get_project_record(projects_root, project_id)
        if project is None:
            raise HTTPException(status_code=404, detail="Project not found")
        return _render(request, "proxy.html", {"project": project})

    @app.get("/project/{project_id}/attacks", response_class=HTMLResponse)
    async def attacks_page(request: Request, project_id: str) -> HTMLResponse:
        """Purpose: Render the attacks module page. JS fetches /api/attacks/unauth."""
        project = idb.get_project_record(projects_root, project_id)
        if project is None:
            raise HTTPException(status_code=404, detail="Project not found")
        return _render(request, "attacks.html", {"project": project})

    # ------------------------------------------------------------------ #
    # API routers                                                          #
    # ------------------------------------------------------------------ #

    _api = APIRouter(prefix="/api")
    _api.include_router(api_projects.router)
    _api.include_router(api_flows.router)
    _api.include_router(api_endpoints.router)
    _api.include_router(api_roles.router)
    _api.include_router(api_modules.router)
    _api.include_router(api_access.router)
    _api.include_router(api_auth.router)
    _api.include_router(api_proxy.router)
    _api.include_router(api_replay.router)
    _api.include_router(api_scheduler.router)
    _api.include_router(api_mutations.router)
    _api.include_router(api_outscope.router)
    _api.include_router(api_stream.router)
    _api.include_router(api_attacks.router)
    app.include_router(_api)

    return app
