"""
Module: talos.proxy.addon

Purpose:
    mitmproxy addon for Talos — the capture-only layer.
    Intercepts completed HTTP flows, enforces project scope, extracts a
    minimal raw representation, and pushes it into the flow queue.

Strict rules enforced here (no exceptions):
    - No database writes.
    - No normalization or transformation of extracted data.
    - No session detection.
    - No endpoint clustering.
    - No attack logic.
    - No blocking operations inside the proxy thread.

Extraction specifics:
    - project_id is NOT included in the flow payload; attached at worker layer.
    - role_id and module_id are resolved at addon startup and injected into every
      flow dict before it is enqueued. The worker persists them as-is without
      re-resolving. This preserves audit integrity — role/module are locked to the
      identity context that was active when the proxy was started.
    - Timestamps use mitmproxy's own start/end floats — no clock of our own.
    - URL fragment is stripped; all other normalization stays in the worker.
    - Noisy headers (proxy-injected, connection-management) are dropped using
      a per-project filter file loaded once at addon startup.

Dependencies:
    mitmproxy, pathlib, talos.proxy.scope, talos.proxy.queue,
    talos.projects.manager, talos.projects.access, talos.projects.db, talos.config,
    talos.configuration
Data flow:
    mitmproxy → request() hook → HTTPManipulationEngine (request rules)
              → server
              → response() hook → HTTPManipulationEngine (response rules)
              → scope check → _extract_flow() → flow_queue.put()
Side effects:
    - Resolves the effective project (TALOS_PROJECT override or registry
      ACTIVE) on addon instantiation.
    - Loads EffectiveConfig once at startup (drop headers, HTTP rules,
      capture constraints).
    - Mutates requests/responses per http.rules when the engine is enabled.
    - Enqueues flow dicts into the module-level FlowQueue.
    - Emits CAPTURE/SKIP events at DEBUG level (not visible by default).
      FlowWorker shutdown log shows processed count for verification.
"""

import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from mitmproxy import http

from talos.config import TalosConfig
from talos.configuration.http_engine import HTTPManipulationEngine
from talos.configuration.manager import load_effective_config
from talos.configuration.model import EffectiveConfig
from talos.projects.access import get_active_role_id, get_active_module_id
from talos.projects.db import seed_default_context
from talos.projects.manager import ProjectManager, NoActiveProject, ProjectNotFound
from talos.projects.model import Project, ScopeConstraints
from talos.projects.outscope import load_prefix_set
from talos.proxy.scope import is_url_in_scope
from talos.proxy.queue import flow_queue
from talos.url_identity import UrlIdentityError, parse_request_url
from talos.worker import FlowWorker

logger = logging.getLogger(__name__)



class TalosAddon:
    """
    Purpose:
        mitmproxy addon class. One instance is created per mitmdump session.

    Fields:
        _project        — Active project loaded at startup.
        _scope          — Scope pattern list from the project config.
        _constraints    — Capture constraints from EffectiveConfig (bodies / size).
        _drop_headers   — Frozenset of lowercase header names to exclude from storage.
                          Loaded once from EffectiveConfig at startup.
        _http_engine    — HTTPManipulationEngine for declarative http.rules.
        _effective      — Immutable EffectiveConfig snapshot for this session.
        _out_of_scope   — Frozenset of Basic Scope prefixes that are out-of-scope.
                          Loaded once from the DB at startup; overrides the allow-list.
        _role_id        — UUID of the active role at proxy start; stamped on every flow.
        _module_id      — UUID of the active module at proxy start; stamped on every flow.
        _worker         — FlowWorker thread started at addon init; stopped in done().

    Note:
        ReplayScheduler no longer runs inside the proxy process. Start it with
        `talos scheduler start` so attack work survives proxy restarts.

    Invariant:
        Instantiation raises NoActiveProject if no project is bound
        (registry ACTIVE or TALOS_PROJECT / --project process override) —
        the proxy refuses to run without a bound project.
        role_id and module_id are always resolved before any flow is enqueued —
        seed_default_context guarantees the global fallback is present.
    """

    def __init__(self) -> None:
        config = TalosConfig.from_env()
        # Inherits TALOS_PROJECT when talos --project <id> proxy start exported it.
        manager = ProjectManager(projects_root=config.projects_dir)
        try:
            project = manager.active()
        except ProjectNotFound as exc:
            raise NoActiveProject(str(exc)) from exc

        if project is None:
            # Hard gate — no project, no capture. Fail loudly at startup.
            raise NoActiveProject(
                "No active project. Run 'talos project open <id>', "
                "or pass --project <id> / set TALOS_PROJECT."
            )

        # Single layered config snapshot for this proxy session (CLI-022).
        effective: EffectiveConfig = load_effective_config(
            project, data_dir=config.data_dir
        )
        self._effective: EffectiveConfig = effective

        self._project: Project = project
        self._scope: list[str] = project.scope
        # Prefer EffectiveConfig capture settings over registry constraints so
        # global/project.yaml overrides apply without rewriting the registry.
        self._constraints: ScopeConstraints = ScopeConstraints(
            capture_in_scope_only=True,
            store_bodies=effective.capture.store_bodies,
            max_body_size=effective.capture.max_body_size,
        )
        self._drop_headers: frozenset[str] = effective.drop_headers_set()
        # Single HTTP Manipulation Engine for request + response rules.
        # Config changes take effect on next proxy restart (or config notify).
        self._http_engine: HTTPManipulationEngine = HTTPManipulationEngine.from_http_section(
            effective.http
        )

        # Load out-of-scope prefixes once at startup.  Changes made via CLI
        # during a live session take effect on next proxy restart.
        self._out_of_scope: frozenset[str] = load_prefix_set(project.db_path)

        # Ensure global role and module exist before reading active IDs.
        # Must run before any call to get_active_role_id / get_active_module_id.
        seed_default_context(project.db_path)

        # Resolve capture-time identity once at startup — immutable for this session.
        # Why IDs not names: FK integrity in the flows table; name changes after
        # capture do not silently corrupt historical records.
        self._role_id: str = get_active_role_id(project.db_path)
        self._module_id: str = get_active_module_id(project.db_path)

        # Start the worker thread. Must happen after the queue is ready so no
        # flows are enqueued before the worker is consuming.
        self._worker = FlowWorker(project=project, queue=flow_queue)
        self._worker.start()

        logger.info(
            "Proxy addon loaded. project=%s scope_entries=%d "
            "out_of_scope_prefixes=%d store_bodies=%s max_body=%d drop_headers=%d "
            "http_engine=%s http_rules=%d",
            project.id,
            len(self._scope),
            len(self._out_of_scope),
            self._constraints.store_bodies,
            self._constraints.max_body_size,
            len(self._drop_headers),
            "on" if self._http_engine.enabled else "off",
            len(self._http_engine.rules),
        )

    def done(self) -> None:
        """
        Purpose:
            Called by mitmproxy when the addon session ends (proxy shutting down).
            Signals the worker to stop and waits for it to drain the queue.
        Side effects:
            - Stops the worker thread; flushes remaining flows to DB + archive.
        """
        self._worker.stop()

    def request(self, flow: http.HTTPFlow) -> None:
        """
        Purpose:
            Called by mitmproxy before the request is forwarded to the server.
            Runs the HTTP Manipulation Engine (request-direction rules).
        Side effects:
            - May mutate method, URL, headers, cookies, query, body.
            - May delay, drop, or abort the flow per rule actions.
        """
        context = {
            "passive_capture": True,
            "role_id": self._role_id,
            "module_id": self._module_id,
        }
        self._http_engine.apply_request_flow(flow, context=context)

    def response(self, flow: http.HTTPFlow) -> None:
        """
        Purpose:
            Called by mitmproxy after a complete request/response cycle.
            1. Apply response-direction HTTP rules (before capture so stored
               flows reflect what the client receives).
            2. Scope check, extract flow data, enqueue for workers.
        Input:
            flow — mitmproxy HTTPFlow with both request and response populated.
        Side effects:
            - May mutate response headers, cookies, status, body.
            - Enqueues extracted dict if in scope.
            - Out-of-scope flows produce no output and no side effects.
        """
        context = {
            "passive_capture": True,
            "role_id": self._role_id,
            "module_id": self._module_id,
        }
        self._http_engine.apply_response_flow(flow, context=context)

        # Shared Basic Scope evaluator: out-of-scope overrides in-scope;
        # matching uses full URL identity (scheme, host, port, path).
        if not is_url_in_scope(
            flow.request.pretty_url,
            self._scope,
            self._out_of_scope,
        ):
            logger.debug("SKIP %s %s", flow.request.method, flow.request.pretty_url)
            return

        extracted = _extract_flow(flow, self._constraints, self._drop_headers)
        # Attach capture-time identity — resolved once at addon startup.
        # Immutable per flow: role/module must not change after capture.
        extracted["role_id"] = self._role_id
        extracted["module_id"] = self._module_id
        flow_queue.put(extracted)

        response = flow.response
        status = response.status_code if response is not None else "no-response"
        logger.debug(
            "CAPTURE %s %s %s -> %s",
            extracted["flow_id"][:8],
            extracted["method"],
            extracted["url"],
            status,
        )


def _extract_flow(
    flow: http.HTTPFlow,
    constraints: ScopeConstraints,
    drop_headers: frozenset[str],
) -> dict:
    """
    Purpose:
        Produce a minimal, raw dict from a completed mitmproxy HTTPFlow.
        No normalization beyond fragment stripping and header filtering.
        No project context — project_id is attached at the worker layer.
    Input:
        flow         — completed mitmproxy HTTPFlow.
        constraints  — active capture constraints (body storage, size limit).
        drop_headers — lowercase set of header names to exclude.
    Output:
        Dict containing all captured fields ready for the queue.
    Side effects: None.
    """
    request = flow.request
    response = flow.response

    req_body, req_truncated = _capture_body(request.content, constraints)
    resp_body, resp_truncated = _capture_body(
        response.content if response is not None else None,
        constraints,
    )

    # Parse the URL once — derive path, query, fragment-stripped URL, and
    # canonical origin for endpoint identity (scheme + authority with ports).
    parsed = urlsplit(request.pretty_url)
    clean_url = parsed._replace(fragment="").geturl()
    path = parsed.path
    query = parsed.query or ""

    # Canonical origin for endpoint clustering (method + origin + path).
    # Falls back to pretty_host when the URL cannot be parsed as http(s).
    try:
        identity = parse_request_url(clean_url)
        origin = identity.canonical_origin
        host_display = identity.hostname
    except UrlIdentityError:
        origin = request.pretty_host
        host_display = request.pretty_host

    return {
        "flow_id": str(uuid.uuid4()),
        # mitmproxy timestamps are Unix floats; convert to ISO-8601 for portability.
        "request_start": _ts_to_iso(request.timestamp_start),
        "response_end": _ts_to_iso(
            response.timestamp_end if response is not None else None
        ),
        "method": request.method,
        # Fragment removed — never meaningful for server-side analysis.
        "url": clean_url,
        # Host field carries canonical origin so endpoints remain distinct
        # across non-default ports and schemes (see worker._upsert_endpoint).
        "host": origin,
        "hostname": host_display,
        "path": path,
        "query": query,
        "request_headers": _filter_headers(dict(request.headers), drop_headers),
        "request_cookies": dict(request.cookies),
        "request_body": req_body,
        "request_body_truncated": req_truncated,
        "status_code": response.status_code if response is not None else None,
        "response_headers": (
            _filter_headers(dict(response.headers), drop_headers)
            if response is not None
            else {}
        ),
        "response_body": resp_body,
        "response_body_truncated": resp_truncated,
    }


def _capture_body(
    content: bytes | None,
    constraints: ScopeConstraints,
) -> tuple[bytes | None, bool]:
    """
    Purpose:
        Apply body storage constraints to raw content bytes.
    Input:
        content     — raw body bytes from mitmproxy; None if body is absent.
        constraints — project capture constraints.
    Output:
        (body, truncated) — body bytes (possibly truncated) and a bool flag.
    Rules:
        - store_bodies=False → return (None, False); body is not stored.
        - len(content) > max_body_size → truncate, return (truncated_bytes, True).
        - Otherwise → return (content, False).
    Side effects: None.
    """
    if not constraints.store_bodies or content is None:
        return None, False

    if len(content) > constraints.max_body_size:
        return content[: constraints.max_body_size], True

    return content, False


def _load_drop_headers(path: Path) -> frozenset[str]:
    """
    Purpose:
        Load the set of header names to exclude from captured flows.
        Reads a text file with one header name per line; ignores comments and blanks.
    Input:
        path — absolute path to the project's headers_drop.txt.
    Output:
        Frozenset of lowercase header names to drop.
    Edge case:
        File absent → returns empty frozenset; all headers pass through.
        This is non-fatal: proxy still starts; user gets a WARNING log.
    Side effects:
        Reads from disk once at addon startup. Not re-read during a session.
    """
    if not path.exists():
        logger.warning(
            "headers_drop file not found at %s — all headers will be captured", path
        )
        return frozenset()

    names: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            names.add(stripped.lower())
    return frozenset(names)


def _filter_headers(headers: dict, drop_headers: frozenset[str]) -> dict:
    """
    Purpose:
        Remove known-noisy headers from a header dict before storage.
    Input:
        headers      — raw {name: value} dict from mitmproxy.
        drop_headers — lowercase set of names to exclude.
    Output:
        New dict with excluded headers removed. Original is not mutated.
    Side effects: None.
    """
    return {k: v for k, v in headers.items() if k.lower() not in drop_headers}


def _ts_to_iso(ts: float | None) -> str | None:
    """
    Purpose:
        Convert a Unix float timestamp (from mitmproxy) to UTC ISO-8601 string.
    Input:  ts — Unix timestamp float, or None if the event did not occur.
    Output: ISO-8601 string, or None.
    Side effects: None.
    """
    if ts is None:
        return None
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


# mitmproxy iterates this list at script load time to register addons.
# Must be a module-level list — mitmproxy does NOT call a function named addons().
# Instantiation here validates the active project; NoActiveProject is raised
# (and logged by mitmproxy) if none is set. The CLI gate in proxy/cli.py prevents
# reaching this point without an active project under normal operation.
addons = [TalosAddon()]
