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
    talos.projects.manager, talos.projects.access, talos.projects.db, talos.config
Data flow:
    mitmproxy → response() hook → scope check → _extract_flow()
              → attach role_id/module_id → flow_queue.put()
Side effects:
    - Reads the active project from the registry on addon instantiation.
    - Reads the project's headers_drop.txt once at startup.
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
from talos.projects.access import get_active_role_id, get_active_module_id
from talos.projects.db import seed_default_context
from talos.projects.manager import ProjectManager, NoActiveProject
from talos.projects.model import Project, ScopeConstraints
from talos.projects.outscope import load_domain_set
from talos.projects.mutation import load_mutations
from talos.proxy.scope import in_scope, is_out_of_scope
from talos.proxy.queue import flow_queue
from talos.worker import FlowWorker
from talos.scheduler.scheduler import ReplayScheduler

logger = logging.getLogger(__name__)



class TalosAddon:
    """
    Purpose:
        mitmproxy addon class. One instance is created per mitmdump session.

    Fields:
        _project        — Active project loaded at startup.
        _scope          — Scope pattern list from the project config.
        _constraints    — Capture constraints from the project config.
        _drop_headers   — Frozenset of lowercase header names to exclude from storage.
                          Loaded once from the project's headers_drop.txt at startup.
        _blocked_domains — Frozenset of lowercase domain strings that are out-of-scope.
                           Loaded once from the DB at startup; overrides the allow-list.
        _role_id        — UUID of the active role at proxy start; stamped on every flow.
        _module_id      — UUID of the active module at proxy start; stamped on every flow.
        _mutations      — List of enabled mutation dicts loaded at startup; applied in request().
        _worker         — FlowWorker thread started at addon init; stopped in done().
        _scheduler      — ReplayScheduler daemon thread; started after worker, stopped in done().

    Invariant:
        Instantiation raises NoActiveProject if no project is active —
        the proxy refuses to run without a bound project.
        role_id and module_id are always resolved before any flow is enqueued —
        seed_default_context guarantees the global fallback is present.
    """

    def __init__(self) -> None:
        config = TalosConfig.from_env()
        manager = ProjectManager(projects_root=config.projects_dir)
        project = manager.active()

        if project is None:
            # Hard gate — no project, no capture. Fail loudly at startup.
            raise NoActiveProject(
                "No active project. Run 'talos project open <id>' before starting the proxy."
            )

        self._project: Project = project
        self._scope: list[str] = project.scope
        self._constraints: ScopeConstraints = project.constraints
        self._drop_headers: frozenset[str] = _load_drop_headers(
            project.headers_drop_path
        )

        # Load out-of-scope domains once at startup.  Changes made via CLI
        # during a live session take effect on next proxy restart.
        self._blocked_domains: frozenset[str] = load_domain_set(project.db_path)

        # Load request mutations once at startup.  Changes made via CLI
        # during a live session take effect on next proxy restart.
        self._mutations: list[dict] = load_mutations(project.db_path)

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

        # Start the scheduler as a daemon thread alongside the proxy.
        self._scheduler = ReplayScheduler(project=project)
        self._scheduler.start()

        logger.info(
            "Proxy addon loaded. project=%s scope_entries=%d "
            "out_of_scope_domains=%d store_bodies=%s max_body=%d drop_headers=%d "
            "mutations=%d",
            project.id,
            len(self._scope),
            len(self._blocked_domains),
            self._constraints.store_bodies,
            self._constraints.max_body_size,
            len(self._drop_headers),
            len(self._mutations),
        )

    def done(self) -> None:
        """
        Purpose:
            Called by mitmproxy when the addon session ends (proxy shutting down).
            Signals the worker to stop and waits for it to drain the queue.
        Side effects:
            - Stops the worker thread; flushes remaining flows to DB + archive.
        - Stops the scheduler thread.
        """
        self._worker.stop()
        self._scheduler.stop()

    def request(self, flow: http.HTTPFlow) -> None:

        """
        Purpose:
            Called by mitmproxy before the request is forwarded to the server.
            Applies all enabled request mutations (header injections) loaded at
            startup. Runs before the response hook so the server sees the
            mutated request and the captured flow includes the injected headers.
        Side effects:
            - Mutates flow.request.headers for each enabled header mutation.
              Existing headers with the same name are overwritten.
        """

        """
        Purpose:
            Called by mitmproxy before the request is forwarded to the server.

            Applies all enabled request mutations and removes conditional cache
            headers so every request reaches the origin server instead of being
            answered with HTTP 304 Not Modified.

        Side effects:
            - Removes If-None-Match.
            - Removes If-Modified-Since.
            - Applies configured header mutations.
        """

        # ------------------------------------------------------------------
        # Remove conditional cache validators.
        #
        # Browsers frequently send these headers which allow the server to
        # respond with 304 Not Modified. Talos wants fresh responses for
        # Endpoint Intelligence and Input Validation, so strip them before
        # forwarding upstream.
        # ------------------------------------------------------------------
        flow.request.headers.pop("If-None-Match", None)
        flow.request.headers.pop("If-Modified-Since", None)

        # Apply configured request mutations.
        for m in self._mutations:
            if m["type"] == "header":
                flow.request.headers[m["key"]] = m["value"]

    def response(self, flow: http.HTTPFlow) -> None:
        """
        Purpose:
            Called by mitmproxy after a complete request/response cycle.
            Applies scope check, extracts flow data, enqueues for workers.
        Input:
            flow — mitmproxy HTTPFlow with both request and response populated.
        Side effects:
            - Enqueues extracted dict if in scope.
            - Out-of-scope flows produce no output and no side effects.
        """
        host = flow.request.pretty_host

        # Scope gate — drop out-of-scope flows immediately.
        if not in_scope(flow.request.pretty_url, self._scope):
            logger.debug("SKIP %s %s", flow.request.method, flow.request.pretty_url)
            return

        host = flow.request.pretty_host

        # Out-of-scope override — blocked domains are never captured even when
        # they match the scope allow-list.
        if is_out_of_scope(host, self._blocked_domains):
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

    # Parse the URL once — derive path, query, and fragment-stripped URL from
    # the same parse to avoid redundant string operations.
    parsed = urlsplit(request.pretty_url)
    clean_url = parsed._replace(fragment="").geturl()
    path = parsed.path
    query = parsed.query or ""

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
        "host": request.pretty_host,
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
