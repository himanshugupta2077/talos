"""
Module: talos.ui.api

Purpose:
    FastAPI sub-package exposing all /api/* routes for the Talos UI.
    Each sub-module owns one domain — projects, flows, endpoints, roles,
    modules, access, replay, scheduler, mutations, outscope, proxy, stream.

    stream provides the SSE endpoint (/api/stream) that pushes incremental
    DB change events (flow, endpoint_count, sched_counts, proxy_log,
    proxy_status) to connected browser clients without triggering full-page
    reloads.

    proxy provides lifecycle control routes (/api/proxy/start|stop|status)
    backed by the ProxyManager singleton on app.state.

    attacks provides the attack-module routes (/api/attacks/unauth*) for
    bulk-enqueuing AUTH_TEST jobs and managing attack_config settings.

Dependencies: fastapi, talos.projects.*, talos.replay.*, talos.scheduler.*,
              talos.ui.proxy_manager
Data flow:
    HTTP request → router module → core module → DB → JSON response
    HTTP GET /api/stream → SSE generator → polls DB + proxy queue → SSE frames
    HTTP POST /api/proxy/start → ProxyManager.start() → subprocess
Side effects: None at import time.
"""
