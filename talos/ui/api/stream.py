"""
Module: talos.ui.api.stream

Purpose:
    Server-Sent Events (SSE) endpoint that pushes DB change notifications to the
    browser without triggering full-page reloads.

    The server polls the project SQLite database at a fixed interval and emits
    lightweight JSON events for:
        flow           — a new flow was persisted (one event per flow)
        endpoint_count — the total normalised endpoint count changed
        sched_counts   — the scheduler status counts changed
        proxy_log      — one log line from the mitmdump process stdout
        proxy_status   — proxy running state changed ("running" / "stopped")

    The client receives these events and patches only the affected DOM region.
    No full re-renders; layout stays fixed.

Dependencies: fastapi, asyncio, json, talos.ui.db, talos.scheduler.db,
              talos.ui.api._deps, talos.ui.proxy_manager
Data flow:
    HTTP GET /api/stream
        → _stream_events() generator
        → polls DB every _POLL_INTERVAL seconds
        → drains proxy subscriber queue each cycle
        → yields SSE-formatted frames

Side effects:
    Holds an open HTTP connection per connected client until the client
    disconnects or the server shuts down.
    Opens read-only SQLite connections on every poll cycle; does not hold
    a persistent connection.
    Subscribes to ProxyManager on connect; unsubscribes on disconnect.

Stability contract:
    - Never emits a full dataset replacement — only incremental deltas.
    - Caps new-flow bursts at _MAX_FLOWS_PER_POLL per cycle.
    - Emits a keepalive SSE comment every cycle to prevent proxy/LB timeouts.
    - Falls back to a no-op if the DB is absent or a table is missing (stream stays
      open, client retries naturally via EventSource reconnect).
    - Proxy events are best-effort: if the subscriber queue is full, lines are
      dropped on the producer side without affecting the stream connection.
"""

import asyncio
import json
import logging

from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import StreamingResponse

from talos.ui import db as idb
from talos.ui.api._deps import ActiveProject
from talos.ui.proxy_manager import ProxyManager
from talos.scheduler import db as sched_db

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/stream", tags=["stream"])

# Seconds between DB polls.  Low enough for near-real-time feel; high enough to
# avoid hammering SQLite on a loaded machine.
_POLL_INTERVAL: float = 2.0

# Max new flows emitted per poll cycle.  Prevents burst flooding the client when
# many flows arrive at once (e.g. proxy replays).
_MAX_FLOWS_PER_POLL: int = 50


def _sse(event: str, data: object) -> str:
    """
    Purpose: Serialise a single SSE frame.
    Input:   event — event-type label; data — JSON-serialisable payload.
    Output:  SSE wire format: "event: …\\ndata: …\\n\\n"
    Side effects: None.
    """
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


async def _stream_events(
    db_path: Path,
    project_id: str,
    proxy_manager: ProxyManager | None = None,
):
    """
    Purpose:
        Async generator that yields SSE frames for the lifetime of the client
        connection.  Maintains three independent cursors so each domain (flows,
        endpoints, scheduler) is checked and emitted independently.

        Also subscribes to the ProxyManager (when provided) and drains its
        per-client queue each poll cycle, emitting proxy_log and proxy_status
        events.  Recent log history is emitted immediately on connect so the
        client has context from the moment the stream opens.

        Cursor initialisation from current DB state ensures the client never
        receives the full historical dataset on first connect — only events that
        occur after the connection is established.

    Input:
        db_path       — Path to the active project's talos.db.
        project_id    — Active project ID string (used for scheduler queries).
        proxy_manager — Optional ProxyManager; None disables proxy events.

    Output:
        SSE-formatted strings yielded asynchronously.

    Side effects:
        Opens read-only SQLite connections on each poll cycle.
        Subscribes to proxy_manager on entry; unsubscribes on generator cleanup.
    """
    # ── Subscribe to proxy manager ──────────────────────────────────────────
    # The queue receives ("log", line) and ("status", status_str) tuples.
    proxy_queue: asyncio.Queue | None = None
    if proxy_manager is not None:
        proxy_queue = proxy_manager.subscribe()

    try:
        # ── Initialise DB cursors ───────────────────────────────────────────
        # Flow cursor: ISO timestamp of the newest existing flow.
        # If the DB is empty we use the Unix epoch so every future row is newer.
        flow_cursor: str = idb.get_latest_flow_captured_at(db_path) or "1970-01-01T00:00:00"

        # Endpoint count: track absolute count; emit when it changes.
        endpoint_count: int = idb.get_endpoint_count(db_path)

        # Scheduler counts: track full status dict; emit when any key changes.
        sched_counts: dict = {}
        try:
            sched_counts = sched_db.get_queue_status(db_path)
        except Exception:
            pass  # Scheduler table may not exist yet; stream continues.

        # Handshake event — confirms the stream is live and carries the project id.
        yield _sse("connected", {"project": project_id})

        # ── Flush proxy history immediately on connect ──────────────────────
        # The subscribe() call pre-seeded the queue with buffered log lines and
        # current status; drain those now so the client renders context at once.
        if proxy_queue is not None:
            while True:
                try:
                    kind, payload = proxy_queue.get_nowait()
                    if kind == "log":
                        yield _sse("proxy_log", {"line": payload})
                    elif kind == "status":
                        yield _sse("proxy_status", {"status": payload})
                except asyncio.QueueEmpty:
                    break

        while True:
            await asyncio.sleep(_POLL_INTERVAL)

            # ── Flow delta ──────────────────────────────────────────────────
            try:
                new_flows = idb.list_flows_after(
                    db_path, flow_cursor, limit=_MAX_FLOWS_PER_POLL
                )
            except Exception:
                logger.debug("stream: flow delta query failed — skipping cycle", exc_info=True)
                new_flows = []

            if new_flows:
                # Advance cursor to newest seen so the next cycle only fetches newer rows.
                flow_cursor = new_flows[-1]["captured_at"]
                for flow in new_flows:
                    yield _sse("flow", flow)

            # ── Endpoint count delta ────────────────────────────────────────
            try:
                new_ec = idb.get_endpoint_count(db_path)
            except Exception:
                new_ec = endpoint_count

            if new_ec != endpoint_count:
                endpoint_count = new_ec
                yield _sse("endpoint_count", {"total": endpoint_count})

            # ── Scheduler count delta ───────────────────────────────────────
            try:
                new_sc = sched_db.get_queue_status(db_path)
            except Exception:
                new_sc = sched_counts

            if new_sc != sched_counts:
                sched_counts = new_sc
                yield _sse("sched_counts", sched_counts)

            # ── Proxy log and status delta ──────────────────────────────────
            # Drain all items queued since the last cycle; non-blocking.
            if proxy_queue is not None:
                while True:
                    try:
                        kind, payload = proxy_queue.get_nowait()
                        if kind == "log":
                            yield _sse("proxy_log", {"line": payload})
                        elif kind == "status":
                            yield _sse("proxy_status", {"status": payload})
                    except asyncio.QueueEmpty:
                        break

            # Keepalive SSE comment — prevents intermediate proxies and load
            # balancers from closing idle connections between payload events.
            yield ": keepalive\n\n"

    finally:
        # Ensure the subscriber queue is removed even if the client disconnects
        # mid-stream or the generator is garbage-collected.
        if proxy_manager is not None and proxy_queue is not None:
            proxy_manager.unsubscribe(proxy_queue)


@router.get("")
async def stream_events(request: Request, project: ActiveProject) -> StreamingResponse:
    """
    Purpose:
        Open an SSE stream for the currently active project.
        The client connects once; the server pushes events as state changes.
        Proxy log and status events are included when a ProxyManager is attached
        to app.state.
    Input:
        request — FastAPI Request (used to access app.state.proxy_manager).
        project — resolved active project (via Depends).
    Output:  StreamingResponse with media_type text/event-stream.
    Side effects:
        Holds an open HTTP connection for the life of the client connection.
        Subscribes to ProxyManager for the duration of the connection.
    """
    proxy_manager: ProxyManager | None = getattr(
        request.app.state, "proxy_manager", None
    )
    return StreamingResponse(
        _stream_events(project.db_path, project.id, proxy_manager),
        media_type="text/event-stream",
        headers={
            # Prevent any intermediate layer from buffering SSE frames.
            "Cache-Control": "no-cache",
            # Disable nginx proxy buffering when Talos is served behind a reverse proxy.
            "X-Accel-Buffering": "no",
        },
    )
