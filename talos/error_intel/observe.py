"""
Module: talos.error_intel.observe

Purpose:
    Public entrypoint for Error Intelligence.

    Attack modules, IV, BAC, Unauth, replay, and FlowWorker must **not**
    parse error bodies themselves.  They call observe_error(...) or
    maybe_enqueue_error_scan(flow_id=...) after the flow is committed.

    Production path prefers enqueue-by-flow_id so callers never pass
    multi-MB bodies twice — the worker reloads flows.response_body.

Phase status:
    Phase 6+ — observe_error can enqueue or process inline; returns
               ErrorObservation list when storage succeeds.
    attach_error_context enriches observations / pending context.

Dependencies:
    pathlib, typing
    talos.error_intel.{candidate, config, db, models, worker helpers}
Data flow:
    caller context → gate → enqueue or process_error_scan_job → observations
Side effects:
    May enqueue ErrorIntelJob; may write error_clusters / observations.
    Never raises on gate/config/scan failure (returns []).
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Optional, Union

from talos.error_intel.candidate import is_error_candidate
from talos.error_intel.config import ErrorIntelConfig, default_config, header_names_for_gate
from talos.error_intel.constants import (
    ATTACK_TYPE_UNKNOWN,
    DEFAULT_PAYLOAD_REDACTED_MAX,
)
from talos.error_intel import db as error_db
from talos.error_intel.models import ErrorIntelJob, ErrorObservation
from talos.error_intel.queue import ErrorIntelQueue
from talos.error_intel.redact import redact_payload

logger = logging.getLogger(__name__)


def observe_error(
    *,
    project_id: str,
    flow_id: str,
    response_status: Optional[int] = None,
    response_headers: Optional[Any] = None,
    response_body: Optional[Union[str, bytes]] = None,
    endpoint_id: Optional[str] = None,
    parameter_uuid: Optional[str] = None,
    parameter_name: Optional[str] = None,
    attack_type: Optional[str] = None,
    payload: Optional[str] = None,
    duration_ms: Optional[float] = None,
    content_type: Optional[str] = None,
    path: Optional[str] = None,
    config: Optional[ErrorIntelConfig] = None,
    enqueue_only: bool = False,
    error_queue: Optional[ErrorIntelQueue] = None,
    db_path: Optional[Union[str, Path]] = None,
    url: str = "",
    host: str = "",
    force: bool = False,
) -> list[ErrorObservation]:
    """
    Purpose:
        Observe a response for error intelligence.  Callers supply flow
        identity and optional attack context; they must not reimplement
        stack/DB classifiers.

    Contract (locked):
        - Passive only — no extra HTTP.
        - Intelligence first — no Findings created here (v1).
        - Prefer flow_id + body on DB; response_body is optional when the
          worker path loads from flows.
        - Non-fatal for callers — never raises on gate/config/scan miss.

    Behaviour (Phase 6+):
        1. Respect config.enabled (default True).
        2. Run is_error_candidate on the supplied signals (body optional
           when enqueue_only / db_path so worker can load later).
        3. If enqueue_only and error_queue: put ErrorIntelJob, return [].
        4. Else if db_path: process_error_scan_job (reload body from DB)
           and return [observation] when stored.
        5. Else if response_body provided and db_path missing: cannot
           store without DB — return [] (callers should pass db_path).
        6. When the gate rejects, return [].

    Input:
        project_id / flow_id — required identity
        response_status / response_headers / response_body — optional
            signals for the gate (body may be omitted when enqueue_only)
        endpoint_id / parameter_* / attack_type / payload / duration_ms —
            observation context (stored on sightings, not fingerprint)
        content_type / path — gate aids
        config — ErrorIntelConfig; None → defaults (or DB config when db_path)
        enqueue_only — when True with error_queue, only enqueue by flow_id
        error_queue — optional ErrorIntelQueue for async path
        db_path — project talos.db for store / worker reload
        force — re-scan even if observations already exist for flow_id

    Output:
        list[ErrorObservation] — zero or one observation for this call
        (enqueue_only always returns []).

    Side effects:
        May enqueue; may write error_clusters / error_observations.
        Never blocks capture on failure.
    """
    if not project_id or not flow_id:
        return []

    try:
        cfg = config
        if cfg is None and db_path is not None:
            try:
                cfg = error_db.get_config(Path(db_path))
            except Exception:
                cfg = default_config()
        if cfg is None:
            cfg = default_config()
        if not cfg.enabled:
            return []

        # When body is omitted, gate still allows 4xx/5xx / error headers so
        # enqueue path can load the body from DB.
        if not is_error_candidate(
            status_code=response_status,
            content_type=content_type,
            headers=response_headers,
            body=response_body,
            path=path,
            error_header_names=header_names_for_gate(cfg),
            gate_sniff_bytes=cfg.gate_sniff_bytes,
        ):
            return []

        payload_redacted = None
        if payload is not None:
            payload_redacted = redact_payload(
                payload, max_len=DEFAULT_PAYLOAD_REDACTED_MAX
            )

        job = ErrorIntelJob(
            project_id=project_id,
            flow_id=flow_id,
            endpoint_id=endpoint_id,
            url=url or "",
            host=host or "",
            path=path or "",
            content_type=content_type or "",
            status_code=response_status,
            truncated=False,
            attack_type=attack_type or ATTACK_TYPE_UNKNOWN,
            parameter_uuid=parameter_uuid,
            parameter_name=parameter_name,
            payload_redacted=payload_redacted,
            duration_ms=duration_ms,
            observed_at="",
        )

        # Async path: enqueue and return (worker will store).
        if enqueue_only and error_queue is not None:
            error_queue.put(job)
            return []

        if error_queue is not None and enqueue_only is False and db_path is None:
            # Prefer enqueue when queue available without db_path for inline.
            error_queue.put(job)
            return []

        if db_path is None:
            # Cannot persist without a database path.
            logger.debug(
                "observe_error: no db_path — gate passed but nothing stored "
                "(flow_id=%s)",
                flow_id,
            )
            return []

        from talos.error_intel.worker import (
            persist_error_context_to_flow_meta,
            process_error_scan_job,
            set_pending_error_context,
        )

        # Ensure attack context is available even if flow_meta is sparse
        # (process-local + durable flow_meta for multi-process workers).
        if parameter_uuid or parameter_name or attack_type or payload is not None:
            set_pending_error_context(
                flow_id,
                parameter_uuid=parameter_uuid,
                parameter_name=parameter_name,
                attack_type=attack_type,
                payload=payload,
            )
            try:
                persist_error_context_to_flow_meta(
                    Path(db_path),
                    flow_id,
                    parameter_uuid=parameter_uuid,
                    parameter_name=parameter_name,
                    attack_type=attack_type,
                    payload=payload,
                )
            except Exception:
                logger.debug(
                    "observe_error: flow_meta persist failed — flow_id=%s",
                    flow_id,
                    exc_info=True,
                )

        if enqueue_only and error_queue is not None:
            error_queue.put(job)
            return []

        if error_queue is not None and not force:
            error_queue.put(job)
            return []

        result = process_error_scan_job(
            db_path=Path(db_path),
            job=job,
            force=force,
            config=cfg,
        )
        if not result or not result.get("stored"):
            return []
        obs = result.get("observation")
        if isinstance(obs, ErrorObservation):
            return [obs]
        # Fallback: re-list by flow
        return error_db.list_observations(
            Path(db_path), flow_id=flow_id, limit=1
        )
    except Exception:
        logger.exception(
            "observe_error failed — flow_id=%s — caller unaffected",
            flow_id,
        )
        return []


def attach_error_context(
    *,
    project_id: str,
    flow_id: str,
    parameter_uuid: Optional[str] = None,
    parameter_name: Optional[str] = None,
    attack_type: Optional[str] = None,
    payload: Optional[str] = None,
    db_path: Optional[Union[str, Path]] = None,
) -> bool:
    """
    Purpose:
        Contextual enrich API for attack engines (Phase 6 dual-path).

        Automatic scan covers the body via flow commit; this call attaches
        parameter / attack_type / payload linkage to the observation for
        that flow without re-parsing the body.

    Behaviour:
        1. Validate identity.
        2. Always store pending process-local context for the worker.
        3. When db_path is provided:
             - persist context onto flows.flow_meta.error_intel (cross-process)
             - UPDATE existing observations for flow_id (fills empty fields only)

    Input:
        project_id / flow_id — required
        parameter_uuid / parameter_name / attack_type / payload — context
        db_path — optional project DB for immediate observation update +
            flow_meta persistence (BUG-13)

    Output:
        True when context was recorded (pending and/or DB update);
        False on identity failure.

    Side effects:
        Process-local pending map; optional UPDATE error_observations +
        flows.flow_meta.
    """
    if not project_id or not flow_id:
        return False
    try:
        from talos.error_intel.worker import (
            persist_error_context_to_flow_meta,
            set_pending_error_context,
        )

        set_pending_error_context(
            flow_id,
            parameter_uuid=parameter_uuid,
            parameter_name=parameter_name,
            attack_type=attack_type,
            payload=payload,
        )
        if db_path is not None:
            path = Path(db_path)
            # Durable source of truth across process boundaries (BUG-13).
            persist_error_context_to_flow_meta(
                path,
                flow_id,
                parameter_uuid=parameter_uuid,
                parameter_name=parameter_name,
                attack_type=attack_type,
                payload=payload,
            )
            payload_redacted = None
            if payload is not None:
                payload_redacted = redact_payload(
                    payload, max_len=DEFAULT_PAYLOAD_REDACTED_MAX
                )
            error_db.update_observations_context(
                path,
                flow_id,
                parameter_uuid=parameter_uuid,
                parameter_name=parameter_name,
                attack_type=attack_type,
                payload_redacted=payload_redacted,
            )
        return True
    except Exception:
        logger.exception(
            "attach_error_context failed — flow_id=%s",
            flow_id,
        )
        return False
