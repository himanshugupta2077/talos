"""
Module: talos.intruder.engine

Purpose:
    Intruder session execution engine for one time-slice segment (or full
    --right-now foreground run). Strategy loop + TimingController + httpx
    + batched SQLite commits + cooperative pause/cancel.

Dependencies: asyncio, httpx, time, uuid, json
Data flow:
    scheduler / CLI → run_session_segment → SegmentOutcome
Side effects:
    - Outbound HTTP
    - Writes intruder_results + session checkpoint/progress
    - Optional interesting flow rows (no error_intel/passive)
"""

from __future__ import annotations

import asyncio
import json
import logging
import random
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional
from urllib.parse import urlparse

import httpx

from talos.burp.outbound import prepare_send_headers
from talos.burp.trace import ENGINE_INTRUDER
from talos.intruder import db as intruder_db
from talos.intruder.config_schema import merge_defaults
from talos.intruder.findings_bridge import findings_config_from, maybe_promote_result
from talos.intruder.generators import build_generator
from talos.intruder.grep import evaluate_grep_rules, rules_to_pool
from talos.intruder.match import evaluate_match_rules
from talos.intruder.models import (
    CONTROL_CANCEL,
    CONTROL_PAUSE,
    DEFAULT_AUTH_FAIL_THRESHOLD,
    DEFAULT_MAX_ATTEMPTS,
    DEFAULT_MAX_CONCURRENCY,
    DEFAULT_MAX_DURATION_S,
    DEFAULT_MAX_RESULTS,
    DEFAULT_POOL_MAX_VALUES,
    DEFAULT_RPS,
    DEFAULT_SLICE_MAX_ATTEMPTS,
    DEFAULT_SLICE_MAX_WALL_S,
    DEFAULT_TIMEOUT_S,
    RESULT_BATCH_FLUSH_S,
    RESULT_BATCH_SIZE,
    CONTROL_FLAG_CACHE_S,
    STORAGE_ALL_FLOWS,
    STORAGE_METRICS_ONLY,
    STORAGE_SAMPLE_FLOWS,
    AttemptResult,
    SegmentOutcome,
    STATUS_CANCELLED,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_PAUSED,
    STATUS_RUNNING,
)
from talos.intruder.results import attempt_result_to_row, build_metrics_from_response
from talos.intruder.strategies import build_strategy
from talos.intruder.template import baseline_from_config, render_attempt, variables_from_config
from talos.intruder.timing import TimingController
from talos.projects.proxy_config import get_upstream_url
from talos.scheduler.db import (
    SCHED_STATE_PAUSED,
    SCHED_STATE_WAITING_FOR_SESSION,
    get_scheduler_state,
)

_log = logging.getLogger(__name__)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _build_strategy_from_config(
    cfg: dict[str, Any],
    *,
    force: bool = False,
    db_path: Optional[Path] = None,
    project_id: Optional[str] = None,
):
    payload_sets_cfg = cfg.get("payload_sets") or {}
    generators = {}
    processors_map: dict[str, list[str]] = {}
    sess_block = cfg.get("session") or {}
    pid = project_id or sess_block.get("project_id")
    for name, pset in payload_sets_cfg.items():
        opts = dict(pset.get("options") or {})
        if force:
            opts["force"] = True
        if db_path is not None:
            opts.setdefault("db_path", str(db_path))
        if pid is not None:
            opts.setdefault("project_id", pid)
        generators[name] = build_generator(str(pset.get("generator")), opts)
        processors_map[name] = list(pset.get("processors") or [])

    strategy_cfg = cfg.get("strategy") or {}
    stype = str(strategy_cfg.get("type") or "single").lower()
    if stype == "cartesian":
        stype = "cluster_bomb"
    opts = dict(strategy_cfg.get("options") or {})
    opts["processors"] = processors_map
    variables = variables_from_config(cfg)
    injectable = [v.name for v in variables if not v.is_fixed()]
    # Sniper targets default to injectable
    if stype == "sniper" and not opts.get("targets"):
        opts["targets"] = injectable
    # Multi-set default ordered sets
    if stype in ("pitchfork", "zip", "cluster_bomb") and not opts.get("sets"):
        matched = [v for v in injectable if v in generators]
        opts["sets"] = matched if matched else list(generators.keys())
    return build_strategy(stype, injectable or [v.name for v in variables], generators, options=opts)


async def run_session_segment(
    session_id: str,
    db_path: Path,
    project_id: str,
    *,
    job_id: Optional[str] = None,
    should_stop: Optional[Callable[[], bool]] = None,
    force: bool = False,
) -> SegmentOutcome:
    """
    Execute one segment of an Intruder session (time-sliced or full foreground).

    Cooperative checks each attempt boundary:
      control_flag, scheduler_state, should_stop, slice budget, hard caps.
    """
    session = intruder_db.get_session(db_path, session_id)
    if session is None:
        return SegmentOutcome(
            reason="failed",
            attempts_this_segment=0,
            session_status=STATUS_FAILED,
            error="session_not_found",
        )

    cfg = merge_defaults(session.get("config") or {})
    safety = cfg.get("safety") or {}
    timing_cfg = cfg.get("timing") or {}
    slice_cfg = cfg.get("slice") or {}
    storage = cfg.get("storage") or {}
    match_rules = list(cfg.get("match") or [])
    grep_rules = list(cfg.get("grep") or [])

    max_attempts = int(safety.get("max_attempts", DEFAULT_MAX_ATTEMPTS))
    max_duration_s = float(safety.get("max_duration_s", DEFAULT_MAX_DURATION_S))
    max_results = int(storage.get("max_results", DEFAULT_MAX_RESULTS))
    auth_fail_threshold = int(safety.get("auth_fail_threshold", DEFAULT_AUTH_FAIL_THRESHOLD))
    slice_max_attempts = int(slice_cfg.get("max_attempts", DEFAULT_SLICE_MAX_ATTEMPTS))
    slice_max_wall_s = float(slice_cfg.get("max_wall_s", DEFAULT_SLICE_MAX_WALL_S))
    timeout_s = float(timing_cfg.get("timeout_s", DEFAULT_TIMEOUT_S))
    storage_mode = str(storage.get("mode") or STORAGE_METRICS_ONLY).lower()
    sample_rate = float(storage.get("sample_rate") or 0.0)
    store_interesting = bool(storage.get("store_interesting_bodies", True))
    max_body_bytes = int(storage.get("max_body_bytes", 65536))
    skip_auth = bool(safety.get("skip_auth_artifacts", False))
    per_host_cap = timing_cfg.get("max_concurrency_per_host")
    if per_host_cap is not None and per_host_cap != "":
        try:
            per_host_cap = int(per_host_cap)
        except (TypeError, ValueError):
            per_host_cap = None
    else:
        per_host_cap = None

    progress = dict(session.get("progress") or {})
    checkpoint = dict(session.get("checkpoint") or {})
    active_duration_s = float(progress.get("active_duration_s") or 0.0)
    sent = int(progress.get("sent") or 0)
    matched = int(progress.get("matched") or 0)
    errors = int(progress.get("errors") or 0)
    consecutive_auth_fail = int(progress.get("consecutive_auth_fail") or 0)
    findings_promoted = int(progress.get("findings_promoted") or 0)
    fcfg = findings_config_from(cfg)
    # Phase 3: batch pool writes per segment flush
    pool_buffer: dict[str, list[str]] = {}

    # Restore strategy from checkpoint
    try:
        strategy = _build_strategy_from_config(
            cfg, force=force, db_path=db_path, project_id=project_id
        )
    except Exception as exc:  # noqa: BLE001
        _log.error("Intruder strategy build failed: %s", exc)
        intruder_db.update_session(
            db_path,
            session_id,
            status=STATUS_FAILED,
            failure_reason=str(exc),
            finished_at=_now_iso(),
        )
        return SegmentOutcome(
            reason="failed",
            attempts_this_segment=0,
            session_status=STATUS_FAILED,
            error=str(exc),
        )

    if checkpoint.get("strategy"):
        try:
            strategy.restore(checkpoint["strategy"])
        except Exception:  # noqa: BLE001
            _log.warning("Strategy restore failed; continuing from current cursor")

    next_index = int(checkpoint.get("attempt_index", -1)) + 1

    baseline = baseline_from_config(cfg)
    variables = variables_from_config(cfg)
    normalized_path = str((cfg.get("template") or {}).get("normalized_path") or "")
    baseline_fp = (progress.get("baseline_fingerprint") or {})
    if not baseline_fp and session.get("base_flow_id"):
        flow = intruder_db.load_flow(db_path, session["base_flow_id"])
        if flow:
            from talos.input_validation.fingerprint import fingerprint_from_flow
            baseline_fp = fingerprint_from_flow(flow).to_dict()
            progress["baseline_fingerprint"] = baseline_fp

    timing = TimingController(
        mode=str(timing_cfg.get("mode") or "fixed"),
        rps=float(timing_cfg.get("rps", DEFAULT_RPS)),
        max_concurrency=int(timing_cfg.get("max_concurrency", DEFAULT_MAX_CONCURRENCY)),
        max_concurrency_per_host=per_host_cap,
        jitter_ms=float(timing_cfg.get("jitter_ms") or 0),
        burst_size=int(timing_cfg.get("burst_size") or 1),
        min_rps=float(timing_cfg.get("min_rps") or 0.25),
        max_rps=(
            float(timing_cfg["max_rps"])
            if timing_cfg.get("max_rps") is not None
            else None
        ),
        slow_ms=float(timing_cfg.get("slow_ms") or 2000.0),
        adaptive_window=int(timing_cfg.get("adaptive_window") or 10),
        up_factor=float(timing_cfg.get("up_factor") or 1.1),
        down_factor=float(timing_cfg.get("down_factor") or 0.5),
        error_statuses=timing_cfg.get("error_statuses"),
    )

    # Mark running
    intruder_db.update_session(
        db_path,
        session_id,
        status=STATUS_RUNNING,
        job_id=job_id if job_id is not None else session.get("job_id"),
        started_at=session.get("started_at") or _now_iso(),
        finished_at=None,
    )

    segment_start = time.monotonic()
    segment_attempts = 0
    buffer: list[dict[str, Any]] = []
    last_flush = time.monotonic()
    last_control_read = 0.0
    cached_control: Optional[str] = None
    stop_reason: Optional[str] = None
    session_status = STATUS_RUNNING
    outcome_reason = "completed"

    proxy_url = get_upstream_url(db_path)
    timeout = httpx.Timeout(timeout_s)
    limits = httpx.Limits(
        max_connections=max(4, timing.max_concurrency * 2),
        max_keepalive_connections=max(2, timing.max_concurrency),
    )

    async def _read_control() -> Optional[str]:
        nonlocal last_control_read, cached_control
        now = time.monotonic()
        if now - last_control_read < CONTROL_FLAG_CACHE_S and cached_control is not None:
            return cached_control
        sess = intruder_db.get_session(db_path, session_id)
        cached_control = (sess or {}).get("control_flag")
        last_control_read = now
        return cached_control

    def _flush(final_status: Optional[str] = None) -> None:
        nonlocal buffer, last_flush, checkpoint, progress
        ck = {
            "attempt_index": next_index - 1 if next_index > 0 else checkpoint.get("attempt_index", -1),
            "strategy": strategy.checkpoint(),
            "segment_attempts": segment_attempts,
        }
        # Only update attempt_index when we have sent something this segment or prior.
        if next_index > 0:
            ck["attempt_index"] = next_index - 1
        strat_prog = strategy.progress()
        progress.update({
            "sent": sent,
            "matched": matched,
            "errors": errors,
            "attempt_index": ck["attempt_index"],
            "estimate_total": strat_prog.get("total_estimate") or progress.get("estimate_total"),
            "percent": strat_prog.get("percent"),
            "rps_ema": timing.rps_ema,
            "effective_rps": timing.effective_rps,
            "timing": timing.snapshot(),
            "active_duration_s": active_duration_s + (time.monotonic() - segment_start),
            "consecutive_auth_fail": consecutive_auth_fail,
            "findings_promoted": findings_promoted,
            "updated_at": _now_iso(),
            "baseline_fingerprint": baseline_fp,
        })
        if stop_reason:
            progress["stopped_reason"] = stop_reason
        checkpoint = ck
        rows = list(buffer)
        buffer = []
        last_flush = time.monotonic()
        # Flush extracted pools before/with results batch
        if pool_buffer:
            for pool_name, vals in pool_buffer.items():
                if not vals:
                    continue
                try:
                    intruder_db.upsert_pool_values(
                        db_path,
                        project_id,
                        pool_name,
                        vals,
                        session_id=session_id,
                        source_rule=pool_name,
                        max_values=DEFAULT_POOL_MAX_VALUES,
                    )
                except Exception:  # noqa: BLE001
                    _log.exception("Failed to upsert pool %s", pool_name)
            pool_buffer.clear()
        intruder_db.insert_results_batch(
            db_path,
            session_id,
            rows,
            checkpoint=checkpoint,
            progress=progress,
            status=final_status,
        )

    def _should_store_flow(result: AttemptResult) -> bool:
        """
        Decide whether to write a flows row for this attempt.

        modes:
          metrics_only  — only interesting (match-tagged) when store_interesting_bodies
          sample_flows  — interesting OR Bernoulli(sample_rate)
          all_flows     — every successful attempt
        """
        if not result.success:
            return False
        if storage_mode == STORAGE_ALL_FLOWS:
            return True
        if storage_mode == STORAGE_SAMPLE_FLOWS:
            if result.interesting and store_interesting:
                return True
            if sample_rate > 0.0 and random.random() < sample_rate:
                return True
            return False
        # metrics_only (default)
        return bool(store_interesting and result.interesting)

    async def _maybe_store_flow(result: AttemptResult, spec) -> Optional[str]:
        if not _should_store_flow(result):
            return None
        body = result.response_body or b""
        if len(body) > max_body_bytes:
            body = body[:max_body_bytes]
            truncated = True
        else:
            truncated = False
        flow_id = str(uuid.uuid4())
        parsed = urlparse(spec.url)
        role_id = baseline.get("role_id")
        module_id = baseline.get("module_id")
        if not role_id or not module_id:
            # Load from base flow
            bf = intruder_db.load_flow(db_path, session.get("base_flow_id") or "")
            if bf:
                role_id = role_id or bf.get("role_id")
                module_id = module_id or bf.get("module_id")
        if not role_id or not module_id:
            return None
        content_type = ""
        for k, v in (result.response_headers or {}).items():
            if k.lower() == "content-type":
                content_type = v
                break
        flow = {
            "id": flow_id,
            "project_id": project_id,
            "captured_at": _now_iso(),
            "response_end": _now_iso(),
            "method": spec.method,
            "url": spec.url,
            "host": parsed.netloc or parsed.hostname or "",
            "path": parsed.path or "/",
            "query": parsed.query or "",
            "request_headers": spec.headers,
            "request_cookies": {},
            "request_body": spec.body,
            "request_body_truncated": False,
            "status_code": result.status_code,
            "response_headers": result.response_headers or {},
            "response_body": body,
            "response_body_truncated": truncated,
            "content_type": content_type,
            "endpoint_id": session.get("endpoint_id") or baseline.get("endpoint_id"),
            "role_id": role_id,
            "module_id": module_id,
            "original_flow_id": session.get("base_flow_id"),
            "replay_error": None,
            "flow_meta": {
                "generated_by": "intruder",
                "session_id": session_id,
                "attempt_index": result.attempt_index,
                "variables": result.variables,
                "storage_mode": storage_mode,
            },
        }
        try:
            intruder_db.insert_intruder_flow(db_path, flow)
            return flow_id
        except Exception as exc:  # noqa: BLE001
            _log.debug("Intruder flow insert failed: %s", exc)
            return None

    try:
        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=False,
            proxy=proxy_url,
            limits=limits,
        ) as client:
            while True:
                # Cooperative checks
                control = await _read_control()
                if control == CONTROL_CANCEL:
                    stop_reason = "cancelled"
                    outcome_reason = "cancelled"
                    session_status = STATUS_CANCELLED
                    break
                if control == CONTROL_PAUSE:
                    stop_reason = "paused"
                    outcome_reason = "paused"
                    session_status = STATUS_PAUSED
                    break

                try:
                    state_val = get_scheduler_state(db_path)
                except Exception:  # noqa: BLE001
                    state_val = None
                if state_val in (SCHED_STATE_PAUSED, SCHED_STATE_WAITING_FOR_SESSION):
                    stop_reason = "scheduler_pause"
                    outcome_reason = "paused"
                    session_status = STATUS_PAUSED
                    break

                if should_stop and should_stop():
                    stop_reason = "process_stop"
                    outcome_reason = "process_stop"
                    session_status = STATUS_PAUSED
                    break

                # Slice budget
                elapsed_seg = time.monotonic() - segment_start
                if segment_attempts >= slice_max_attempts or elapsed_seg >= slice_max_wall_s:
                    stop_reason = "slice"
                    outcome_reason = "continue"
                    session_status = STATUS_RUNNING
                    break

                # Hard caps (active duration)
                if sent >= max_attempts:
                    stop_reason = "max_attempts"
                    outcome_reason = "completed"
                    session_status = STATUS_COMPLETED
                    break
                if active_duration_s + elapsed_seg >= max_duration_s:
                    stop_reason = "max_duration"
                    outcome_reason = "completed"
                    session_status = STATUS_COMPLETED
                    break
                if sent >= max_results:
                    stop_reason = "max_results"
                    outcome_reason = "completed"
                    session_status = STATUS_COMPLETED
                    break
                if consecutive_auth_fail >= auth_fail_threshold:
                    stop_reason = "auth_failures"
                    outcome_reason = "completed"
                    session_status = STATUS_COMPLETED
                    break

                # Next payload
                bindings = strategy.next()
                if bindings is None:
                    stop_reason = "exhausted"
                    outcome_reason = "completed"
                    session_status = STATUS_COMPLETED
                    break

                attempt_index = next_index
                next_index += 1
                segment_attempts += 1

                try:
                    spec = render_attempt(
                        baseline,
                        variables,
                        bindings,
                        attempt_index=attempt_index,
                        normalized_path=normalized_path,
                        skip_auth_artifacts=skip_auth,
                    )
                except Exception as exc:  # noqa: BLE001
                    result = AttemptResult(
                        attempt_index=attempt_index,
                        variables=bindings,
                        status_code=None,
                        success=False,
                        failure_reason=f"render_error:{exc}",
                        duration_ms=None,
                    )
                    errors += 1
                    sent += 1
                    buffer.append(attempt_result_to_row(result))
                    continue

                request_host = urlparse(spec.url).netloc or urlparse(spec.url).hostname or ""
                await timing.acquire(host=request_host)
                t0 = time.monotonic()
                status_code = None
                success = False
                failure_reason = None
                resp_body = b""
                resp_headers: dict[str, str] = {}
                burp_meta: dict | None = None
                try:
                    var_bits: list[str] = []
                    if isinstance(bindings, dict):
                        for key, value in list(bindings.items())[:4]:
                            var_bits.append(f"{key}={value}")
                    parsed_url = urlparse(spec.url)
                    send_headers, burp_meta = prepare_send_headers(
                        dict(spec.headers),
                        db_path=db_path,
                        engine=ENGINE_INTRUDER,
                        flow={
                            "method": spec.method,
                            "path": parsed_url.path or "/",
                            "normalized_path": normalized_path or parsed_url.path or "/",
                            "host": request_host,
                            "url": spec.url,
                            "project_id": project_id,
                            "endpoint_id": session.get("endpoint_id")
                            or baseline.get("endpoint_id"),
                        },
                        extras={
                            "technique": "intruder",
                            "attempt": str(attempt_index),
                            "variant": ", ".join(var_bits),
                        },
                        endpoint_id=str(
                            session.get("endpoint_id")
                            or baseline.get("endpoint_id")
                            or ""
                        ),
                        host=request_host,
                    )
                    resp = await client.request(
                        method=spec.method,
                        url=spec.url,
                        headers=send_headers,
                        content=spec.body,
                    )
                    status_code = resp.status_code
                    resp_body = resp.content or b""
                    resp_headers = {k: v for k, v in resp.headers.items()}
                    success = True
                    from talos.burp.snapshot import record_send_response

                    record_send_response(burp_meta, project_id, resp)
                except httpx.TimeoutException:
                    failure_reason = "timeout"
                except httpx.HTTPError as exc:
                    failure_reason = f"http_error:{type(exc).__name__}"
                except Exception as exc:  # noqa: BLE001
                    failure_reason = f"error:{exc}"
                finally:
                    timing.release(host=request_host)
                if failure_reason:
                    from talos.burp.snapshot import record_send_failure

                    record_send_failure(burp_meta, project_id, failure_reason)

                duration_ms = (time.monotonic() - t0) * 1000.0
                metrics = build_metrics_from_response(
                    status_code=status_code,
                    response_headers=resp_headers,
                    response_body=resp_body if success else None,
                    duration_ms=duration_ms,
                    variables=bindings,
                )
                tags = evaluate_match_rules(
                    metrics,
                    match_rules,
                    baseline={"body_length": baseline_fp.get("body_length"), "fingerprint": baseline_fp},
                )
                grepped: dict[str, list[str]] = {}
                grep_tags: list[str] = []
                if grep_rules and success:
                    grepped, grep_tags = evaluate_grep_rules(
                        metrics,
                        grep_rules,
                        response_headers=resp_headers,
                    )
                    for pool_name, vals in rules_to_pool(grepped, grep_rules).items():
                        bucket = pool_buffer.setdefault(pool_name, [])
                        for v in vals:
                            if v not in bucket:
                                bucket.append(v)
                all_tags = list(tags) + [f"grep:{t}" for t in grep_tags]
                interesting = bool(tags) if match_rules else False
                if grep_tags:
                    interesting = True
                # Without match rules, never mark interesting for body storage
                # unless store_interesting and operator added rules (or grep tag_interesting).

                result = AttemptResult(
                    attempt_index=attempt_index,
                    variables=bindings,
                    status_code=status_code,
                    success=success,
                    failure_reason=failure_reason,
                    duration_ms=duration_ms,
                    metrics={k: v for k, v in metrics.items() if k != "body_text"},
                    match_tags=all_tags,
                    grepped=grepped,
                    interesting=interesting,
                    body_length=metrics.get("body_length"),
                    word_count=metrics.get("word_count"),
                    line_count=metrics.get("line_count"),
                    body_hash=metrics.get("body_hash"),
                    fingerprint=metrics.get("fingerprint") or {},
                    response_body=resp_body if success else None,
                    response_headers=resp_headers,
                )
                timing.note_response(result)

                if success and status_code in (401, 403):
                    consecutive_auth_fail += 1
                elif success:
                    consecutive_auth_fail = 0

                if not success:
                    errors += 1
                if interesting:
                    matched += 1
                # Storage modes may store non-interesting rows (sample/all)
                fid = await _maybe_store_flow(result, spec)
                if fid:
                    result.flow_id = fid

                # Phase 5: optional findings promote (fail-soft, capped)
                row = attempt_result_to_row(result)
                row["id"] = str(uuid.uuid4())
                if fcfg.get("promote") and (interesting or row.get("match_tags")):
                    try:
                        finding_id, findings_promoted = maybe_promote_result(
                            db_path,
                            project_id,
                            session,
                            row,
                            fcfg=fcfg,
                            findings_promoted=findings_promoted,
                            job_id=job_id,
                        )
                        if finding_id:
                            row["finding_id"] = finding_id
                            result.finding_id = finding_id
                    except Exception as exc:  # noqa: BLE001
                        _log.debug("Intruder findings promote skipped: %s", exc)

                sent += 1
                buffer.append(row)

                if (
                    len(buffer) >= RESULT_BATCH_SIZE
                    or (time.monotonic() - last_flush) >= RESULT_BATCH_FLUSH_S
                ):
                    _flush()

    except Exception as exc:  # noqa: BLE001
        _log.exception("Intruder segment failed: %s", exc)
        stop_reason = f"failed:{exc}"
        outcome_reason = "failed"
        session_status = STATUS_FAILED
        try:
            _flush(final_status=STATUS_FAILED)
        except Exception:  # noqa: BLE001
            pass
        intruder_db.update_session(
            db_path,
            session_id,
            status=STATUS_FAILED,
            failure_reason=str(exc),
            finished_at=_now_iso(),
            control_flag=None,
        )
        return SegmentOutcome(
            reason="failed",
            attempts_this_segment=segment_attempts,
            session_status=STATUS_FAILED,
            error=str(exc),
        )

    # Final flush + status
    segment_wall = time.monotonic() - segment_start
    active_duration_s = active_duration_s + segment_wall
    progress["active_duration_s"] = active_duration_s
    if stop_reason:
        progress["stopped_reason"] = stop_reason

    finished = None
    clear_control = None
    if session_status in (STATUS_COMPLETED, STATUS_CANCELLED, STATUS_FAILED):
        finished = _now_iso()
        clear_control = None
    elif session_status == STATUS_PAUSED:
        clear_control = None
        # clear control_flag after pause settlement
        clear_control = None

    _flush(final_status=session_status if session_status != STATUS_RUNNING else None)

    # Update terminal fields
    kwargs: dict[str, Any] = {
        "status": session_status,
        "progress": progress,
        "checkpoint": checkpoint,
        "control_flag": None,
    }
    if finished:
        kwargs["finished_at"] = finished
    if session_status == STATUS_RUNNING and outcome_reason == "continue":
        # Stay running; job_id updated by scheduler when continuation enqueued
        pass
    if session_status in (STATUS_PAUSED, STATUS_COMPLETED, STATUS_CANCELLED, STATUS_FAILED):
        kwargs["job_id"] = None
    if session_status == STATUS_FAILED and stop_reason:
        kwargs["failure_reason"] = stop_reason

    intruder_db.update_session(db_path, session_id, **kwargs)

    # Map process_stop to paused reason for scheduler
    reason = outcome_reason
    if reason == "process_stop":
        reason = "paused"

    return SegmentOutcome(
        reason=reason if reason != "slice" else "continue",
        attempts_this_segment=segment_attempts,
        session_status=session_status,
        error=None,
    )
