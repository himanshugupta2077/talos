"""
Project dashboard aggregate reads.

Assembles a single JSON snapshot for the Control Panel mission dashboard.
Ownership: read-only composition over SQLite, endpoint_reads, proxy CLI status,
HTTP rules list, and effective config. Mutations remain on their own pages.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import cli, config, db, endpoint_reads

_SUSPICION_THRESHOLD = 3

_EMPTY_FINDINGS = {
    "by_status": {
        "TRIAGING": 0,
        "CONFIRMED": 0,
        "REJECTED": 0,
        "DUPLICATE": 0,
    },
    "by_attack_type": [],
    "groups_open": 0,
    "recent_triaging": [],
}

_EMPTY_SCHEDULER = {
    "state": None,
    "counts": {},
    "config": None,
    "active_queue": 0,
    "queue_fill_pct": 0,
    "recent_failed": [],
    "by_job_type_active": [],
}

_EMPTY_FLOWS = {
    "total": 0,
    "by_source": {},
    "by_status_class": {"2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0, "other": 0},
    "distinct_hosts": 0,
    "distinct_methods": 0,
    "last_captured_at": None,
}

_EMPTY_ENDPOINTS = {
    "inventory": {
        "total": 0,
        "testable": 0,
        "excluded": 0,
        "dangerous": 0,
        "logout": 0,
        "unqualified": 0,
    },
    "policy": {
        "by_priority": {"CRITICAL": 0, "HIGH": 0, "NORMAL": 0, "LOW": 0},
        "manual_overrides": 0,
        "rule_controlled": 0,
        "auto_controlled": 0,
        "total": 0,
    },
    "coverage": {
        "qualified_pct": 0,
        "baseline_pct": 0,
        "multi_role_pct": 0,
        "params_pct": 0,
        "excluded_pct": 0,
    },
}

_EMPTY_HTTP = {
    "enabled": True,
    "summary": {
        "active": 0,
        "request": 0,
        "response": 0,
        "disabled": 0,
        "total": 0,
    },
}


def _parse_dt(value: str | None) -> datetime | None:
    if value is None:
        return None
    s = str(value).strip()
    if not s:
        return None
    s = s.replace("Z", "+00:00")
    if s.endswith(" UTC"):
        s = s[:-4].rstrip() + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _default_constraints() -> dict[str, Any]:
    return {
        "capture_in_scope_only": True,
        "store_bodies": True,
        "max_body_size": 1 * 1024 * 1024,
    }


def _last_json_from_steps(results) -> dict:
    if not results:
        return {}
    last = results[-1]
    text = getattr(last, "stdout", None) or ""
    if not text.strip():
        if isinstance(last, dict):
            text = last.get("stdout") or ""
        else:
            d = last.to_dict() if hasattr(last, "to_dict") else {}
            text = d.get("stdout") or ""
    try:
        data = json.loads(text)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _parse_json_stdout(stdout: str) -> Any:
    text = (stdout or "").strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


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


def _section_summaries(values: dict[str, Any], sources: dict[str, str]) -> list[dict]:
    cards: list[dict] = []
    up_enabled = values.get("proxy.upstream.enabled", False)
    up_url = values.get("proxy.upstream.url")
    cards.append(
        {
            "section": "proxy",
            "label": "Proxy",
            "summary": (
                f"Upstream · {up_url}" if up_enabled and up_url else "Direct"
            ),
            "source": _dominant_source(sources, "proxy"),
        }
    )
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
            "summary": f"Bodies {'on' if store else 'off'} · {size_label}",
            "source": _dominant_source(sources, "capture"),
        }
    )
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
    auto = values.get("attack.unauth_auto_run", False)
    cards.append(
        {
            "section": "attack",
            "label": "Attack",
            "summary": f"Unauth auto-run {'on' if auto else 'off'}",
            "source": _dominant_source(sources, "attack"),
        }
    )
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
    return cards


def _findings_block(db_path: Path, project_id: str) -> dict[str, Any]:
    by_status = dict(_EMPTY_FINDINGS["by_status"])
    if not db.db_exists(db_path):
        return dict(_EMPTY_FINDINGS)

    for row in db.query_all(
        db_path,
        "SELECT status, COUNT(*) AS n FROM findings "
        "WHERE project_id=? GROUP BY status",
        (project_id,),
    ):
        status = row.get("status") or ""
        by_status[status] = int(row.get("n") or 0)

    by_attack = [
        {"type": r.get("attack_type") or "unknown", "n": int(r.get("n") or 0)}
        for r in db.query_all(
            db_path,
            "SELECT attack_type, COUNT(*) AS n FROM findings "
            "WHERE project_id=? GROUP BY attack_type ORDER BY n DESC LIMIT 8",
            (project_id,),
        )
    ]

    groups_open = 0
    try:
        groups_open = int(
            db.scalar(
                db_path,
                "SELECT COUNT(*) FROM finding_groups WHERE project_id=?",
                (project_id,),
            )
            or 0
        )
    except Exception:
        groups_open = 0

    recent = db.query_all(
        db_path,
        "SELECT id, title, attack_type, verdict, status, created_at "
        "FROM findings WHERE project_id=? AND status='TRIAGING' "
        "ORDER BY created_at DESC LIMIT 5",
        (project_id,),
    )

    return {
        "by_status": by_status,
        "by_attack_type": by_attack,
        "groups_open": groups_open,
        "recent_triaging": recent,
    }


def _scheduler_block(db_path: Path) -> dict[str, Any]:
    if not db.db_exists(db_path):
        return dict(_EMPTY_SCHEDULER)

    try:
        counts_rows = db.query_all(
            db_path, "SELECT status, COUNT(*) AS n FROM scheduler_jobs GROUP BY status"
        )
        counts = {row["status"]: int(row["n"] or 0) for row in counts_rows}
        cfg = db.query_one(db_path, "SELECT * FROM scheduler_config")
        try:
            state = db.query_one(db_path, "SELECT * FROM scheduler_state")
        except Exception:
            state = None

        active = (
            int(counts.get("pending") or 0)
            + int(counts.get("running") or 0)
            + int(counts.get("paused") or 0)
        )
        max_q = 200
        if cfg and cfg.get("max_queue_size") is not None:
            try:
                max_q = int(cfg["max_queue_size"]) or 200
            except (TypeError, ValueError):
                max_q = 200
        fill = int(round(100 * active / max_q)) if max_q > 0 else 0
        fill = min(fill, 100)

        # PK is job_id (not id); timestamps are created_at / finished_at (no updated_at).
        recent_failed_rows = db.query_all(
            db_path,
            "SELECT job_id, job_type, status, failure_reason, priority, "
            "created_at, finished_at FROM scheduler_jobs "
            "WHERE status='failed' "
            "ORDER BY COALESCE(finished_at, created_at) DESC LIMIT 5",
        )
        recent_failed = [
            {
                "id": r.get("job_id"),
                "job_id": r.get("job_id"),
                "job_type": r.get("job_type"),
                "status": r.get("status"),
                "failure_reason": r.get("failure_reason"),
                "priority": r.get("priority"),
                "created_at": r.get("created_at"),
                "updated_at": r.get("finished_at") or r.get("created_at"),
                "finished_at": r.get("finished_at"),
            }
            for r in recent_failed_rows
        ]

        by_type = [
            {"job_type": r.get("job_type") or "unknown", "n": int(r.get("n") or 0)}
            for r in db.query_all(
                db_path,
                "SELECT job_type, COUNT(*) AS n FROM scheduler_jobs "
                "WHERE status IN ('pending','running','paused') "
                "GROUP BY job_type ORDER BY n DESC LIMIT 8",
            )
        ]

        return {
            "state": state,
            "counts": counts,
            "config": {
                "min_delay": (cfg or {}).get("min_delay"),
                "max_delay": (cfg or {}).get("max_delay"),
                "max_queue_size": max_q,
            }
            if cfg
            else {"min_delay": 2.0, "max_delay": 6.0, "max_queue_size": max_q},
            "active_queue": active,
            "queue_fill_pct": fill,
            "recent_failed": recent_failed,
            "by_job_type_active": by_type,
        }
    except Exception:
        return dict(_EMPTY_SCHEDULER)


def _flows_block(db_path: Path) -> dict[str, Any]:
    if not db.db_exists(db_path):
        return dict(_EMPTY_FLOWS)

    total = int(db.scalar(db_path, "SELECT COUNT(*) FROM flows") or 0)
    by_source = {
        (r.get("source") or "unknown"): int(r.get("n") or 0)
        for r in db.query_all(
            db_path, "SELECT source, COUNT(*) AS n FROM flows GROUP BY source"
        )
    }

    by_class = {"2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0, "other": 0}
    for r in db.query_all(
        db_path,
        """
        SELECT
          CASE
            WHEN status_code IS NULL THEN 'other'
            WHEN status_code BETWEEN 200 AND 299 THEN '2xx'
            WHEN status_code BETWEEN 300 AND 399 THEN '3xx'
            WHEN status_code BETWEEN 400 AND 499 THEN '4xx'
            WHEN status_code BETWEEN 500 AND 599 THEN '5xx'
            ELSE 'other'
          END AS cls,
          COUNT(*) AS n
        FROM flows
        GROUP BY cls
        """,
    ):
        cls = r.get("cls") or "other"
        if cls in by_class:
            by_class[cls] = int(r.get("n") or 0)
        else:
            by_class["other"] += int(r.get("n") or 0)

    distinct_hosts = int(
        db.scalar(db_path, "SELECT COUNT(DISTINCT host) FROM flows") or 0
    )
    distinct_methods = int(
        db.scalar(db_path, "SELECT COUNT(DISTINCT method) FROM flows") or 0
    )
    last_row = db.query_one(db_path, "SELECT MAX(captured_at) AS last_at FROM flows")
    last_captured = (last_row or {}).get("last_at")

    return {
        "total": total,
        "by_source": by_source,
        "by_status_class": by_class,
        "distinct_hosts": distinct_hosts,
        "distinct_methods": distinct_methods,
        "last_captured_at": last_captured,
    }


def _endpoints_block(project_id: str, db_path: Path) -> dict[str, Any]:
    if not db.db_exists(db_path):
        return dict(_EMPTY_ENDPOINTS)
    try:
        inv = endpoint_reads.inventory_summary(project_id)
        pol = endpoint_reads.policy_summary(project_id)
        cov = endpoint_reads.coverage(project_id)
        cards = cov.get("cards") or {}
        return {
            "inventory": inv,
            "policy": {
                "by_priority": pol.get("by_priority")
                or {"CRITICAL": 0, "HIGH": 0, "NORMAL": 0, "LOW": 0},
                "manual_overrides": pol.get("manual_overrides", 0),
                "rule_controlled": pol.get("rule_controlled", 0),
                "auto_controlled": pol.get("auto_controlled", 0),
                "total": pol.get("total", 0),
            },
            "coverage": {
                "qualified_pct": cards.get("qualified_pct", 0),
                "baseline_pct": cards.get("baseline_pct", 0),
                "multi_role_pct": cards.get("multi_role_pct", 0),
                "params_pct": cards.get("parameters_pct", 0),
                "excluded_pct": cards.get("excluded_pct", 0),
            },
        }
    except Exception:
        return dict(_EMPTY_ENDPOINTS)


def _session_health_block(db_path: Path) -> list[dict[str, Any]]:
    if not db.db_exists(db_path):
        return []

    roles = db.query_all(
        db_path,
        "SELECT id, name, is_active FROM roles ORDER BY name",
    )
    out: list[dict[str, Any]] = []
    for role in roles:
        role_id = role["id"]
        provider_row = db.query_one(
            db_path,
            "SELECT provider, updated_at FROM role_auth_provider WHERE role_id=?",
            (role_id,),
        )
        artifacts = db.query_all(
            db_path,
            "SELECT key, value, collected_at FROM role_auth_state WHERE role_id=?",
            (role_id,),
        )
        health_row = db.query_one(
            db_path,
            "SELECT ttl_seconds, refresh_before_seconds FROM session_health_config "
            "WHERE role_id=?",
            (role_id,),
        )
        control_n = int(
            db.scalar(
                db_path,
                "SELECT COUNT(*) FROM session_health_control_flows WHERE role_id=?",
                (role_id,),
            )
            or 0
        )
        suspicion = db.query_one(
            db_path,
            "SELECT suspicion_count, last_checked_at FROM session_suspicion_state "
            "WHERE role_id=?",
            (role_id,),
        )
        manual = db.query_one(
            db_path,
            "SELECT expires_at, ttl_seconds, updated_at FROM manual_session_config "
            "WHERE role_id=?",
            (role_id,),
        )

        provider_name = (provider_row or {}).get("provider") if provider_row else None
        configured = bool(provider_name) or bool(artifacts) or bool(manual)
        suspicion_count = int((suspicion or {}).get("suspicion_count") or 0)
        health_degraded = suspicion_count >= _SUSPICION_THRESHOLD

        ttl = 1200
        if health_row and health_row.get("ttl_seconds") is not None:
            try:
                ttl = int(health_row["ttl_seconds"])
            except (TypeError, ValueError):
                ttl = 1200

        session_age_seconds = None
        expires_in_seconds = None
        collected_at = next(
            (a.get("collected_at") for a in artifacts if a.get("collected_at")),
            None,
        )
        if collected_at:
            ca = _parse_dt(str(collected_at))
            if ca is not None:
                session_age_seconds = int(
                    (datetime.now(timezone.utc) - ca).total_seconds()
                )

        if provider_name == "manual" and manual and manual.get("expires_at"):
            exp = _parse_dt(str(manual["expires_at"]))
            if exp is not None:
                expires_in_seconds = int(
                    (exp - datetime.now(timezone.utc)).total_seconds()
                )
        elif session_age_seconds is not None:
            expires_in_seconds = ttl - session_age_seconds

        out.append(
            {
                "role_id": role_id,
                "role_name": role.get("name") or role_id,
                "is_active": bool(role.get("is_active")),
                "provider": provider_name,
                "configured": configured,
                "health_degraded": health_degraded,
                "suspicion_count": suspicion_count,
                "suspicion_threshold": _SUSPICION_THRESHOLD,
                "expires_in_seconds": expires_in_seconds,
                "session_age_seconds": session_age_seconds,
                "control_flow_count": control_n,
                "artifact_count": len(artifacts),
            }
        )
    return out


def _http_rules_block(project_id: str) -> dict[str, Any]:
    try:
        result = cli.run_scoped(
            project_id, ["config", "http", "list", "--format", "json"]
        )
        payload = _last_json_from_steps(result)
        rules = payload.get("rules") or []
        enabled = payload.get("enabled", True)
        active = [r for r in rules if r.get("enabled", True)]
        request_n = sum(
            1
            for r in active
            if str(r.get("direction", "request")).lower() in ("request", "both")
        )
        response_n = sum(
            1
            for r in active
            if str(r.get("direction", "request")).lower() in ("response", "both")
        )
        disabled_n = sum(1 for r in rules if not r.get("enabled", True))
        return {
            "enabled": bool(enabled),
            "summary": {
                "active": len(active),
                "request": request_n,
                "response": response_n,
                "disabled": disabled_n,
                "total": len(rules),
            },
        }
    except Exception:
        return dict(_EMPTY_HTTP)


def _talos_config_block(project_id: str) -> dict[str, Any]:
    try:
        result = cli.run(
            ["--project", project_id, "config", "effective", "--format", "json"],
            timeout=30,
        )
        if not result.ok:
            return {"source_counts": {}, "sections": [], "key_flags": {}}
        data = _parse_json_stdout(result.stdout)
        if not isinstance(data, dict):
            return {"source_counts": {}, "sections": [], "key_flags": {}}
        values = data.get("values") or {}
        sources = data.get("sources") or {}
        if not isinstance(values, dict):
            values = {}
        if not isinstance(sources, dict):
            sources = {}
        sources = {str(k): str(v).lower() for k, v in sources.items()}
        sections = _section_summaries(values, sources)
        source_counts = _source_counts(sources)
        key_flags = {
            "upstream_enabled": bool(values.get("proxy.upstream.enabled", False)),
            "upstream_url": values.get("proxy.upstream.url"),
            "store_bodies": values.get("capture.store_bodies", True),
            "max_body_size": values.get("capture.max_body_size"),
            "unauth_auto_run": bool(values.get("attack.unauth_auto_run", False)),
            "http_enabled": bool(values.get("http.enabled", True)),
            "min_delay": values.get("scheduler.min_delay"),
            "max_delay": values.get("scheduler.max_delay"),
            "max_queue_size": values.get("scheduler.max_queue_size"),
        }
        return {
            "source_counts": source_counts,
            "sections": sections,
            "key_flags": key_flags,
        }
    except Exception:
        return {"source_counts": {}, "sections": [], "key_flags": {}}


def _proxy_block() -> dict[str, Any]:
    stopped = {
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
        "last_error": None,
        "validation_deferred": False,
        "cli_ok": False,
    }
    try:
        result = cli.run(["proxy", "status", "--format", "json"], timeout=15)
        if not result.ok:
            err = (result.stderr or result.stdout or "proxy status failed").strip()
            body = dict(stopped)
            body["last_error"] = err or None
            return body
        data = _parse_json_stdout(result.stdout)
        if not isinstance(data, dict):
            body = dict(stopped)
            body["last_error"] = "proxy status returned non-JSON output"
            return body
        state = str(data.get("state") or "stopped").lower()
        out = dict(data)
        out["state"] = state
        out["running"] = state == "running"
        out["transitional"] = bool(
            data.get("transitional")
            or state in ("starting", "draining", "stopping")
        )
        out["cli_ok"] = True
        return out
    except Exception as exc:
        body = dict(stopped)
        body["last_error"] = str(exc)
        return body


def project_dashboard(project_id: str) -> dict[str, Any] | None:
    """
    Full mission-control snapshot for one project.
    Returns None if the project is unknown.
    Returns zeros and safe defaults when the DB is missing.
    """
    record = db.get_project_record(project_id)
    if record is None:
        return None

    db_path = config.project_db_path(project_id, record)
    exists = db.db_exists(db_path)
    active_id = db.get_active_project_id()
    status = record.get("status") or "inactive"
    is_active = (
        status == "active"
        or bool(record.get("active") or record.get("is_active"))
        or project_id == active_id
    )
    scope = record.get("scope") or []
    if not isinstance(scope, list):
        scope = []
    constraints_raw = record.get("constraints") or {}
    if not isinstance(constraints_raw, dict):
        constraints_raw = {}
    constraints = {**_default_constraints(), **constraints_raw}

    outscope_count = 0
    roles_n = 0
    modules_n = 0
    if exists:
        try:
            outscope_count = int(
                db.scalar(
                    db_path,
                    "SELECT COUNT(*) FROM out_of_scope_domains WHERE project_id=?",
                    (project_id,),
                )
                or 0
            )
        except Exception:
            outscope_count = 0
        roles_n = int(db.scalar(db_path, "SELECT COUNT(*) FROM roles") or 0)
        modules_n = int(db.scalar(db_path, "SELECT COUNT(*) FROM modules") or 0)

    findings = _findings_block(db_path, project_id) if exists else dict(_EMPTY_FINDINGS)
    scheduler = _scheduler_block(db_path) if exists else dict(_EMPTY_SCHEDULER)
    flows = _flows_block(db_path) if exists else dict(_EMPTY_FLOWS)
    endpoints = _endpoints_block(project_id, db_path)
    session_health = _session_health_block(db_path) if exists else []
    proxy = _proxy_block()
    http_rules = _http_rules_block(project_id) if exists else dict(_EMPTY_HTTP)
    talos_config = _talos_config_block(project_id)

    proxy_running = bool(proxy.get("running"))
    any_session_degraded = any(r.get("health_degraded") for r in session_health)
    any_session_ok = any(
        r.get("configured") and not r.get("health_degraded") for r in session_health
    )
    readiness = {
        "active": is_active,
        "db": exists,
        "scope": len(scope) > 0,
        "proxy": proxy_running,
        "session": (
            "degraded"
            if any_session_degraded
            else ("ok" if any_session_ok else "unconfigured")
        ),
        "queue_pressure": int(scheduler.get("queue_fill_pct") or 0) >= 80,
        "triaging": int((findings.get("by_status") or {}).get("TRIAGING") or 0),
    }

    return {
        "project": {
            "id": project_id,
            "name": record.get("name", project_id),
            "description": record.get("description", ""),
            "active": is_active,
            "status": "active" if is_active else status,
            "db_exists": exists,
            "data_dir": str(config.project_data_dir(project_id, record)),
            "scope": scope,
            "scope_count": len(scope),
            "outscope_count": outscope_count,
            "constraints": {
                "capture_in_scope_only": bool(
                    constraints.get("capture_in_scope_only", True)
                ),
                "store_bodies": bool(constraints.get("store_bodies", True)),
                "max_body_size": int(
                    constraints.get("max_body_size") or 1 * 1024 * 1024
                ),
            },
            "roles": roles_n,
            "modules": modules_n,
            "created_at": record.get("created_at"),
        },
        "readiness": readiness,
        "findings": findings,
        "scheduler": scheduler,
        "proxy": proxy,
        "endpoints": endpoints,
        "flows": flows,
        "session_health": session_health,
        "http_rules": http_rules,
        "talos_config": talos_config,
    }
