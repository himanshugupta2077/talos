"""
Module: talos.error_intel.cli

Purpose:
    Operator CLI for Error Intelligence (Phase 8):

        talos error-intel status
        talos error-intel config show|set
        talos error-intel errors list|show   # clusters
        talos error-intel observations list  # filter by endpoint/param/attack
        talos error-intel rescan --all|--flow ID
        talos error-intel rollup parameter|endpoint

    No auto Findings. Evidence snippets are size-capped at store time.

Dependencies:
    argparse, sys, sqlite3
    talos.cli_output, talos.projects.manager
    talos.error_intel.{db, config, constants, worker}
Data flow:
    talos.__main__ → run_error_intel_cli(manager, argv) → handlers → stdout/DB
Side effects:
    config set / rescan write to project SQLite; list/show are read-only.
"""

from __future__ import annotations

import argparse
import sqlite3
import sys
from pathlib import Path
from typing import Any, Optional

from talos.cli_output import (
    EXIT_USAGE,
    add_format_argument,
    cli_error,
    cli_json,
    cli_precondition_error,
    cli_usage_error,
    wants_json,
)
from talos.error_intel import db as error_db
from talos.error_intel.config import merge_config
from talos.error_intel.constants import ERROR_INTEL_VERSION
from talos.error_intel.worker import process_error_scan_sync
from talos.projects.manager import ProjectManager


def run_error_intel_cli(manager: ProjectManager, argv: list[str]) -> None:
    """
    Purpose:
        Parse error-intel subcommands and dispatch.
    Input:
        manager — ProjectManager
        argv    — args after ``error-intel``
    Side effects:
        May write config / rescan; prints; may sys.exit.
    """
    if not argv or argv[0] in ("--help", "-h"):
        _print_usage()
        sys.exit(0)

    sub = argv[0]
    rest = argv[1:]

    if sub == "status":
        _cmd_status(manager, rest)
    elif sub == "config":
        _cmd_config(manager, rest)
    elif sub in ("errors", "clusters"):
        _cmd_errors(manager, rest)
    elif sub in ("observations", "obs"):
        _cmd_observations(manager, rest)
    elif sub == "rescan":
        _cmd_rescan(manager, rest)
    elif sub == "rollup":
        _cmd_rollup(manager, rest)
    else:
        cli_error(f"Unknown error-intel subcommand '{sub}'.", exit_code=None)
        _print_usage()
        sys.exit(EXIT_USAGE)


def _print_usage() -> None:
    print(
        "talos error-intel — Error Intelligence (passive error clusters)\n\n"
        "Usage: talos error-intel <subcommand> [args]\n\n"
        "  status                      Cluster / observation counts by severity\n"
        "  config show                 Show error_intel_config\n"
        "  config set KEY VALUE        Update one config field\n"
        "  errors list|show            Error clusters (fingerprint identity)\n"
        "  observations list           Sightings (flow / param / attack)\n"
        "  rescan --all | --flow ID    Re-run pipeline on stored bodies\n"
        "  rollup parameter|endpoint   Phase 7 parameter/endpoint rollups\n\n"
        "Aliases: clusters → errors, obs → observations\n"
        "No auto Findings in v1 — intelligence tables only.\n"
    )


def _require_project(manager: ProjectManager):
    """Resolve active project or exit with precondition error."""
    project = manager.active()
    if project is None:
        cli_precondition_error(
            "No active project. Use: talos project open <id> "
            "or talos --project <id> …"
        )
    return project


# ------------------------------------------------------------------ #
# status                                                               #
# ------------------------------------------------------------------ #

def _cmd_status(manager: ProjectManager, argv: list[str]) -> None:
    parser = argparse.ArgumentParser(
        prog="talos error-intel status", add_help=True
    )
    add_format_argument(parser)
    args = parser.parse_args(argv)
    project = _require_project(manager)
    db_path = project.db_path
    cfg = error_db.get_config(db_path)

    clusters = error_db.count_clusters(db_path, project.id)
    observations = error_db.count_observations(
        db_path, project_id=project.id
    )
    by_sev = error_db.severity_counts(db_path, project.id)
    by_cat = error_db.category_counts(db_path, project.id)

    payload = {
        "enabled": cfg.enabled,
        "store_generic_http_errors": cfg.store_generic_http_errors,
        "scanner_version": ERROR_INTEL_VERSION,
        "clusters": clusters,
        "observations": observations,
        "by_severity": by_sev,
        "by_category": by_cat,
        "queue_maxsize": cfg.queue_maxsize,
        "max_body_scan": cfg.max_body_scan,
    }
    if wants_json(args):
        cli_json(payload)
        return

    print(f"Error Intelligence status — project={project.id}")
    print(f"  enabled:                    {cfg.enabled}")
    print(f"  store_generic_http_errors:  {cfg.store_generic_http_errors}")
    print(f"  scanner_version:            {ERROR_INTEL_VERSION}")
    print(f"  clusters:                   {clusters}")
    print(f"  observations:               {observations}")
    print(f"  queue_maxsize:              {cfg.queue_maxsize}")
    if by_sev:
        print("  by severity:")
        for k in sorted(by_sev.keys()):
            print(f"    {k}: {by_sev[k]}")
    if by_cat:
        print("  by category:")
        for k in sorted(by_cat.keys()):
            print(f"    {k}: {by_cat[k]}")


# ------------------------------------------------------------------ #
# config                                                               #
# ------------------------------------------------------------------ #

_CONFIG_KEYS = frozenset({
    "enabled",
    "store_generic_http_errors",
    "max_body_scan",
    "gate_sniff_bytes",
    "queue_maxsize",
    "evidence_snippet_max",
    "error_header_names",
})


def _cmd_config(manager: ProjectManager, argv: list[str]) -> None:
    if not argv or argv[0] in ("--help", "-h"):
        print(
            "talos error-intel config show\n"
            "talos error-intel config set <key> <value>\n\n"
            f"Keys: {', '.join(sorted(_CONFIG_KEYS))}\n"
        )
        sys.exit(0)

    action = argv[0]
    rest = argv[1:]
    project = _require_project(manager)

    if action == "show":
        parser = argparse.ArgumentParser(
            prog="talos error-intel config show", add_help=True
        )
        add_format_argument(parser)
        args = parser.parse_args(rest)
        cfg = error_db.get_config(project.db_path)
        data = cfg.to_dict()
        if wants_json(args):
            cli_json(data)
            return
        for key in sorted(data.keys()):
            print(f"  {key}: {data[key]}")
        return

    if action == "set":
        if len(rest) < 2:
            cli_usage_error(
                "Usage: talos error-intel config set <key> <value>"
            )
        key = rest[0]
        value = rest[1]
        if key not in _CONFIG_KEYS:
            cli_error(
                f"Unknown config key '{key}'. "
                f"Known: {', '.join(sorted(_CONFIG_KEYS))}"
            )
        cfg = error_db.get_config(project.db_path)
        parsed = _parse_config_value(key, value)
        updated = merge_config(cfg, {key: parsed})
        error_db.update_config(project.db_path, updated)
        print(
            f"Updated error-intel config {key} = "
            f"{getattr(updated, key)}"
        )
        return

    cli_error(f"Unknown config action '{action}'. Use show|set.")


def _parse_config_value(key: str, value: str) -> Any:
    """Coerce CLI string to config field type."""
    if key in {"enabled", "store_generic_http_errors"}:
        low = value.strip().lower()
        if low in ("1", "true", "yes", "on"):
            return True
        if low in ("0", "false", "no", "off"):
            return False
        cli_usage_error(f"Boolean expected for {key}, got {value!r}")
    if key in {
        "max_body_scan",
        "gate_sniff_bytes",
        "queue_maxsize",
        "evidence_snippet_max",
    }:
        try:
            return int(value)
        except ValueError:
            cli_usage_error(f"Integer expected for {key}, got {value!r}")
    if key == "error_header_names":
        # comma or space separated
        return value
    return value


# ------------------------------------------------------------------ #
# errors (clusters)                                                    #
# ------------------------------------------------------------------ #

def _cmd_errors(manager: ProjectManager, argv: list[str]) -> None:
    if not argv or argv[0] in ("--help", "-h"):
        print(
            "talos error-intel errors list "
            "[--category CAT] [--severity SEV] [--limit N]\n"
            "talos error-intel errors show <error_id>\n"
        )
        sys.exit(0)

    action = argv[0]
    rest = argv[1:]
    project = _require_project(manager)

    if action == "list":
        parser = argparse.ArgumentParser(
            prog="talos error-intel errors list", add_help=True
        )
        parser.add_argument("--category", default=None)
        parser.add_argument("--severity", default=None)
        parser.add_argument("--limit", type=int, default=50)
        add_format_argument(parser)
        args = parser.parse_args(rest)
        clusters = error_db.list_clusters(
            project.db_path,
            project.id,
            category=args.category,
            severity=args.severity,
            limit=args.limit,
        )
        rows = [_cluster_row(c) for c in clusters]
        if wants_json(args):
            cli_json({"errors": rows})
            return
        if not rows:
            print("No error clusters.")
            return
        print(
            f"{'ID':<10} {'SEV':<10} {'CAT':<16} "
            f"{'OBS':>4} EXCEPTION"
        )
        for r in rows:
            exc = (r.get("exception_type") or r.get("message_norm") or "")[
                :40
            ]
            print(
                f"{r['id'][:8]:<10} {r['severity']:<10} "
                f"{r['category']:<16} {r['observation_count']:>4} {exc}"
            )
        return

    if action == "show":
        if not rest:
            cli_usage_error(
                "Usage: talos error-intel errors show <error_id>"
            )
        error_id = rest[0]
        parser = argparse.ArgumentParser(
            prog="talos error-intel errors show", add_help=True
        )
        add_format_argument(parser)
        args = parser.parse_args(rest[1:])
        cluster = _resolve_cluster(project.db_path, project.id, error_id)
        if cluster is None:
            cli_error(f"Error cluster not found: {error_id}")
        obs = error_db.list_observations(
            project.db_path, error_id=cluster.id, limit=20
        )
        payload = {
            "error": _cluster_row(cluster),
            "observations": [_obs_row(o) for o in obs],
        }
        if wants_json(args):
            cli_json(payload)
            return
        e = payload["error"]
        print(f"Error cluster {e['id']}")
        for k, v in e.items():
            if k == "id":
                continue
            print(f"  {k}: {v}")
        print(f"Observations ({len(payload['observations'])}):")
        for o in payload["observations"]:
            print(
                f"  - flow={ (o.get('flow_id') or '')[:8] or '-'}  "
                f"attack={o.get('attack_type')}  "
                f"param={o.get('parameter_name') or o.get('parameter_uuid') or '-'}"
            )
        return

    cli_error(f"Unknown errors action '{action}'. Use list|show.")


def _resolve_cluster(db_path: Path, project_id: str, error_id: str):
    """Resolve full or prefix cluster id."""
    cluster = error_db.get_cluster(db_path, error_id)
    if cluster is not None:
        return cluster
    if len(error_id) >= 8:
        all_c = error_db.list_clusters(db_path, project_id, limit=500)
        matches = [c for c in all_c if c.id.startswith(error_id)]
        if len(matches) == 1:
            return matches[0]
    return None


def _cluster_row(c) -> dict[str, Any]:
    return {
        "id": c.id,
        "project_id": c.project_id,
        "fingerprint": c.fingerprint,
        "category": c.category,
        "severity": c.severity,
        "language": c.language,
        "framework": c.framework,
        "database": c.database,
        "server": c.server,
        "exception_type": c.exception_type,
        "message_norm": c.message_norm,
        "technologies": list(c.technologies or []),
        "has_stack_trace": c.has_stack_trace,
        "has_path_leak": c.has_path_leak,
        "has_internal_host": c.has_internal_host,
        "has_version_leak": c.has_version_leak,
        "confidence": c.confidence,
        "evidence_snippet": c.evidence_snippet,
        "first_seen": c.first_seen,
        "last_seen": c.last_seen,
        "observation_count": c.observation_count,
        "scanner_version": c.scanner_version,
    }


# ------------------------------------------------------------------ #
# observations                                                         #
# ------------------------------------------------------------------ #

def _cmd_observations(manager: ProjectManager, argv: list[str]) -> None:
    if not argv or argv[0] in ("--help", "-h"):
        print(
            "talos error-intel observations list "
            "[--error ID] [--flow ID] [--endpoint ID] "
            "[--parameter UUID] [--attack TYPE] [--limit N]\n"
        )
        sys.exit(0)

    action = argv[0]
    rest = argv[1:]
    if action != "list":
        cli_error("Usage: talos error-intel observations list …")

    parser = argparse.ArgumentParser(
        prog="talos error-intel observations list", add_help=True
    )
    parser.add_argument("--error", dest="error_id", default=None)
    parser.add_argument("--flow", dest="flow_id", default=None)
    parser.add_argument("--endpoint", dest="endpoint_id", default=None)
    parser.add_argument("--parameter", dest="parameter_uuid", default=None)
    parser.add_argument("--attack", dest="attack_type", default=None)
    parser.add_argument("--limit", type=int, default=50)
    add_format_argument(parser)
    args = parser.parse_args(rest)
    project = _require_project(manager)

    # When only project scope, list via clusters then observations is heavy;
    # list_observations without error_id returns global rows — filter by
    # joining through project clusters when no specific filters.
    if (
        not args.error_id
        and not args.flow_id
        and not args.endpoint_id
        and not args.parameter_uuid
        and not args.attack_type
    ):
        clusters = error_db.list_clusters(
            project.db_path, project.id, limit=200
        )
        obs_all = []
        remaining = args.limit
        for c in clusters:
            if remaining <= 0:
                break
            batch = error_db.list_observations(
                project.db_path,
                error_id=c.id,
                limit=remaining,
            )
            obs_all.extend(batch)
            remaining = args.limit - len(obs_all)
        # Sort newest first
        obs_all.sort(key=lambda o: o.observed_at or "", reverse=True)
        observations = obs_all[: args.limit]
    else:
        observations = error_db.list_observations(
            project.db_path,
            error_id=args.error_id,
            flow_id=args.flow_id,
            endpoint_id=args.endpoint_id,
            parameter_uuid=args.parameter_uuid,
            attack_type=args.attack_type,
            limit=args.limit,
        )
        # Filter to this project when error_id not given
        if not args.error_id and observations:
            project_ids = {
                c.id
                for c in error_db.list_clusters(
                    project.db_path, project.id, limit=1000
                )
            }
            observations = [
                o for o in observations if o.error_id in project_ids
            ]

    rows = [_obs_row(o) for o in observations]
    if wants_json(args):
        cli_json({"observations": rows})
        return
    if not rows:
        print("No error observations.")
        return
    print(
        f"{'ID':<10} {'ERROR':<10} {'ATTACK':<10} "
        f"{'STATUS':>6} PARAM"
    )
    for r in rows:
        param = r.get("parameter_name") or r.get("parameter_uuid") or "-"
        if isinstance(param, str) and len(param) > 24:
            param = param[:21] + "…"
        print(
            f"{r['id'][:8]:<10} {(r.get('error_id') or '')[:8]:<10} "
            f"{r.get('attack_type') or '-':<10} "
            f"{str(r.get('response_status') or '-'):>6} {param}"
        )


def _obs_row(o) -> dict[str, Any]:
    return {
        "id": o.id,
        "error_id": o.error_id,
        "flow_id": o.flow_id,
        "endpoint_id": o.endpoint_id,
        "parameter_uuid": o.parameter_uuid,
        "parameter_name": o.parameter_name,
        "attack_type": o.attack_type,
        "payload_redacted": o.payload_redacted,
        "response_status": o.response_status,
        "response_length": o.response_length,
        "duration_ms": o.duration_ms,
        "response_hash": o.response_hash,
        "detectors": list(o.detectors or []),
        "artifacts": [
            {"kind": a.kind, "value": a.value, "normalized": a.normalized}
            for a in (o.artifacts or [])
        ],
        "observed_at": o.observed_at,
    }


# ------------------------------------------------------------------ #
# rescan                                                               #
# ------------------------------------------------------------------ #

def _cmd_rescan(manager: ProjectManager, argv: list[str]) -> None:
    if not argv or argv[0] in ("--help", "-h"):
        print(
            "talos error-intel rescan --all [--force] [--outdated] [--limit N]\n"
            "talos error-intel rescan --flow <flow_id> [--force]\n"
            "\n"
            "Without --force, flows already observed at the current\n"
            f"ERROR_INTEL_VERSION ({ERROR_INTEL_VERSION}) are skipped.\n"
            "Observations from older scanner versions are reprocessed\n"
            "automatically (versioned invalidation).\n"
            "--outdated limits --all to flows whose cluster scanner_version\n"
            "differs from the current version (or has no observation yet).\n"
        )
        sys.exit(0)

    parser = argparse.ArgumentParser(
        prog="talos error-intel rescan", add_help=True
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Rescan recent error-like flows from the DB",
    )
    parser.add_argument("--flow", dest="flow_id", default=None)
    parser.add_argument(
        "--force",
        action="store_true",
        help="Re-process even when current-version observations exist",
    )
    parser.add_argument(
        "--outdated",
        action="store_true",
        help=(
            "With --all: only flows missing an observation or whose cluster "
            f"scanner_version != {ERROR_INTEL_VERSION}"
        ),
    )
    parser.add_argument("--limit", type=int, default=200)
    args = parser.parse_args(argv)

    if not args.all and not args.flow_id:
        cli_usage_error(
            "Specify --all or --flow <flow_id>"
        )

    project = _require_project(manager)
    db_path = project.db_path
    cfg = error_db.get_config(db_path)
    if not cfg.enabled:
        print("Error Intelligence is disabled (config.enabled=false).")
        return

    if args.flow_id:
        result = process_error_scan_sync(
            db_path=db_path,
            project_id=project.id,
            flow_id=args.flow_id,
            force=args.force,
            config=cfg,
        )
        if result and result.get("stored"):
            print(
                f"Stored error cluster {result.get('cluster_id')} "
                f"(created={result.get('created')}) for flow {args.flow_id}"
            )
        elif result and result.get("duplicate"):
            print(
                f"Flow {args.flow_id} already has current-version observations "
                f"(use --force to re-scan; version={ERROR_INTEL_VERSION})."
            )
        else:
            print(
                f"No error match for flow {args.flow_id} "
                f"(not candidate or detectors empty)."
            )
        return

    # --all: walk recent error-like flows (incl. 2xx JSON/text candidates)
    flow_ids = _list_rescan_flow_ids(
        db_path,
        project.id,
        limit=args.limit,
        outdated_only=args.outdated,
    )
    stored = 0
    skipped = 0
    dups = 0
    for fid in flow_ids:
        result = process_error_scan_sync(
            db_path=db_path,
            project_id=project.id,
            flow_id=fid,
            force=args.force,
            config=cfg,
        )
        if result and result.get("stored"):
            stored += 1
        elif result and result.get("duplicate"):
            dups += 1
        else:
            skipped += 1
    print(
        f"Rescan complete — scanned={len(flow_ids)} stored={stored} "
        f"duplicates={dups} skipped={skipped} version={ERROR_INTEL_VERSION}"
    )


def _list_rescan_flow_ids(
    db_path: Path,
    project_id: str,
    *,
    limit: int = 200,
    outdated_only: bool = False,
) -> list[str]:
    """
    Purpose:
        Select recent flow IDs that are cheap error candidates.

        Includes 4xx/5xx, missing status, and 2xx responses with scannable
        content types / body length so stack traces on HTTP 200 enter bulk
        rescan (BUG-10). Full gate still runs inside process_error_scan_sync.

        When outdated_only is True, skip flows whose observation cluster is
        already at ERROR_INTEL_VERSION (BUG-09).
    """
    lim = max(1, int(limit))
    # Over-fetch when filtering outdated so we still fill the limit.
    fetch = lim * 4 if outdated_only else lim
    with sqlite3.connect(str(db_path)) as conn:
        rows = conn.execute(
            """
            SELECT id FROM flows
            WHERE project_id = ?
              AND (
                status_code >= 400
                OR status_code IS NULL
                OR (
                  status_code BETWEEN 200 AND 299
                  AND (
                    content_type LIKE '%json%'
                    OR content_type LIKE '%text%'
                    OR content_type LIKE '%html%'
                    OR content_type LIKE '%xml%'
                    OR content_type IS NULL
                    OR content_type = ''
                  )
                  AND response_body IS NOT NULL
                  AND length(response_body) >= 40
                )
              )
            ORDER BY captured_at DESC
            LIMIT ?
            """,
            (project_id, fetch),
        ).fetchall()
    ids = [str(r[0]) for r in rows]
    if not outdated_only:
        return ids[:lim]

    out: list[str] = []
    for fid in ids:
        if error_db.has_current_observation_for_flow(
            db_path, fid, scanner_version=ERROR_INTEL_VERSION
        ):
            continue
        out.append(fid)
        if len(out) >= lim:
            break
    return out


# ------------------------------------------------------------------ #
# rollup (Phase 7)                                                     #
# ------------------------------------------------------------------ #

def _cmd_rollup(manager: ProjectManager, argv: list[str]) -> None:
    if not argv or argv[0] in ("--help", "-h"):
        print(
            "talos error-intel rollup parameter "
            "[--parameter UUID] [--limit N]\n"
            "talos error-intel rollup endpoint "
            "[--endpoint ID] [--limit N]\n"
        )
        sys.exit(0)

    kind = argv[0]
    rest = argv[1:]
    project = _require_project(manager)

    if kind == "parameter":
        parser = argparse.ArgumentParser(
            prog="talos error-intel rollup parameter", add_help=True
        )
        parser.add_argument("--parameter", dest="parameter_uuid", default=None)
        parser.add_argument("--limit", type=int, default=50)
        add_format_argument(parser)
        args = parser.parse_args(rest)
        rows = error_db.parameter_error_rollup(
            project.db_path,
            project.id,
            parameter_uuid=args.parameter_uuid,
            limit=args.limit,
        )
        if wants_json(args):
            cli_json({"rollup": rows})
            return
        if not rows:
            print("No parameter-linked error observations.")
            return
        print(
            f"{'PARAM':<24} {'SEV':<10} {'CAT':<14} "
            f"{'OBS':>4} EXCEPTION"
        )
        for r in rows:
            name = r.get("parameter_name") or r.get("parameter_uuid") or "-"
            if len(str(name)) > 22:
                name = str(name)[:19] + "…"
            exc = (r.get("exception_type") or "")[:30]
            print(
                f"{name:<24} {r.get('severity') or '-':<10} "
                f"{r.get('category') or '-':<14} "
                f"{r.get('observation_count') or 0:>4} {exc}"
            )
        return

    if kind == "endpoint":
        parser = argparse.ArgumentParser(
            prog="talos error-intel rollup endpoint", add_help=True
        )
        parser.add_argument("--endpoint", dest="endpoint_id", default=None)
        parser.add_argument("--limit", type=int, default=50)
        add_format_argument(parser)
        args = parser.parse_args(rest)
        rows = error_db.endpoint_error_rollup(
            project.db_path,
            project.id,
            endpoint_id=args.endpoint_id,
            limit=args.limit,
        )
        if wants_json(args):
            cli_json({"rollup": rows})
            return
        if not rows:
            print("No endpoint-linked error observations.")
            return
        print(
            f"{'ENDPOINT':<12} {'SEV':<10} {'CAT':<14} "
            f"{'OBS':>4} EXCEPTION"
        )
        for r in rows:
            ep = (r.get("endpoint_id") or "-")[:10]
            exc = (r.get("exception_type") or "")[:30]
            print(
                f"{ep:<12} {r.get('severity') or '-':<10} "
                f"{r.get('category') or '-':<14} "
                f"{r.get('observation_count') or 0:>4} {exc}"
            )
        return

    cli_error(f"Unknown rollup kind '{kind}'. Use parameter|endpoint.")
