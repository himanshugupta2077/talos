"""
Module: talos.passive.cli

Purpose:
    Operator CLI for Passive Source Intelligence (Phase 9):

        talos passive status
        talos passive config show|set
        talos passive rules list
        talos passive documents list|show
        talos passive detections list|show
        talos passive rescan [--all | --document ID | --flow ID]

    Secrets are redacted in default output; ``--show-secrets`` is reserved
    (raw secrets are not stored on detection rows — evidence may hold them).

Dependencies:
    argparse, sys, hashlib, sqlite3
    talos.cli_output, talos.projects.manager
    talos.passive.{db, config, constants, rules_loader, worker helpers}
Data flow:
    talos.__main__ → run_passive_cli(manager, argv) → handlers → stdout/DB
Side effects:
    config set / rescan write to project SQLite; list/show are read-only.
"""

from __future__ import annotations

import argparse
import hashlib
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
from talos.passive import db as passive_db
from talos.passive.config import PassiveScanConfig, merge_config
from talos.passive.constants import SCANNER_VERSION, SourceKind
from talos.passive.detectors.orchestrator import DetectorOrchestrator
from talos.passive.extractors.html import extract_html_virtual_docs
from talos.passive.extractors.sourcemap import extract_sourcemap_virtual_docs
from talos.passive.finding_bridge import maybe_create_findings_for_detections
from talos.passive.models import Detection
from talos.passive.normalize import normalize_body
from talos.passive.rules_loader import load_rule_packs
from talos.passive.worker import path_looks_like_sourcemap
from talos.projects.manager import ProjectManager


def run_passive_cli(manager: ProjectManager, argv: list[str]) -> None:
    """
    Purpose:
        Parse passive subcommands and dispatch.
    Input:
        manager — ProjectManager
        argv    — args after ``passive``
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
    elif sub == "rules":
        _cmd_rules(manager, rest)
    elif sub == "documents":
        _cmd_documents(manager, rest)
    elif sub == "detections":
        _cmd_detections(manager, rest)
    elif sub == "rescan":
        _cmd_rescan(manager, rest)
    else:
        cli_error(f"Unknown passive subcommand '{sub}'.", exit_code=None)
        _print_usage()
        sys.exit(EXIT_USAGE)


def _print_usage() -> None:
    print(
        "talos passive — Passive Source Intelligence / secret scan\n\n"
        "Usage: talos passive <subcommand> [args]\n\n"
        "  status                 Document / detection / finding counts\n"
        "  config show            Show passive_scan_config\n"
        "  config set KEY VALUE   Update one config field\n"
        "  rules list             List loaded detector rules\n"
        "  documents list|show    Source documents inventory\n"
        "  detections list|show   Passive detections (redacted)\n"
        "  rescan                 Re-run detectors on stored bodies\n"
        "                         [--all | --document ID | --flow ID]\n\n"
        "Secrets are redacted in list/show output by default.\n"
    )


def _require_project(manager: ProjectManager):
    """Resolve active project or exit with precondition error."""
    project = manager.get_active_project()
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
    parser = argparse.ArgumentParser(prog="talos passive status", add_help=True)
    add_format_argument(parser)
    args = parser.parse_args(argv)
    project = _require_project(manager)
    db_path = project.db_path
    cfg = passive_db.get_config(db_path)

    docs = passive_db.count_documents(db_path, project.id)
    dets = passive_db.count_detections(db_path, project.id)
    dets_finding = passive_db.count_detections(
        db_path, project.id, has_finding=True
    )
    pending = passive_db.count_documents(
        db_path, project.id, scan_status="pending"
    )
    scanned = passive_db.count_documents(
        db_path, project.id, scan_status="scanned"
    )

    payload = {
        "enabled": cfg.enabled,
        "auto_finding_threshold": cfg.auto_finding_threshold,
        "scanner_version": SCANNER_VERSION,
        "documents": docs,
        "documents_scanned": scanned,
        "documents_pending": pending,
        "detections": dets,
        "detections_with_finding": dets_finding,
        "queue_maxsize": cfg.queue_maxsize,
    }
    if wants_json(args):
        cli_json(payload)
        return

    print(f"Passive scan status — project={project.id}")
    print(f"  enabled:                 {cfg.enabled}")
    print(f"  auto_finding_threshold:  {cfg.auto_finding_threshold}")
    print(f"  scanner_version:         {SCANNER_VERSION}")
    print(f"  documents:               {docs} (scanned={scanned}, pending={pending})")
    print(f"  detections:              {dets} (with finding={dets_finding})")
    print(f"  queue_maxsize:           {cfg.queue_maxsize}")


# ------------------------------------------------------------------ #
# config                                                               #
# ------------------------------------------------------------------ #

_CONFIG_KEYS = frozenset({
    "enabled",
    "auto_finding_threshold",
    "max_document_size",
    "max_decode_depth",
    "max_decode_bytes",
    "max_candidates_per_document",
    "scan_html",
    "scan_javascript",
    "scan_json",
    "scan_xml",
    "scan_text",
    "scan_css",
    "scan_sourcemaps",
    "scan_wasm",
    "store_raw_secret_in_evidence",
    "store_suppressed_detections",
    "queue_maxsize",
})


def _cmd_config(manager: ProjectManager, argv: list[str]) -> None:
    if not argv or argv[0] in ("--help", "-h"):
        print(
            "talos passive config show\n"
            "talos passive config set <key> <value>\n\n"
            f"Keys: {', '.join(sorted(_CONFIG_KEYS))}\n"
        )
        sys.exit(0)

    action = argv[0]
    rest = argv[1:]
    project = _require_project(manager)

    if action == "show":
        parser = argparse.ArgumentParser(
            prog="talos passive config show", add_help=True
        )
        add_format_argument(parser)
        args = parser.parse_args(rest)
        cfg = passive_db.get_config(project.db_path)
        data = cfg.to_dict()
        if wants_json(args):
            cli_json(data)
            return
        for key in sorted(data.keys()):
            print(f"  {key}: {data[key]}")
        return

    if action == "set":
        if len(rest) < 2:
            cli_usage_error("Usage: talos passive config set <key> <value>")
        key = rest[0]
        value = rest[1]
        if key not in _CONFIG_KEYS:
            cli_error(
                f"Unknown config key '{key}'. "
                f"Known: {', '.join(sorted(_CONFIG_KEYS))}"
            )
        cfg = passive_db.get_config(project.db_path)
        parsed = _parse_config_value(key, value)
        updated = merge_config(cfg, {key: parsed})
        passive_db.update_config(project.db_path, updated)
        print(f"Updated passive config {key} = {getattr(updated, key)}")
        return

    cli_error(f"Unknown config action '{action}'. Use show|set.")


def _parse_config_value(key: str, value: str) -> Any:
    """Coerce CLI string to config field type."""
    if key in {
        "enabled",
        "scan_html",
        "scan_javascript",
        "scan_json",
        "scan_xml",
        "scan_text",
        "scan_css",
        "scan_sourcemaps",
        "scan_wasm",
        "store_raw_secret_in_evidence",
        "store_suppressed_detections",
    }:
        low = value.strip().lower()
        if low in ("1", "true", "yes", "on"):
            return True
        if low in ("0", "false", "no", "off"):
            return False
        cli_usage_error(f"Boolean expected for {key}, got {value!r}")
    if key in {
        "max_document_size",
        "max_decode_depth",
        "max_decode_bytes",
        "max_candidates_per_document",
        "queue_maxsize",
    }:
        try:
            return int(value)
        except ValueError:
            cli_usage_error(f"Integer expected for {key}, got {value!r}")
    return value


# ------------------------------------------------------------------ #
# rules                                                                #
# ------------------------------------------------------------------ #

def _cmd_rules(manager: ProjectManager, argv: list[str]) -> None:
    if not argv or argv[0] in ("--help", "-h"):
        print("talos passive rules list\n")
        sys.exit(0)
    if argv[0] != "list":
        cli_error("Usage: talos passive rules list")

    parser = argparse.ArgumentParser(prog="talos passive rules list", add_help=True)
    add_format_argument(parser)
    args = parser.parse_args(argv[1:])
    # Ensure project context exists (rules are package-local but CLI is project-scoped)
    _require_project(manager)

    index = load_rule_packs()
    rows = [
        {
            "id": r.id,
            "name": r.name,
            "family": r.family,
            "secret_type": r.secret_type,
            "confidence_level": r.confidence_level,
            "enabled": r.enabled,
            "pack": r.pack,
            "finding_title": r.finding_title or "",
        }
        for r in index.all_rules
    ]
    if wants_json(args):
        cli_json({"rules": rows, "load_errors": index.load_errors})
        return
    if not rows:
        print("No rules loaded.")
        if index.load_errors:
            print("Load errors:")
            for pack, msg in index.load_errors:
                print(f"  {pack}: {msg}")
        return
    print(f"{'ID':<28} {'LEVEL':<20} {'PACK':<22} NAME")
    for r in rows:
        print(
            f"{r['id']:<28} {r['confidence_level']:<20} "
            f"{r['pack']:<22} {r['name']}"
        )
    if index.load_errors:
        print("\nLoad errors:")
        for pack, msg in index.load_errors:
            print(f"  {pack}: {msg}")


# ------------------------------------------------------------------ #
# documents                                                            #
# ------------------------------------------------------------------ #

def _cmd_documents(manager: ProjectManager, argv: list[str]) -> None:
    if not argv or argv[0] in ("--help", "-h"):
        print(
            "talos passive documents list [--status STATUS] [--kind KIND]\n"
            "talos passive documents show <document_id>\n"
        )
        sys.exit(0)

    action = argv[0]
    rest = argv[1:]
    project = _require_project(manager)

    if action == "list":
        parser = argparse.ArgumentParser(
            prog="talos passive documents list", add_help=True
        )
        parser.add_argument("--status", default=None)
        parser.add_argument("--kind", default=None)
        parser.add_argument("--limit", type=int, default=50)
        add_format_argument(parser)
        args = parser.parse_args(rest)
        docs = passive_db.list_documents(
            project.db_path,
            project.id,
            scan_status=args.status,
            source_kind=args.kind,
            limit=args.limit,
        )
        rows = [_document_row(d) for d in docs]
        if wants_json(args):
            cli_json({"documents": rows})
            return
        if not rows:
            print("No source documents.")
            return
        print(
            f"{'ID':<10} {'KIND':<12} {'STATUS':<12} "
            f"{'SIZE':>8} HASH"
        )
        for r in rows:
            print(
                f"{r['id'][:8]:<10} {r['source_kind']:<12} "
                f"{r['scan_status']:<12} {r['body_size']:>8} "
                f"{r['body_hash'][:16]}…"
            )
        return

    if action == "show":
        if not rest:
            cli_usage_error("Usage: talos passive documents show <document_id>")
        doc_id = rest[0]
        parser = argparse.ArgumentParser(
            prog="talos passive documents show", add_help=True
        )
        add_format_argument(parser)
        args = parser.parse_args(rest[1:])
        doc = passive_db.get_document(project.db_path, doc_id)
        if doc is None and len(doc_id) >= 8:
            # Allow short id prefix match
            all_docs = passive_db.list_documents(
                project.db_path, project.id, limit=500
            )
            matches = [d for d in all_docs if d.id.startswith(doc_id)]
            doc = matches[0] if len(matches) == 1 else None
        if doc is None:
            cli_error(f"Document not found: {doc_id}")
        occs = passive_db.list_occurrences(project.db_path, doc.id, limit=20)
        dets = passive_db.list_detections(
            project.db_path, document_id=doc.id, limit=50
        )
        payload = {
            "document": _document_row(doc),
            "occurrences": [
                {
                    "id": o.id,
                    "flow_id": o.flow_id,
                    "url": o.url,
                    "path": o.path,
                    "observed_at": o.observed_at,
                }
                for o in occs
            ],
            "detections": [_detection_row(d) for d in dets],
        }
        if wants_json(args):
            cli_json(payload)
            return
        d = payload["document"]
        print(f"Document {d['id']}")
        for k, v in d.items():
            if k == "id":
                continue
            print(f"  {k}: {v}")
        print(f"Occurrences ({len(payload['occurrences'])}):")
        for o in payload["occurrences"]:
            print(f"  - {o['path']}  flow={o['flow_id'][:8]}")
        print(f"Detections ({len(payload['detections'])}):")
        for det in payload["detections"]:
            print(
                f"  - {det['detector_id']} {det['confidence_level']} "
                f"{det['redacted_value']}"
            )
        return

    cli_error(f"Unknown documents action '{action}'. Use list|show.")


def _document_row(doc) -> dict[str, Any]:
    return {
        "id": doc.id,
        "project_id": doc.project_id,
        "body_hash": doc.body_hash,
        "source_kind": doc.source_kind.value
        if isinstance(doc.source_kind, SourceKind)
        else str(doc.source_kind),
        "body_size": doc.body_size,
        "truncated": doc.truncated,
        "scanner_version": doc.scanner_version,
        "scan_status": doc.scan_status,
        "first_flow_id": doc.first_flow_id,
        "parent_document_id": doc.parent_document_id,
        "logical_source_name": doc.logical_source_name,
        "first_seen": doc.first_seen,
        "last_seen": doc.last_seen,
        "last_scanned_at": doc.last_scanned_at,
    }


# ------------------------------------------------------------------ #
# detections                                                           #
# ------------------------------------------------------------------ #

def _cmd_detections(manager: ProjectManager, argv: list[str]) -> None:
    if not argv or argv[0] in ("--help", "-h"):
        print(
            "talos passive detections list "
            "[--type TYPE] [--confidence LEVEL] [--category CAT] "
            "[--document ID] [--suppressed] [--has-finding]\n"
            "talos passive detections show <detection_id>\n"
        )
        sys.exit(0)

    action = argv[0]
    rest = argv[1:]
    project = _require_project(manager)

    if action == "list":
        parser = argparse.ArgumentParser(
            prog="talos passive detections list", add_help=True
        )
        parser.add_argument("--type", dest="secret_type", default=None)
        parser.add_argument("--confidence", default=None)
        parser.add_argument(
            "--category",
            default=None,
            help="secret | infrastructure_disclosure | sensitive_info",
        )
        parser.add_argument("--document", default=None)
        parser.add_argument(
            "--suppressed",
            action="store_true",
            help="Include only suppressed detections",
        )
        parser.add_argument(
            "--has-finding",
            action="store_true",
            help="Only detections linked to a finding",
        )
        parser.add_argument("--limit", type=int, default=50)
        add_format_argument(parser)
        args = parser.parse_args(rest)

        dets = passive_db.list_detections(
            project.db_path,
            project_id=project.id,
            document_id=args.document,
            confidence_level=args.confidence,
            category=args.category,
            suppressed=True if args.suppressed else False,
            has_finding=True if args.has_finding else None,
            limit=args.limit,
        )
        if args.secret_type:
            dets = [
                d for d in dets
                if (d.secret_type or "") == args.secret_type
                or d.detector_id == args.secret_type
            ]
        rows = [_detection_row(d) for d in dets]
        if wants_json(args):
            cli_json({"detections": rows})
            return
        if not rows:
            print("No detections.")
            return
        print(
            f"{'ID':<10} {'DETECTOR':<24} {'LEVEL':<18} "
            f"{'FINDING':<8} VALUE"
        )
        for r in rows:
            fid = (r["finding_id"] or "")[:8] or "-"
            print(
                f"{r['id'][:8]:<10} {r['detector_id']:<24} "
                f"{r['confidence_level']:<18} {fid:<8} "
                f"{r['redacted_value']}"
            )
        return

    if action == "show":
        if not rest:
            cli_usage_error(
                "Usage: talos passive detections show <detection_id>"
            )
        det_id = rest[0]
        parser = argparse.ArgumentParser(
            prog="talos passive detections show", add_help=True
        )
        add_format_argument(parser)
        args = parser.parse_args(rest[1:])
        det = passive_db.get_detection(project.db_path, det_id)
        if det is None and len(det_id) >= 8:
            all_d = passive_db.list_detections(
                project.db_path, project_id=project.id, limit=500
            )
            matches = [d for d in all_d if d.id.startswith(det_id)]
            det = matches[0] if len(matches) == 1 else None
        if det is None:
            cli_error(f"Detection not found: {det_id}")
        row = _detection_row(det)
        if wants_json(args):
            cli_json(row)
            return
        print(f"Detection {row['id']}")
        for k, v in row.items():
            if k == "id":
                continue
            print(f"  {k}: {v}")
        return

    cli_error(f"Unknown detections action '{action}'. Use list|show.")


def _detection_row(det: Detection) -> dict[str, Any]:
    return {
        "id": det.id,
        "document_id": det.document_id,
        "occurrence_id": det.occurrence_id,
        "detector_id": det.detector_id,
        "detector_family": det.detector_family,
        "category": det.category,
        "secret_type": det.secret_type,
        "matched_key": det.matched_key,
        "redacted_value": det.redacted_value,
        "value_fingerprint": det.value_fingerprint,
        "confidence_score": det.confidence_score,
        "confidence_level": det.confidence_level,
        "entropy": det.entropy,
        "encoding_chain": list(det.encoding_chain or []),
        "decode_depth": det.decode_depth,
        "suppressed": det.suppressed,
        "suppression_reason": det.suppression_reason,
        "finding_id": det.finding_id,
        "created_at": det.created_at,
    }


# ------------------------------------------------------------------ #
# rescan                                                               #
# ------------------------------------------------------------------ #

def _cmd_rescan(manager: ProjectManager, argv: list[str]) -> None:
    parser = argparse.ArgumentParser(prog="talos passive rescan", add_help=True)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--all",
        action="store_true",
        help="Rescan documents where scanner_version != current",
    )
    group.add_argument("--document", metavar="ID", help="Rescan one document")
    group.add_argument("--flow", metavar="ID", help="Rescan body from a flow")
    parser.add_argument(
        "--force",
        action="store_true",
        help="Rescan even when already at current SCANNER_VERSION",
    )
    args = parser.parse_args(argv)
    project = _require_project(manager)
    db_path = project.db_path
    config = passive_db.get_config(db_path)
    orch = DetectorOrchestrator(config=config)

    targets: list[tuple[str, Optional[str]]] = []
    # (document_id, preferred_flow_id)

    if args.document:
        doc = passive_db.get_document(db_path, args.document)
        if doc is None:
            cli_error(f"Document not found: {args.document}")
        targets.append((doc.id, doc.first_flow_id))
    elif args.flow:
        doc_id = _document_id_for_flow(db_path, args.flow)
        if doc_id:
            targets.append((doc_id, args.flow))
        else:
            # Scan flow body even if not yet registered
            n = _rescan_flow_body(
                db_path, project.id, args.flow, config, orch
            )
            print(f"Rescanned flow {args.flow[:8]}… → {n} detections stored")
            return
    else:
        docs = passive_db.list_documents(db_path, project.id, limit=5000)
        for d in docs:
            if d.parent_document_id:
                # Virtual docs rescanned via parent map
                continue
            if args.force or d.scanner_version != SCANNER_VERSION:
                targets.append((d.id, d.first_flow_id))

    if not targets:
        print("Nothing to rescan.")
        return

    total_dets = 0
    total_findings = 0
    for doc_id, flow_id in targets:
        n_d, n_f = _rescan_document(
            db_path,
            project.id,
            doc_id,
            preferred_flow_id=flow_id,
            config=config,
            orch=orch,
            force=args.force,
        )
        total_dets += n_d
        total_findings += n_f

    print(
        f"Rescan complete — documents={len(targets)} "
        f"detections_upserted={total_dets} findings={total_findings}"
    )


def _document_id_for_flow(db_path: Path, flow_id: str) -> Optional[str]:
    """Find a source_documents id linked via occurrence flow_id."""
    with sqlite3.connect(str(db_path)) as conn:
        row = conn.execute(
            """
            SELECT document_id FROM source_occurrences
            WHERE flow_id = ?
            ORDER BY observed_at DESC LIMIT 1
            """,
            (flow_id,),
        ).fetchone()
    return str(row[0]) if row else None


def _load_flow_body(db_path: Path, flow_id: str) -> Optional[bytes]:
    if not flow_id:
        return None
    try:
        with sqlite3.connect(str(db_path)) as conn:
            row = conn.execute(
                "SELECT response_body FROM flows WHERE id = ?",
                (flow_id,),
            ).fetchone()
    except sqlite3.Error:
        return None
    if row is None or row[0] is None:
        return None
    body = row[0]
    if isinstance(body, memoryview):
        return body.tobytes()
    if isinstance(body, bytes):
        return body
    if isinstance(body, str):
        return body.encode("utf-8", errors="replace")
    return bytes(body)


def _rescan_document(
    db_path: Path,
    project_id: str,
    document_id: str,
    *,
    preferred_flow_id: Optional[str],
    config: PassiveScanConfig,
    orch: DetectorOrchestrator,
    force: bool,
) -> tuple[int, int]:
    """
    Purpose:
        Reload body from an occurrence flow, re-run detectors, findings.
    Output:
        (detections_stored, findings_created)
    """
    doc = passive_db.get_document(db_path, document_id)
    if doc is None:
        return 0, 0

    flow_id = preferred_flow_id or doc.first_flow_id
    if not flow_id:
        occs = passive_db.list_occurrences(db_path, document_id, limit=1)
        flow_id = occs[0].flow_id if occs else None
    if not flow_id:
        return 0, 0

    body = _load_flow_body(db_path, flow_id)
    if body is None:
        return 0, 0

    if not force and doc.scanner_version == SCANNER_VERSION:
        # Still allow if caller forced list inclusion
        pass

    passive_db.reset_document_for_rescan(db_path, document_id)
    norm = normalize_body(body)
    text = norm.text or ""

    detections = orch.scan_text(
        text,
        document_id=document_id,
        occurrence_id=None,
    )
    # Attach best occurrence for findings evidence
    occs = passive_db.list_occurrences(db_path, document_id, limit=1)
    occ_id = occs[0].id if occs else None

    stored: list[Detection] = []
    for det in detections:
        det.occurrence_id = det.occurrence_id or occ_id
        raw = det.raw_value
        row = passive_db.insert_detection(db_path, det)
        if row is None:
            continue
        if raw and not row.raw_value:
            row.raw_value = raw
        stored.append(row)

    # Source map virtuals
    if config.scan_sourcemaps and (
        doc.source_kind == SourceKind.SOURCEMAP
        or path_looks_like_sourcemap(
            (occs[0].path if occs else "") or "",
            (occs[0].content_type if occs else "") or "",
        )
    ):
        virtuals = extract_sourcemap_virtual_docs(
            text,
            parent_document_id=document_id,
            project_id=project_id,
        )
        for virt in virtuals:
            _rescan_virtual_child(
                db_path,
                project_id,
                parent_document_id=document_id,
                virt=virt,
                flow_id=flow_id,
                occ_id=occ_id,
                orch=orch,
                stored=stored,
            )

    # HTML inline script / bootstrap virtuals (Phase 11)
    if doc.source_kind == SourceKind.HTML and config.scan_html:
        html_virtuals = extract_html_virtual_docs(
            text,
            parent_document_id=document_id,
            project_id=project_id,
        )
        for virt in html_virtuals:
            _rescan_virtual_child(
                db_path,
                project_id,
                parent_document_id=document_id,
                virt=virt,
                flow_id=flow_id,
                occ_id=occ_id,
                orch=orch,
                stored=stored,
            )

    n_findings = maybe_create_findings_for_detections(
        db_path, project_id, stored, config=config
    )
    passive_db.mark_document_scanned(db_path, document_id, SCANNER_VERSION)
    return len(stored), n_findings


def _rescan_virtual_child(
    db_path: Path,
    project_id: str,
    *,
    parent_document_id: str,
    virt,
    flow_id: Optional[str],
    occ_id: Optional[str],
    orch: DetectorOrchestrator,
    stored: list[Detection],
) -> None:
    """
    Purpose:
        Upsert + re-scan one virtual child document during rescan.
    Side effects:
        Writes document/detection rows; appends to stored.
    """
    vbytes = (virt.text or "").encode("utf-8", errors="replace")
    vhash = hashlib.sha256(vbytes).hexdigest()
    vdoc, _ = passive_db.upsert_document(
        db_path,
        project_id,
        vhash,
        virt.source_kind,
        len(vbytes),
        first_flow_id=flow_id,
        parent_document_id=parent_document_id,
        logical_source_name=virt.logical_source_name,
    )
    passive_db.reset_document_for_rescan(db_path, vdoc.id)
    vdets = orch.scan_text(
        virt.text or "",
        document_id=vdoc.id,
        occurrence_id=occ_id,
    )
    for det in vdets:
        raw = det.raw_value
        row = passive_db.insert_detection(db_path, det)
        if row is None:
            continue
        if raw and not row.raw_value:
            row.raw_value = raw
        stored.append(row)
    passive_db.mark_document_scanned(db_path, vdoc.id, SCANNER_VERSION)


def _rescan_flow_body(
    db_path: Path,
    project_id: str,
    flow_id: str,
    config: PassiveScanConfig,
    orch: DetectorOrchestrator,
) -> int:
    """Register + scan a flow that has no document yet. Returns detection count."""
    body = _load_flow_body(db_path, flow_id)
    if body is None:
        cli_error(f"Flow body not found: {flow_id}")
    body_hash = hashlib.sha256(body).hexdigest()
    doc, _ = passive_db.upsert_document(
        db_path,
        project_id,
        body_hash,
        SourceKind.JAVASCRIPT,
        len(body),
        first_flow_id=flow_id,
    )
    n, _ = _rescan_document(
        db_path,
        project_id,
        doc.id,
        preferred_flow_id=flow_id,
        config=config,
        orch=orch,
        force=True,
    )
    return n
