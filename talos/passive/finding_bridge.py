"""
Module: talos.passive.finding_bridge

Purpose:
    Create Findings from high-confidence passive secret detections.

    The Findings subsystem remains the owner of finding lifecycle
    (status, PRIMARY/LINKED, evidence, timeline).  This bridge only:

        1. Decides eligibility (threshold, suppressed, already linked)
        2. Supplies cluster_key = PASSIVE_SECRET:<value_fingerprint>
        3. Calls findings_db.create_finding + evidence + timeline
        4. Sets passive_detections.finding_id via link_detection_finding

    Does **not** use endpoint-centric build_cluster_key — secrets cluster
    by fingerprint so the same key in two files becomes PRIMARY then LINKED.

Dependencies:
    logging, pathlib
    talos.findings.db, talos.findings.model
    talos.passive.{constants, config, db, models, rules_loader}
Data flow:
    SourceScanWorker (after insert_detection)
        → maybe_create_findings_for_detections / create_passive_secret_finding
        → findings tables + passive_detections.finding_id
Side effects:
    Writes findings / evidence / timeline; updates passive_detections.finding_id.
    Never raises into the scan worker loop (callers wrap or use maybe_*).
"""

from __future__ import annotations

import logging
import sqlite3
from pathlib import Path
from typing import Optional

import talos.findings.db as findings_db
from talos.findings.model import (
    ATTACK_DISPLAY,
    EVIDENCE_TYPE_ENDPOINT,
    EVIDENCE_TYPE_MODULE,
    EVIDENCE_TYPE_ORIGINAL_FLOW,
    EVIDENCE_TYPE_PASSIVE_DETECTION,
    EVIDENCE_TYPE_ROLE,
    EVIDENCE_TYPE_SOURCE_DOCUMENT,
    EVIDENCE_TYPE_SOURCE_OCCURRENCE,
    RELATION_TYPE_LINKED,
    RELATION_TYPE_PRIMARY,
    TIMELINE_ACTOR_SYSTEM,
)
from talos.passive import db as passive_db
from talos.passive.config import PassiveScanConfig
from talos.passive.constants import (
    ATTACK_TYPE_PASSIVE_SECRET,
    CATEGORY_SECRET,
    CLUSTER_KEY_PREFIX_PASSIVE_SECRET,
    VERDICT_EXPOSED,
)
from talos.passive.models import Detection
from talos.passive.rules_loader import get_rule_index

logger = logging.getLogger(__name__)

# Default titles when rule pack has no finding_title
_DEFAULT_TITLE_BY_SECRET_TYPE: dict[str, str] = {
    "aws_access_key": "Exposed AWS Access Key ID",
    "google_api_key": "Exposed Google API Key (Unverified)",
    "github_pat": "Exposed GitHub Personal Access Token",
    "stripe_secret": "Exposed Stripe Secret Key",
    "stripe_secret_key": "Exposed Stripe Secret Key",
    "private_key": "Exposed Private Key (PEM/OpenSSH)",
    "private_key_pem": "Exposed Private Key (PEM/OpenSSH)",
    "bearer_token": "Exposed Bearer Token",
    "jwt": "Exposed JWT (Unverified)",
    "connection_string": "Exposed Database Connection String",
    "slack_token": "Exposed Slack Token",
    "slack_webhook": "Exposed Slack Webhook URL",
    "sendgrid_api_key": "Exposed SendGrid API Key",
    "twilio_api_key": "Exposed Twilio API Key",
    "generic_secret": "Exposed Client-Side Secret",
}


def build_passive_secret_cluster_key(value_fingerprint: str) -> str:
    """
    Purpose:
        Build the stable cluster identity for a secret fingerprint.
    Input:
        value_fingerprint — SHA-256 hex from fingerprint_secret()
    Output:
        ``PASSIVE_SECRET:<fingerprint>``
    Side effects: None.
    """
    fp = (value_fingerprint or "").strip().lower()
    return f"{CLUSTER_KEY_PREFIX_PASSIVE_SECRET}:{fp}"


def finding_title_for_detection(
    detection: Detection,
    *,
    in_source_map: bool = False,
) -> str:
    """
    Purpose:
        Human-readable finding title from rule metadata or secret_type.
    Input:
        detection     — Detection with detector_id / secret_type
        in_source_map — append source-map qualifier when True
    Output:
        Title string
    Side effects:
        May load rule index once (cached) to resolve finding_title.
    """
    title = ""
    try:
        index = get_rule_index()
        for rule in index.all_rules:
            if rule.id == detection.detector_id and rule.finding_title:
                title = rule.finding_title
                break
    except Exception:  # noqa: BLE001
        title = ""

    if not title:
        st = (detection.secret_type or "").lower()
        title = _DEFAULT_TITLE_BY_SECRET_TYPE.get(
            st,
            f"Exposed Client-Side Secret ({detection.detector_id or 'unknown'})",
        )

    if in_source_map and "source map" not in title.lower():
        title = f"{title} in Source Map"
    return title


def create_passive_secret_finding(
    db_path: Path,
    project_id: str,
    detection_id: str,
    *,
    config: Optional[PassiveScanConfig] = None,
    raw_value: Optional[str] = None,
    title_override: Optional[str] = None,
) -> Optional[str]:
    """
    Purpose:
        Create (or link) a Finding for one passive detection when eligible.

    Eligibility:
        - detection exists
        - not suppressed
        - category is secret (v1)
        - confidence ≥ config.auto_finding_threshold
        - finding_id not already set

    Clustering:
        cluster_key = PASSIVE_SECRET:<value_fingerprint>
        First sighting → PRIMARY; same secret again → LINKED.

    Input:
        db_path / project_id / detection_id
        config         — PassiveScanConfig (loaded if None)
        raw_value      — optional secret for evidence when store_raw is on
        title_override — optional full title (e.g. source-map suffix)

    Output:
        Finding UUID if created/linked, None if skipped or on soft error.

    Side effects:
        Inserts finding + evidence + timeline; updates detection.finding_id.
    """
    cfg = config if config is not None else passive_db.get_config(db_path)
    detection = passive_db.get_detection(db_path, detection_id)
    if detection is None:
        logger.debug(
            "Passive finding bridge skip — detection not found id=%s",
            detection_id,
        )
        return None

    if detection.finding_id:
        return detection.finding_id

    if detection.suppressed:
        logger.debug(
            "Passive finding bridge skip — suppressed detection_id=%s reason=%s",
            detection_id,
            detection.suppression_reason,
        )
        return None

    if (detection.category or CATEGORY_SECRET) != CATEGORY_SECRET:
        # Infrastructure / disclosures stay observation-only in v1.
        return None

    if not cfg.is_finding_eligible(detection.confidence_level):
        logger.debug(
            "Passive finding bridge skip — below threshold detection_id=%s "
            "level=%s threshold=%s",
            detection_id,
            detection.confidence_level,
            cfg.auto_finding_threshold,
        )
        return None

    if not detection.value_fingerprint:
        logger.warning(
            "Passive finding bridge skip — empty fingerprint detection_id=%s",
            detection_id,
        )
        return None

    document = passive_db.get_document(db_path, detection.document_id)
    occurrence = None
    if detection.occurrence_id:
        occurrence = passive_db.get_occurrence(db_path, detection.occurrence_id)
    if occurrence is None and document is not None:
        occs = passive_db.list_occurrences(db_path, document.id, limit=1)
        occurrence = occs[0] if occs else None

    in_source_map = False
    in_inline_html = False
    if document is not None:
        if document.source_kind.value == "sourcemap":
            in_source_map = True
        elif document.parent_document_id:
            parent = passive_db.get_document(db_path, document.parent_document_id)
            if parent is not None:
                if parent.source_kind.value == "sourcemap":
                    in_source_map = True
                elif parent.source_kind.value == "html":
                    in_inline_html = True

    title = title_override or finding_title_for_detection(
        detection, in_source_map=in_source_map
    )
    if in_inline_html and "inline" not in title.lower() and "html" not in title.lower():
        title = f"{title} (Inline HTML)"
    cluster_key = build_passive_secret_cluster_key(detection.value_fingerprint)
    endpoint_id = occurrence.endpoint_id if occurrence else None

    try:
        finding_id = findings_db.create_finding(
            db_path=db_path,
            project_id=project_id,
            attack_type=ATTACK_TYPE_PASSIVE_SECRET,
            verdict=VERDICT_EXPOSED,
            endpoint_id=endpoint_id,
            title=title,
            cluster_key=cluster_key,
        )
    except Exception as exc:  # noqa: BLE001
        logger.error(
            "Passive finding create failed — detection_id=%s: %s",
            detection_id,
            exc,
        )
        return None

    created = findings_db.get_finding(db_path, finding_id)
    relation_type = (created or {}).get("relation_type", RELATION_TYPE_PRIMARY)
    parent_finding_id = (created or {}).get("parent_finding_id")

    _attach_passive_evidence(
        db_path=db_path,
        finding_id=finding_id,
        detection=detection,
        document=document,
        occurrence=occurrence,
        raw_value=raw_value,
        store_raw=bool(cfg.store_raw_secret_in_evidence),
    )

    _write_passive_timeline(
        db_path=db_path,
        finding_id=finding_id,
        detection=detection,
        document=document,
        occurrence=occurrence,
        relation_type=relation_type,
        parent_finding_id=parent_finding_id,
        cluster_key=cluster_key,
        title=title,
    )

    try:
        passive_db.link_detection_finding(db_path, detection_id, finding_id)
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "Passive finding link failed (finding exists) — "
            "detection_id=%s finding_id=%s: %s",
            detection_id,
            finding_id,
            exc,
        )

    logger.info(
        "Passive finding %s — detection=%s relation=%s secret_type=%s",
        finding_id[:8],
        detection_id[:8],
        relation_type,
        detection.secret_type,
    )
    return finding_id


def maybe_create_findings_for_detections(
    db_path: Path,
    project_id: str,
    detections: list[Detection],
    *,
    config: Optional[PassiveScanConfig] = None,
) -> int:
    """
    Purpose:
        After a scan, create findings for each eligible Detection.
        Uses in-memory Detection (may carry raw_value) and the stored id.

    Input:
        db_path / project_id
        detections — list returned from insert path (with ids + optional raw)
        config     — PassiveScanConfig

    Output:
        Number of findings created or linked this call.

    Side effects:
        Calls create_passive_secret_finding for each candidate; never raises.
    """
    cfg = config if config is not None else passive_db.get_config(db_path)
    created = 0
    for det in detections:
        if not det.id:
            continue
        if det.suppressed or det.finding_id:
            continue
        try:
            fid = create_passive_secret_finding(
                db_path,
                project_id,
                det.id,
                config=cfg,
                raw_value=det.raw_value,
            )
            if fid:
                created += 1
                det.finding_id = fid
        except Exception:
            logger.exception(
                "Passive finding bridge error — detection_id=%s",
                det.id,
            )
    return created


# ------------------------------------------------------------------ #
# Evidence + timeline helpers                                          #
# ------------------------------------------------------------------ #

def _attach_passive_evidence(
    *,
    db_path: Path,
    finding_id: str,
    detection: Detection,
    document,
    occurrence,
    raw_value: Optional[str],
    store_raw: bool,
) -> None:
    """
    Purpose:
        Attach passive-specific + shared evidence rows to a finding.
    Side effects:
        Inserts finding_evidence rows; swallows per-item errors.
    """
    def _add(
        evidence_type: str,
        reference_id: Optional[str],
        label: str,
        data: Optional[dict] = None,
    ) -> None:
        try:
            findings_db.add_evidence(
                db_path=db_path,
                finding_id=finding_id,
                evidence_type=evidence_type,
                reference_id=reference_id,
                label=label,
                data=data,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "Passive evidence attach failed type=%s: %s",
                evidence_type,
                exc,
            )

    det_data: dict = {
        "detector_id": detection.detector_id,
        "detector_family": detection.detector_family,
        "secret_type": detection.secret_type,
        "matched_key": detection.matched_key,
        "redacted_value": detection.redacted_value,
        "value_fingerprint": detection.value_fingerprint,
        "confidence_score": detection.confidence_score,
        "confidence_level": detection.confidence_level,
        "entropy": detection.entropy,
        "encoding_chain": list(detection.encoding_chain or []),
        "decode_depth": detection.decode_depth,
        "match_start": detection.match_start,
        "match_end": detection.match_end,
    }
    if store_raw and raw_value:
        det_data["raw_value"] = raw_value
        det_data["raw_value_stored"] = True

    _add(
        EVIDENCE_TYPE_PASSIVE_DETECTION,
        detection.id,
        f"Passive detection — {detection.detector_id} "
        f"({detection.confidence_level})",
        det_data,
    )

    if document is not None:
        _add(
            EVIDENCE_TYPE_SOURCE_DOCUMENT,
            document.id,
            f"Source document — {document.source_kind.value} "
            f"hash={document.body_hash[:12]}…",
            {
                "body_hash": document.body_hash,
                "source_kind": document.source_kind.value,
                "body_size": document.body_size,
                "truncated": document.truncated,
                "parent_document_id": document.parent_document_id,
                "scanner_version": document.scanner_version,
            },
        )

    if occurrence is not None:
        _add(
            EVIDENCE_TYPE_SOURCE_OCCURRENCE,
            occurrence.id,
            f"Source occurrence — {occurrence.path or occurrence.url}",
            {
                "url": occurrence.url,
                "host": occurrence.host,
                "path": occurrence.path,
                "logical_source_name": occurrence.logical_source_name,
                "content_type": occurrence.content_type,
                "observed_at": occurrence.observed_at,
                "flow_id": occurrence.flow_id,
            },
        )
        if occurrence.flow_id:
            _add(
                EVIDENCE_TYPE_ORIGINAL_FLOW,
                occurrence.flow_id,
                f"Original capture flow — {occurrence.flow_id[:8]}",
                {"flow_id": occurrence.flow_id, "url": occurrence.url},
            )
        if occurrence.endpoint_id:
            _add(
                EVIDENCE_TYPE_ENDPOINT,
                occurrence.endpoint_id,
                f"Endpoint — {occurrence.endpoint_id[:8]}",
                {"endpoint_id": occurrence.endpoint_id},
            )
        if occurrence.role_id:
            role_name = _fetch_name(db_path, "roles", occurrence.role_id)
            _add(
                EVIDENCE_TYPE_ROLE,
                occurrence.role_id,
                f"Role — {role_name or occurrence.role_id[:8]}",
                {"role_id": occurrence.role_id, "name": role_name},
            )
        if occurrence.module_id:
            module_name = _fetch_name(db_path, "modules", occurrence.module_id)
            _add(
                EVIDENCE_TYPE_MODULE,
                occurrence.module_id,
                f"Module — {module_name or occurrence.module_id[:8]}",
                {"module_id": occurrence.module_id, "name": module_name},
            )


def _write_passive_timeline(
    *,
    db_path: Path,
    finding_id: str,
    detection: Detection,
    document,
    occurrence,
    relation_type: str,
    parent_finding_id: Optional[str],
    cluster_key: str,
    title: str,
) -> None:
    """
    Purpose:
        Reconstruct timeline: capture → scan → finding created.
    Side effects:
        Inserts finding_timeline events; non-fatal on errors.
    """
    attack_label = ATTACK_DISPLAY.get(
        ATTACK_TYPE_PASSIVE_SECRET, "Client-Side Secret Exposure"
    )
    try:
        observed = (occurrence.observed_at if occurrence else None) or (
            document.first_seen if document else None
        )
        if observed:
            findings_db.add_timeline_event(
                db_path=db_path,
                finding_id=finding_id,
                event=(
                    "Source body first observed — "
                    f"{(occurrence.path if occurrence else None) or 'unknown path'}"
                ),
                actor=TIMELINE_ACTOR_SYSTEM,
                occurred_at=observed,
            )

        scanned_at = (
            (document.last_scanned_at if document else None)
            or detection.created_at
        )
        if scanned_at:
            findings_db.add_timeline_event(
                db_path=db_path,
                finding_id=finding_id,
                event=(
                    f"Passive scan detected {detection.detector_id} "
                    f"({detection.confidence_level}, score={detection.confidence_score})"
                ),
                actor=TIMELINE_ACTOR_SYSTEM,
                occurred_at=scanned_at,
            )

        relation_note = f" as {relation_type}"
        if relation_type == RELATION_TYPE_LINKED and parent_finding_id:
            relation_note += f" under PRIMARY {parent_finding_id}"
        relation_note += f" (cluster: {cluster_key[:40]}…)"

        findings_db.add_timeline_event(
            db_path=db_path,
            finding_id=finding_id,
            event=(
                f"Finding created{relation_note} — {attack_label}: {title} "
                f"(verdict {VERDICT_EXPOSED})"
            ),
            actor=TIMELINE_ACTOR_SYSTEM,
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "Passive timeline write error (non-fatal): %s",
            exc,
        )


def _fetch_name(db_path: Path, table: str, row_id: Optional[str]) -> Optional[str]:
    """Purpose: Fetch roles/modules.name by id. Side effects: short SQLite read."""
    if not row_id:
        return None
    if table not in ("roles", "modules"):
        return None
    try:
        with sqlite3.connect(str(db_path)) as conn:
            row = conn.execute(
                f"SELECT name FROM {table} WHERE id = ?",
                (row_id,),
            ).fetchone()
        return row[0] if row else None
    except Exception:  # noqa: BLE001
        return None
