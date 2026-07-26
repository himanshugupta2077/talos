"""
Module: talos.passive.detectors.orchestrator

Purpose:
    Run the multi-stage detector pipeline and produce scored, suppressed
    Detection objects ready for persistence.

    Stages:
        1. Specific provider patterns (YAML) + PEM + JWT + connection strings
        2. Contextual generic assignment
        3. Entropy (keyword/assignment gated)
        4. Decoder candidates
        5. Rescan decoded text with stages 1–2 only (no infinite decode loop)
        6. Infrastructure / disclosure observations (Phase 12; not auto-finding)
        7–8. Scoring + suppression (applied to all raw matches)

    Soft per-document scan time budget (Phase 14): when max_scan_time_ms > 0
    and elapsed time exceeds the budget mid-pipeline, remaining stages are
    skipped and a DEBUG log is emitted (partial results still scored).

    Never creates findings. Never creates “Base64 Found” detections.

Dependencies:
    detectors.{specific,pem,jwt,connection_string,contextual,entropy,
               infrastructure}, decoder.pipeline,
    scoring, suppress, redaction, models, config, rules_loader
Data flow:
    text | SourceDocument → scan_* → list[Detection]
Side effects:
    May load YAML rules on first use (via get_rule_index). No DB / HTTP.
"""

from __future__ import annotations

import logging
import time
import uuid
from typing import Optional

from talos.passive.config import PassiveScanConfig, default_config
from talos.passive.decoder.pipeline import (
    decode_candidate,
    extract_decode_candidates,
)
from talos.passive.detectors.connection_string import ConnectionStringDetector
from talos.passive.detectors.contextual import ContextualDetector
from talos.passive.detectors.entropy import EntropyDetector
from talos.passive.detectors.infrastructure import InfrastructureDetector
from talos.passive.detectors.jwt import JwtDetector
from talos.passive.detectors.pem import PemDetector
from talos.passive.detectors.specific import SpecificPatternDetector
from talos.passive.models import Detection, RawMatch, SourceDocument
from talos.passive.redaction import fingerprint_secret, redact_secret
from talos.passive.rules_loader import RuleIndex, get_rule_index
from talos.passive.scoring import score_match
from talos.passive.suppress import should_suppress

logger = logging.getLogger(__name__)


class DetectorOrchestrator:
    """
    Purpose:
        Own detector instances and run the full scan pipeline on text.

    Fields:
        config — PassiveScanConfig (size / depth / candidate / time caps)
        index  — RuleIndex
        specific / pem / jwt / connection / contextual / entropy / infra
    """

    def __init__(
        self,
        config: Optional[PassiveScanConfig] = None,
        index: Optional[RuleIndex] = None,
    ) -> None:
        self.config = config if config is not None else default_config()
        self.index = index if index is not None else get_rule_index()
        cap = max(1, int(self.config.max_candidates_per_document))
        self.specific = SpecificPatternDetector(self.index, max_candidates=cap)
        self.pem = PemDetector(max_candidates=min(50, cap))
        self.jwt = JwtDetector(max_candidates=min(50, cap))
        self.connection = ConnectionStringDetector(max_candidates=min(50, cap))
        self.contextual = ContextualDetector(self.index, max_candidates=cap)
        self.entropy = EntropyDetector(self.index, max_candidates=min(200, cap))
        self.infra = InfrastructureDetector(max_candidates=min(100, cap))

    def scan_text(
        self,
        text: str,
        *,
        document_id: str = "",
        occurrence_id: Optional[str] = None,
        document: Optional[SourceDocument] = None,
    ) -> list[Detection]:
        """
        Purpose:
            Run stages 1–8 on text and return Detection list.
        Input:
            text          — normalized scan text
            document_id   — source_documents.id for Detection rows
            occurrence_id — best occurrence for evidence
            document      — optional SourceDocument (uses .text if text empty)
        Output:
            list[Detection] (suppressed omitted unless store_suppressed)
        Side effects: None (pure relative to DB); may log soft timeout.
        """
        body = text if text is not None else ""
        if not body and document is not None and document.text:
            body = document.text
        if not body:
            return []

        cap = max(1, int(self.config.max_candidates_per_document))
        budget_ms = int(getattr(self.config, "max_scan_time_ms", 0) or 0)
        t0 = time.monotonic()
        raw_matches: list[RawMatch] = []

        def _over_budget() -> bool:
            if budget_ms <= 0:
                return False
            elapsed_ms = (time.monotonic() - t0) * 1000.0
            if elapsed_ms >= budget_ms:
                logger.debug(
                    "Passive scan soft timeout — document_id=%s elapsed_ms=%.0f "
                    "budget_ms=%d matches_so_far=%d",
                    document_id or (document.id if document else ""),
                    elapsed_ms,
                    budget_ms,
                    len(raw_matches),
                )
                return True
            return False

        # Stage 1 — specific + PEM + JWT + connection strings
        raw_matches.extend(self.specific.detect(body, document=document))
        if len(raw_matches) < cap and not _over_budget():
            raw_matches.extend(self.pem.detect(body, document=document))
        if len(raw_matches) < cap and not _over_budget():
            raw_matches.extend(self.jwt.detect(body, document=document))
        if len(raw_matches) < cap and not _over_budget():
            raw_matches.extend(self.connection.detect(body, document=document))

        # Stage 2 — contextual
        if len(raw_matches) < cap and not _over_budget():
            raw_matches.extend(self.contextual.detect(body, document=document))

        # Stage 3 — entropy
        if len(raw_matches) < cap and not _over_budget():
            raw_matches.extend(self.entropy.detect(body, document=document))

        # Stages 4–5 — decode candidates → rescan 1–2 only
        if len(raw_matches) < cap and not _over_budget():
            decoded_hits = self._decode_and_rescan(body, document=document)
            raw_matches.extend(decoded_hits)

        # Stage 6 — infrastructure / disclosure (observation-first)
        if len(raw_matches) < cap and not _over_budget():
            raw_matches.extend(self.infra.detect(body, document=document))

        # Cap total raw before scoring
        if len(raw_matches) > cap:
            raw_matches = raw_matches[:cap]

        detections = self._score_and_filter(
            raw_matches,
            document_id=document_id or (document.id if document else ""),
            occurrence_id=occurrence_id,
        )
        return detections

    def scan_document(
        self,
        document: SourceDocument,
        *,
        occurrence_id: Optional[str] = None,
    ) -> list[Detection]:
        """
        Purpose:
            Scan a SourceDocument that already has .text populated.
        Input:
            document / occurrence_id
        Output:
            list[Detection]
        Side effects: None.
        """
        return self.scan_text(
            document.text or "",
            document_id=document.id,
            occurrence_id=occurrence_id,
            document=document,
        )

    def _decode_and_rescan(
        self,
        text: str,
        *,
        document: Optional[SourceDocument] = None,
    ) -> list[RawMatch]:
        """
        Purpose:
            Extract encode candidates, decode up to max_depth, rescan with
            stages 1–2 only (no nested decode recursion).
        Input:
            text / document
        Output:
            list[RawMatch] with encoding_chain set
        Side effects: None.
        """
        max_depth = max(0, int(self.config.max_decode_depth))
        max_bytes = max(1, int(self.config.max_decode_bytes))
        cap = max(1, int(self.config.max_candidates_per_document))
        cand_cap = min(100, cap)

        if max_depth <= 0:
            return []

        candidates = extract_decode_candidates(text, max_candidates=cand_cap)
        hits: list[RawMatch] = []
        seen_decoded: set[str] = set()

        for cand in candidates:
            result = decode_candidate(
                cand.value,
                max_depth=max_depth,
                max_bytes=max_bytes,
                prefer=cand.hint or None,
            )
            if not result.success or not result.decoded:
                continue
            # Skip if decoded equals original candidate (no real change)
            if result.decoded == cand.value:
                continue
            # Dedup identical decoded payloads
            dedup_key = result.decoded[:200]
            if dedup_key in seen_decoded:
                continue
            seen_decoded.add(dedup_key)

            chain = list(result.encoding_chain)
            depth = int(result.depth)

            # Rescan stages 1–2 only on decoded text (no nested decode / infra)
            stage_hits: list[RawMatch] = []
            stage_hits.extend(
                self.specific.detect(
                    result.decoded,
                    document=document,
                    encoding_chain=chain,
                    decode_depth=depth,
                )
            )
            stage_hits.extend(
                self.pem.detect(
                    result.decoded,
                    document=document,
                    encoding_chain=chain,
                    decode_depth=depth,
                )
            )
            stage_hits.extend(
                self.jwt.detect(
                    result.decoded,
                    document=document,
                    encoding_chain=chain,
                    decode_depth=depth,
                )
            )
            stage_hits.extend(
                self.connection.detect(
                    result.decoded,
                    document=document,
                    encoding_chain=chain,
                    decode_depth=depth,
                )
            )
            stage_hits.extend(
                self.contextual.detect(
                    result.decoded,
                    document=document,
                    encoding_chain=chain,
                    decode_depth=depth,
                )
            )

            for h in stage_hits:
                # Offsets are into decoded text — keep them; note parent
                # candidate offset in metadata for evidence later.
                h.metadata = dict(h.metadata or {})
                h.metadata["decoded_from_start"] = cand.start
                h.metadata["decoded_from_end"] = cand.end
                h.metadata["stage"] = "decode_rescan"
                hits.append(h)
                if len(hits) >= cap:
                    return hits

        return hits

    def _score_and_filter(
        self,
        raw_matches: list[RawMatch],
        *,
        document_id: str,
        occurrence_id: Optional[str],
    ) -> list[Detection]:
        """
        Purpose:
            Score each RawMatch, apply suppression, build Detection rows.
        Input:
            raw_matches / document_id / occurrence_id
        Output:
            list[Detection] (non-suppressed by default)
        Side effects: None.
        """
        store_suppressed = bool(self.config.store_suppressed_detections)
        store_raw = bool(self.config.store_raw_secret_in_evidence)
        out: list[Detection] = []
        seen_fp: set[tuple[str, str, int]] = set()

        for raw in raw_matches:
            score, level = score_match(raw)
            suppressed, reason = should_suppress(
                raw.raw_value,
                detector_family=raw.detector_family,
                detector_id=raw.detector_id,
                matched_key=raw.matched_key,
                entropy=raw.entropy,
                raw_match=raw,
            )
            if suppressed and not store_suppressed:
                continue

            case_sensitive = raw.metadata.get("case_sensitive")
            if case_sensitive is None:
                case_sensitive = None  # let fingerprint use family default
            else:
                case_sensitive = bool(case_sensitive)

            fp = fingerprint_secret(
                raw.detector_family,
                raw.raw_value,
                case_sensitive=case_sensitive,
            )
            dedup = (raw.detector_id, fp, int(raw.match_start))
            if dedup in seen_fp:
                continue
            seen_fp.add(dedup)

            # Aggregated disclosures may supply a UI-safe summary
            display = raw.metadata.get("summary") if raw.metadata else None
            redacted = (
                str(display)[:500]
                if display
                else redact_secret(raw.raw_value)
            )

            det = Detection(
                id=str(uuid.uuid4()),
                document_id=document_id,
                occurrence_id=occurrence_id,
                detector_id=raw.detector_id,
                detector_family=raw.detector_family,
                category=raw.category,
                secret_type=raw.secret_type,
                matched_key=raw.matched_key,
                redacted_value=redacted,
                value_fingerprint=fp,
                confidence_score=score,
                confidence_level=level,
                entropy=raw.entropy,
                encoding_chain=list(raw.encoding_chain or []),
                decode_depth=int(raw.decode_depth or 0),
                match_start=int(raw.match_start),
                match_end=int(raw.match_end),
                context_before=raw.context_before or "",
                context_after=raw.context_after or "",
                suppressed=suppressed,
                suppression_reason=reason,
                finding_id=None,
                raw_value_stored=store_raw,
                created_at=None,
                raw_value=raw.raw_value if store_raw else None,
            )
            out.append(det)

        return out


# Module-level default orchestrator (lazy)
_DEFAULT: Optional[DetectorOrchestrator] = None


def _default_orchestrator(config: Optional[PassiveScanConfig] = None) -> DetectorOrchestrator:
    """Return a shared orchestrator, rebuilt when config is provided. Side effects: may load rules."""
    global _DEFAULT
    if config is not None:
        return DetectorOrchestrator(config=config)
    if _DEFAULT is None:
        _DEFAULT = DetectorOrchestrator()
    return _DEFAULT


def scan_text(
    text: str,
    *,
    document_id: str = "",
    occurrence_id: Optional[str] = None,
    document: Optional[SourceDocument] = None,
    config: Optional[PassiveScanConfig] = None,
) -> list[Detection]:
    """
    Purpose:
        Module-level convenience wrapper around DetectorOrchestrator.scan_text.
    Side effects: May load rules on first call.
    """
    return _default_orchestrator(config).scan_text(
        text,
        document_id=document_id,
        occurrence_id=occurrence_id,
        document=document,
    )


def scan_document(
    document: SourceDocument,
    *,
    occurrence_id: Optional[str] = None,
    config: Optional[PassiveScanConfig] = None,
) -> list[Detection]:
    """
    Purpose:
        Module-level convenience wrapper for scanning a SourceDocument.
    Side effects: May load rules on first call.
    """
    return _default_orchestrator(config).scan_document(
        document,
        occurrence_id=occurrence_id,
    )
