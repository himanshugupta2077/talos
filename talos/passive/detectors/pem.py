"""
Module: talos.passive.detectors.pem

Purpose:
    Stage 1 companion — multi-line PEM / OpenSSH private key blocks.

    YAML rules cannot comfortably span multi-line BEGIN/END blocks with
    stable offsets; this detector owns that shape and emits CONFIRMED
    provider-family-adjacent PEM detections (family=pem).

Dependencies: re; talos.passive.detectors.base, constants, models
Data flow: text → list[RawMatch]
Side effects: None.
"""

from __future__ import annotations

import re
from typing import Optional

from talos.passive.constants import (
    CATEGORY_SECRET,
    CONFIDENCE_CONFIRMED_PATTERN,
    DETECTOR_FAMILY_PEM,
)
from talos.passive.detectors.base import build_raw_match
from talos.passive.models import RawMatch, SourceDocument

# BEGIN … PRIVATE KEY … END … (RSA / EC / OPENSSH / generic)
_PEM_BLOCK = re.compile(
    r"-----BEGIN (?P<label>(?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?"
    r"PRIVATE KEY)-----"
    r"(?P<body>[\sA-Za-z0-9+/=]+?)"
    r"-----END (?P=label)-----",
    re.DOTALL,
)

_DETECTOR_ID = "private_key_pem"
_SECRET_TYPE = "private_key_pem"
_BASE_SCORE = 95


class PemDetector:
    """
    Purpose:
        Detect PEM/OpenSSH private key material in source text.
    """

    def __init__(self, *, max_candidates: int = 50) -> None:
        self._max_candidates = max(1, int(max_candidates))

    def detect(
        self,
        text: str,
        *,
        document: Optional[SourceDocument] = None,
        encoding_chain: Optional[list[str]] = None,
        decode_depth: int = 0,
    ) -> list[RawMatch]:
        """
        Purpose:
            Find PEM private key blocks.
        Input:
            text / encoding context
        Output:
            list[RawMatch]
        Side effects: None.
        """
        if not text or "BEGIN " not in text or "PRIVATE KEY" not in text:
            return []

        matches: list[RawMatch] = []
        for m in _PEM_BLOCK.finditer(text):
            full = m.group(0)
            # Fingerprint on a stable subset (label + first 64 body chars)
            label = m.group("label") or "PRIVATE KEY"
            body = (m.group("body") or "").replace("\n", "").replace("\r", "").strip()
            # Store redaction-friendly material: full block is long; keep full
            # for fingerprint fidelity but cap stored raw_value length.
            raw_value = full if len(full) <= 4000 else full[:4000]
            matches.append(
                build_raw_match(
                    detector_id=_DETECTOR_ID,
                    detector_family=DETECTOR_FAMILY_PEM,
                    category=CATEGORY_SECRET,
                    secret_type=_SECRET_TYPE,
                    raw_value=raw_value,
                    match_start=m.start(),
                    match_end=m.end(),
                    text=text,
                    encoding_chain=encoding_chain,
                    decode_depth=decode_depth,
                    metadata={
                        "rule_name": "PEM Private Key Block",
                        "base_score": _BASE_SCORE,
                        "base_level": CONFIDENCE_CONFIRMED_PATTERN,
                        "case_sensitive": True,
                        "finding_title": "Exposed Private Key (PEM)",
                        "pem_label": label,
                        "body_len": len(body),
                        "stage": "pem",
                    },
                    compute_entropy=False,
                )
            )
            if len(matches) >= self._max_candidates:
                break
        return matches
