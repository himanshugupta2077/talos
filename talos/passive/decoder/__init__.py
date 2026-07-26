"""
Package: talos.passive.decoder

Purpose:
    Decoder Pipeline for Passive Source Intelligence.

    Encodings alone never create findings.  Decoded text is rescanned by
    detector stages 1–2 (and optionally 3) with encoding_chain metadata.

    Supported codecs (depth-limited):
        base64, base64url, hex, url, html entity, unicode / JS escapes

Dependencies: pipeline.py
Data flow: candidate strings → decode_candidate / extract_decode_candidates
Side effects: None (pure transforms).
"""

from talos.passive.decoder.pipeline import (
    DecodeCandidate,
    decode_candidate,
    extract_decode_candidates,
    try_decode_once,
)

__all__ = [
    "DecodeCandidate",
    "decode_candidate",
    "extract_decode_candidates",
    "try_decode_once",
]
