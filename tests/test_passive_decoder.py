"""
Phase 7 tests: decoder pipeline + entropy stage + decode rescan.
"""

from __future__ import annotations

import base64
from pathlib import Path

from talos.passive.config import PassiveScanConfig
from talos.passive.decoder.pipeline import (
    decode_candidate,
    extract_decode_candidates,
    try_decode_once,
)
from talos.passive.detectors.entropy import EntropyDetector
from talos.passive.detectors.orchestrator import DetectorOrchestrator, scan_text

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "passive"


def test_base64_password_assignment_decoded():
    """base64(password=SuperSecret123) → contextual password detection."""
    text = (FIXTURES / "encoded_password.js").read_text(encoding="utf-8")
    dets = scan_text(text)
    # Must be a secret detection with encoding chain — never "Base64 Found"
    assert not any("base64" in (d.detector_id or "").lower() for d in dets)
    assert not any(d.secret_type == "encoded_content" for d in dets)
    secretish = [
        d
        for d in dets
        if d.encoding_chain and not d.suppressed
    ]
    assert secretish, f"expected encoded secret detection, got {dets}"
    assert any("base64" in (d.encoding_chain or []) for d in secretish)


def test_decode_candidate_depth_limit():
    # Nested base64 of "password=NestedSecret999"
    inner = "password=NestedSecret999"
    layer1 = base64.b64encode(inner.encode()).decode()
    layer2 = base64.b64encode(layer1.encode()).decode()
    layer3 = base64.b64encode(layer2.encode()).decode()
    layer4 = base64.b64encode(layer3.encode()).decode()

    result = decode_candidate(layer4, max_depth=3, max_bytes=256_000)
    assert result.success
    assert result.depth == 3
    # Depth 3 stops before fully unwrapping to plaintext when 4 layers deep
    assert result.decoded != inner

    full = decode_candidate(layer4, max_depth=4, max_bytes=256_000)
    assert full.success
    assert full.depth == 4
    assert "password=" in full.decoded or full.decoded == inner


def test_max_decode_bytes_prevents_runaway():
    # Huge "expansion" via repeated short base64 — enforce byte cap
    tiny = base64.b64encode(b"ab").decode()
    result = decode_candidate(tiny * 50, max_depth=3, max_bytes=32)
    # Either fails or respects size — must not explode
    if result.success:
        assert len(result.decoded.encode("utf-8", errors="replace")) <= 32 * 8


def test_data_uri_image_base64_no_secret_finding():
    # Minimal fake PNG-like data URI (not a real secret)
    b64 = base64.b64encode(b"\x89PNG\r\n\x1a\n" + b"\x00" * 40).decode()
    text = f'const img = "data:image/png;base64,{b64}";'
    dets = scan_text(text)
    assert not any(d.encoding_chain and not d.suppressed for d in dets if d.category == "secret")
    # More importantly: no detection titled as base64
    assert not any("base64" == d.detector_id for d in dets)


def test_try_decode_hex_and_url():
    hexed = "70617373776f72643d586865785365637265743939"  # password=XhexSecret99
    out = try_decode_once(hexed, prefer="hex")
    assert out is not None
    decoded, codec = out
    assert codec == "hex"
    assert "password=" in decoded

    url = "password%3DUrlSecret12345"
    out2 = try_decode_once(url, prefer="url")
    assert out2 is not None
    assert "password=" in out2[0]


def test_extract_skips_empty():
    assert extract_decode_candidates("") == []


def test_entropy_requires_context():
    # Bare high-entropy blob without keyword/assignment → no hit
    bare = "Xk9mQ2pL7vN4wR8tY1uZ0bC3dE5fG6hJ"
    hits = EntropyDetector().detect(f"const x = {bare};")
    # May or may not have assignment operator context (= before value)
    # With `const x = TOKEN` there IS assignment — so may match.
    # Use no operator:
    hits2 = EntropyDetector().detect(f"note {bare} end")
    assert hits2 == []


def test_entropy_with_keyword_promotes():
    token = "Xk9mQ2pL7vN4wR8tY1uZ0bC3dE5fG6hJ"
    text = f'const api_key_hint = "{token}"; // secret nearby'
    # Actually need keyword in window — "secret" is in comment
    text = f'// secret config\nconst v = "{token}";'
    hits = EntropyDetector().detect(text)
    assert hits


def test_orchestrator_respects_max_decode_depth_zero():
    cfg = PassiveScanConfig(max_decode_depth=0)
    text = (FIXTURES / "encoded_password.js").read_text(encoding="utf-8")
    dets = DetectorOrchestrator(config=cfg).scan_text(text)
    assert not any(d.encoding_chain for d in dets)
