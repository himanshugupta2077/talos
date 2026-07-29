"""
Package: talos.intruder

Purpose:
    Talos Intruder — high-volume mutation attack engine (CLI-first).

    Distinct from:
        • talos send   — mutable one-offs (Repeater), hard caps N≤50
        • talos replay — exact identity-preserving re-send
        • input-validation — parameter intelligence with fixed probe taxonomy

    Phase 1:
        Template {{variables}} + inject_value bridge
        Generators: wordlist, numbers, static
        Processors: url_encode, base64_encode
        Strategies: single + sniper
        Fixed RPS timing, concurrency default 1
        Match rules, metrics, pause/resume/cancel
        Time-sliced scheduler jobs (intruder_session)
        CLI + AI JSON schemas + export JSONL/CSV

    Phase 2:
        Strategies: pitchfork, zip, cluster_bomb (cartesian alias)
        Storage modes: sample_flows, all_flows (+ metrics_only)
        Session clone
        Host concurrency caps (max_concurrency_per_host)
        Processors: url_decode, base64_decode, case, html, hashes, strip,
                    prefix:<text>, suffix:<text>

Public surface:
    engine.run_session_segment, models, CLI entry (cli.run_intruder_cli).
"""

from talos.intruder.engine import SegmentOutcome, run_session_segment

__all__ = [
    "SegmentOutcome",
    "run_session_segment",
]
