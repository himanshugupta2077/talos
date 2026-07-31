"""
Module: talos.input_validation.synthesize

Purpose:
    Module 3 — **Synthesis from existing probes** (zero new HTTP).

    Turns already-collected ``iv_probe_results`` (+ joined flow bodies) into a
    versioned parameter intelligence profile (Module 2 shape) using Module 1
    fingerprints and outcome classification.

    This closes the synthesis gap: raw probe rows become aggregated acceptance,
    length, type, validation, reflection, transforms, confidence, negative
    evidence, attempts, and simple capability flags — without spending more
    requests.

What this module does
    - Load completed probes for a ``param_uuid``
    - Build baseline fingerprint (prefer baseline analysis; else first success)
    - Per probe: fingerprint, classify_outcome, reflection / transform hints
    - Aggregate into observed / inferred / tested / attempts / capabilities
    - Mark partial when required analyses are missing or signals conflict
    - Persist via ``upsert_param_profile(..., bump_version=True)`` when asked

What this module does **not** do
    - Send HTTP (no scheduler probe enqueue)
    - Build multiprobe payloads (M4 multiprobe.py) — only consumes results
    - Invent exploit findings (candidates are prioritization only)

Module 8: folds ``analysis=parser`` rows into ``observed.parser``,
``normalization_pipeline``, ``inferred.parser_family``, capabilities, and
``tested{}`` negatives via ``parser_intel``.

Module 11: after aggregation, ``capabilities.apply_capabilities`` +
``candidates.score_candidates`` fill profile capabilities and attack
candidate scores (stable consumer API in ``candidates.get_param_intelligence``).

Dependencies:
    talos.input_validation.db, fingerprint, outcomes, phases, profile,
    taxonomy (M6), length_search (M6), type_intel (M7), parser_intel (M8),
    capabilities + candidates (M11)
Data flow:
    iv_probe_results + flows → synthesize_param_profile() → profile dict
        → optional upsert_param_profile()
Side effects:
    DB read always; DB write only when persist=True.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any
from urllib.parse import quote

from talos.input_validation import db as iv_db
from talos.input_validation.fingerprint import (
    ResponseFingerprint,
    fingerprint_from_flow,
)
from talos.input_validation.length_search import (
    parse_length_outcomes,
    synthesize_length_state,
)
from talos.input_validation.outcomes import (
    OUTCOME_ACCEPTED,
    OUTCOME_MODIFIED,
    OUTCOME_REJECTED,
    OUTCOME_TRUNCATED,
    OUTCOME_UNKNOWN,
    classify_outcome,
)
from talos.input_validation.multiprobe import (
    analyze_multiprobe_response,
    parse_multiprobe_payload,
)
from talos.input_validation.phases import (
    analyze_reflection,
    analyze_transformations,
)
from talos.input_validation.candidates import (
    enrich_profile_capabilities_and_candidates,
    format_candidates_lines,
    load_and_merge_cross_flow,
)
from talos.input_validation.profile import (
    MAX_ATTEMPTS,
    STATE_CONFLICTING,
    STATE_UNKNOWN,
    UNCERTAINTY_HIGH,
    UNCERTAINTY_LOW,
    UNCERTAINTY_NONE,
    append_attempt,
    empty_characteristic,
    empty_param_profile,
    ensure_profile_shape,
    set_tested,
)
from talos.input_validation.taxonomy import (
    char_to_classes as char_to_taxonomy_classes,
)
from talos.input_validation.type_intel import (
    merge_type_tested,
    resolve_passive_type,
    synthesize_type_state,
    tested_key_for_payload_type,
    types_summary_block,
)
from talos.input_validation.parser_intel import (
    apply_parser_synthesis_to_profile,
    synthesize_parser_state,
)
from talos.input_validation.url_sink_probes import (
    apply_url_sink_synthesis_to_profile,
    synthesize_url_sink_state,
)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Analyses that produce HTTP probe rows (scan phases).
SCAN_ANALYSES: frozenset[str] = frozenset({
    "baseline",
    "multiprobe",
    "identifier",
    "characters",
    "length",
    "types",
    "validation",
    "parser",
    "url_sink",
})

# Analyses preferred as prerequisites before transform/reflection synthesis
# is considered "complete" (not partial).
# Multiprobe alone covers reflection + taxonomy when identifier/characters skipped.
REQUIRED_FOR_FULL_SYNTHESIS: tuple[str, ...] = (
    "baseline",
    "multiprobe",
)

# Job types that still generate HTTP (must finish before analysis races complete).
_SCAN_JOB_TYPES: frozenset[str] = frozenset({
    "iv_baseline",
    "iv_multiprobe",
    "iv_identifier",
    "iv_characters",
    "iv_length",
    "iv_types",
    "iv_validation",
    "iv_parser",
    "iv_url_sink",
})

# Outcomes treated as "accepted enough" for charset / type / length aggregation.
_SOFT_ACCEPT: frozenset[str] = frozenset({
    OUTCOME_ACCEPTED,
    OUTCOME_MODIFIED,
    "encoded",
    "normalized",
})

# Validation payload_type → taxonomy / tested key (Module 7: type_intel is source).
_VALIDATION_TAXONOMY_KEYS: dict[str, str] = {
    "null_byte": "null",
    "whitespace": "whitespace",
    "html_injection": "markup",
    "special_chars": "comment",
    "very_long": "length_limit",
    "empty": "empty",
    "negative_int": "negative_int",
    "float": "float",
    "crlf": "crlf",
    "enum_outside": "enum_outside",
    "zero": "zero",
    "huge_int": "huge_int",
    "null_str": "null_str",
    "unicode": "unicode",
}

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def synthesize_param_profile(
    db_path: Path | str,
    param_uuid: str,
    *,
    persist: bool = True,
    bump_version: bool = True,
) -> dict[str, Any]:
    """
    Purpose:
        Build a parameter intelligence profile from existing probe evidence
        only (offline).  Optionally write it to ``iv_param_profiles``.

    Input:
        db_path      — project SQLite path.
        param_uuid   — deterministic parameter id (host|location|name hash).
        persist      — when True, upsert into iv_param_profiles.
        bump_version — when True and a row exists, increment profile_version.

    Output:
        Shaped profile dict (always; empty skeleton when no probes exist).
        Includes inferred.synthesis metadata (partial flags, counts).

    Side effects:
        DB read; DB write when persist=True.
    """
    path = Path(db_path)
    probes = iv_db.get_probe_results_for_param(path, param_uuid)
    identity = _resolve_identity(path, param_uuid, probes)

    profile = empty_param_profile(
        param_uuid=param_uuid,
        host=identity["host"],
        location=identity["location"],
        name=identity["name"],
    )

    completed = [
        p for p in probes
        if p.get("status") == iv_db.STATUS_COMPLETED and p.get("flow_id")
    ]
    # Include completed rows without flow_id only for counting; cannot fingerprint.
    completed_any = [p for p in probes if p.get("status") == iv_db.STATUS_COMPLETED]

    if not completed:
        profile["inferred"] = {
            "synthesis": {
                "partial": True,
                "source": "offline_probes",
                "completed_probe_count": 0,
                "probe_row_count": len(probes),
                "missing_analyses": sorted(SCAN_ANALYSES),
                "notes": ["no completed probes with flow evidence"],
            },
        }
        profile["requests_used"] = 0
        if persist and identity["host"]:
            stored = iv_db.upsert_param_profile(
                path,
                param_uuid=param_uuid,
                host=identity["host"],
                location=identity["location"],
                param_name=identity["name"],
                profile=profile,
                bump_version=bump_version,
            )
            _refresh_multi_level_after_param(
                path, param_uuid=param_uuid, host=identity["host"], probes=probes,
            )
            return stored
        return ensure_profile_shape(profile)

    baseline_fp, baseline_probe = _select_baseline(completed)
    if baseline_fp is not None:
        profile["observed"]["baseline_fingerprint"] = baseline_fp.to_dict()

    # Per-probe classification + reflection hints.
    probe_summaries: list[dict[str, Any]] = []
    timing_samples: list[float] = []
    for probe in completed:
        summary = _summarize_probe(probe, baseline_fp)
        probe_summaries.append(summary)
        if summary.get("duration_ms") is not None:
            timing_samples.append(float(summary["duration_ms"]))

    profile["observed"]["timing"] = {"samples_ms": timing_samples[:200]}
    profile["requests_used"] = len(completed_any)

    # Aggregates
    _fill_acceptance(profile, probe_summaries)
    _fill_types(profile, probe_summaries, identity=identity, db_path=path)
    _fill_length(profile, probe_summaries)
    _fill_validation_tested(profile, probe_summaries)
    _fill_transforms(profile, completed)
    _fill_parser_and_normalization(profile, completed, probe_summaries)
    _fill_url_sink(profile, completed, probe_summaries, baseline_fp=baseline_fp)
    _fill_reflection(profile, completed, probe_summaries)
    # PR5: merge cross-flow / stored reflection links after probe same-request
    # fill. score=False — capabilities + candidates run once in _fill_capabilities.
    # Final upsert (below) persists the merged profile (persist=False here).
    if param_uuid:
        load_and_merge_cross_flow(
            path,
            profile,
            persist=False,
            score=False,
        )
    _fill_surface(profile, identity, completed)
    _fill_attempts(profile, probe_summaries)
    # Module 11: central capabilities + attack candidate scores
    # (sees stored_reflection / top-level reflected from merge above).
    _fill_capabilities(profile, identity["location"])
    _fill_synthesis_meta(profile, probes, probe_summaries)

    # Multiprobe: fold per-class outcomes from analyzer into acceptance.classes.
    _apply_multiprobe_extension_hooks(profile, probe_summaries)

    shaped = ensure_profile_shape(profile)
    if persist and identity["host"]:
        stored = iv_db.upsert_param_profile(
            path,
            param_uuid=param_uuid,
            host=identity["host"],
            location=identity["location"],
            param_name=identity["name"],
            profile=shaped,
            bump_version=bump_version,
        )
        # Module 10: roll param intelligence up to endpoint + application profiles.
        _refresh_multi_level_after_param(
            path, param_uuid=param_uuid, host=identity["host"], probes=probes,
        )
        return stored
    return shaped


def synthesize_many(
    db_path: Path | str,
    *,
    host: str | None = None,
    param_uuid: str | None = None,
    persist: bool = True,
    bump_version: bool = True,
    limit: int = 5000,
) -> dict[str, Any]:
    """
    Purpose:
        Synthesize profiles for one parameter, all parameters on a host,
        or every param_uuid that has probe rows.

    Output:
        Summary dict:
            synthesized (int), partial (int), empty (int),
            param_uuids (list[str]), errors (list[dict]).

    Side effects: DB read/write via synthesize_param_profile when persist=True.
    """
    path = Path(db_path)
    if param_uuid:
        uuids = [param_uuid]
    else:
        uuids = list_param_uuids_with_probes(path, host=host, limit=limit)

    synthesized = 0
    partial = 0
    empty = 0
    errors: list[dict[str, Any]] = []
    done: list[str] = []

    for uid in uuids:
        try:
            profile = synthesize_param_profile(
                path, uid, persist=persist, bump_version=bump_version,
            )
            done.append(uid)
            meta = (profile.get("inferred") or {}).get("synthesis") or {}
            if int(meta.get("completed_probe_count") or 0) == 0:
                empty += 1
            elif meta.get("partial"):
                partial += 1
                synthesized += 1
            else:
                synthesized += 1
        except Exception as exc:  # noqa: BLE001 — batch resilience
            errors.append({"param_uuid": uid, "error": str(exc)})

    # Module 10: after a batch, re-aggregate app profiles for affected hosts.
    if persist and done:
        hosts: set[str] = set()
        if host:
            hosts.add(host)
        else:
            for uid in done[:200]:
                try:
                    prof = iv_db.get_param_profile(path, uid)
                    if prof and prof.get("host"):
                        hosts.add(str(prof["host"]))
                except Exception:  # noqa: BLE001
                    continue
        for h in hosts:
            try:
                from talos.input_validation.learning import refresh_app_profile
                refresh_app_profile(path, h, bump_version=True)
            except Exception as exc:  # noqa: BLE001
                errors.append({"param_uuid": f"app:{h}", "error": str(exc)})

    return {
        "synthesized": synthesized,
        "partial": partial,
        "empty": empty,
        "param_uuids": done,
        "errors": errors,
        "requested": len(uuids),
    }


def _refresh_multi_level_after_param(
    db_path: Path,
    *,
    param_uuid: str,
    host: str,
    probes: list[dict[str, Any]] | None = None,
) -> None:
    """
    Purpose:
        After a parameter profile is written, refresh endpoint + app profiles
        (Module 10).  Endpoint id is taken from probe rows when available.
    Side effects: DB writes via learning.refresh_multi_level.
    """
    try:
        from talos.input_validation.learning import refresh_multi_level
    except Exception:  # noqa: BLE001
        return

    endpoint_id = ""
    for p in probes or []:
        eid = p.get("endpoint_id") or ""
        if eid:
            endpoint_id = str(eid)
            break
    if not endpoint_id:
        # Fall back: any probe row for this param_uuid.
        try:
            rows = iv_db.get_probe_results_for_param(db_path, param_uuid)
            for p in rows:
                if p.get("endpoint_id"):
                    endpoint_id = str(p["endpoint_id"])
                    break
        except Exception:  # noqa: BLE001
            pass
    try:
        refresh_multi_level(
            db_path,
            endpoint_id=endpoint_id,
            host=host,
            bump_version=True,
        )
    except Exception:  # noqa: BLE001 — synthesis must not fail on rollup
        pass


def list_param_uuids_with_probes(
    db_path: Path | str,
    *,
    host: str | None = None,
    limit: int = 5000,
) -> list[str]:
    """
    Purpose:
        Distinct param_uuid values present in iv_probe_results.
    Side effects: Read-only.
    """
    path = Path(db_path)
    with sqlite3.connect(str(path)) as conn:
        if host:
            rows = conn.execute(
                """
                SELECT DISTINCT param_uuid FROM iv_probe_results
                WHERE host = ?
                ORDER BY param_uuid
                LIMIT ?
                """,
                (host, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT DISTINCT param_uuid FROM iv_probe_results
                ORDER BY param_uuid
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
    return [r[0] for r in rows if r[0]]


def analysis_probes_ready(
    db_path: Path | str,
    param_uuid: str,
    *,
    required_analyses: tuple[str, ...] | list[str] | None = None,
) -> dict[str, Any]:
    """
    Purpose:
        Decide whether transform/reflection analysis should wait, run partial,
        or run fully.  Fixes the analysis race: analysis jobs must not mark
        complete while scan probes for the same parameter are still running.

    Output:
        dict:
            ready (bool)           — True when analysis may run (even partial).
            wait (bool)            — True when scan jobs are still pending/running.
            partial (bool)         — True when some required analyses lack completed probes.
            completed_analyses     — set-like list of analyses with ≥1 completed probe.
            missing_required       — required analyses still missing completed probes.
            pending_scan_jobs      — count of pending/running scan jobs for param.
            completed_probe_count  — completed probe rows.

    Side effects: Read-only.
    """
    path = Path(db_path)
    required = tuple(required_analyses or REQUIRED_FOR_FULL_SYNTHESIS)
    probes = iv_db.get_probe_results_for_param(path, param_uuid)
    completed = [p for p in probes if p.get("status") == iv_db.STATUS_COMPLETED]
    completed_analyses = sorted({
        p.get("analysis") or ""
        for p in completed
        if p.get("analysis")
    })
    missing = [a for a in required if a not in completed_analyses]
    pending = count_pending_scan_jobs(path, param_uuid)

    # Wait only while scan work is still in flight.
    wait = pending > 0
    # Ready when we have at least one completed probe and nothing is waiting,
    # OR when we have baseline/identifier evidence even with some missing.
    ready = (not wait) and len(completed) > 0
    partial = bool(missing) or len(completed) < 3

    return {
        "ready": ready,
        "wait": wait,
        "partial": partial,
        "completed_analyses": completed_analyses,
        "missing_required": missing,
        "pending_scan_jobs": pending,
        "completed_probe_count": len(completed),
    }


def count_pending_scan_jobs(db_path: Path | str, param_uuid: str) -> int:
    """
    Purpose:
        Count pending/running scheduler scan jobs whose meta.parameter_uuid
        matches.  Used to detect the analysis race condition.
    Side effects: Read-only.
    """
    path = Path(db_path)
    if not param_uuid:
        return 0
    with sqlite3.connect(str(path)) as conn:
        # meta is JSON text; LIKE is sufficient for UUID match and avoids
        # requiring json1 extension on older SQLite builds.
        needle = f'%"parameter_uuid": "{param_uuid}"%'
        needle_alt = f'%"param_uuid": "{param_uuid}"%'
        placeholders = ",".join("?" for _ in _SCAN_JOB_TYPES)
        rows = conn.execute(
            f"""
            SELECT COUNT(*) FROM scheduler_jobs
            WHERE status IN ('pending', 'running')
              AND job_type IN ({placeholders})
              AND (
                    meta LIKE ?
                 OR meta LIKE ?
              )
            """,
            (*sorted(_SCAN_JOB_TYPES), needle, needle_alt),
        ).fetchone()
    return int(rows[0] if rows else 0)


# char_to_taxonomy_classes is imported from taxonomy (Module 6) and re-exported
# for callers / tests that import it from synthesize.


def detect_payload_reflection(
    payload: str,
    body: str,
    content_type: str = "",
) -> dict[str, Any]:
    """
    Purpose:
        Lightweight reflection / encoding / transform detection for one probe.
        Adapted from phases.analyze_reflection / analyze_transformations.
    Output:
        dict with reflected, encoding, transforms, location context.
    Side effects: None.
    """
    if not payload or not body:
        return {
            "reflected": False,
            "encoding": "",
            "transforms": [],
            "location": "",
            "payload_in_body": False,
        }

    def _html_enc(s: str) -> str:
        return (
            s.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
        )

    found = False
    encoding = ""
    transforms: list[str] = []

    if payload in body:
        found = True
        encoding = "raw"
    elif _html_enc(payload) in body:
        found = True
        encoding = "html_encoded"
    elif quote(payload, safe="") in body:
        found = True
        encoding = "url_encoded"
    elif payload.strip() and payload.strip() in body:
        found = True
        encoding = "raw"
        transforms.append("trim")
    elif payload.strip() and payload.strip().lower() in body:
        found = True
        encoding = "raw"
        transforms.extend(["trim", "lowercase"])
    elif payload.lower() in body and payload.lower() != payload:
        found = True
        encoding = "raw"
        transforms.append("lowercase")
    elif payload.upper() in body and payload.upper() != payload:
        found = True
        encoding = "raw"
        transforms.append("uppercase")

    ct = (content_type or "").lower()
    location = ""
    if found:
        if "html" in ct:
            location = "html"
        elif "json" in ct:
            location = "json"
        elif "xml" in ct:
            location = "xml"
        elif "javascript" in ct:
            location = "js"
        else:
            location = "other"

    return {
        "reflected": found,
        "encoding": encoding,
        "transforms": transforms,
        "location": location,
        "payload_in_body": found,
    }


def format_profile_summary_lines(profile: dict[str, Any] | None) -> list[str]:
    """
    Purpose:
        Human-readable detail lines for CLI show/export from a synthesized
        intelligence profile (acceptance, reflection, capabilities, partial).
    Side effects: None.
    """
    if not profile or not isinstance(profile, dict):
        return []

    lines: list[str] = []
    obs = profile.get("observed") or {}
    inferred = profile.get("inferred") or {}
    synth = inferred.get("synthesis") or {}

    ver = profile.get("profile_version", "?")
    schema = profile.get("schema_version", "?")
    reqs = profile.get("requests_used", 0)
    partial = bool(synth.get("partial"))
    lines.append(
        f"schema_v{schema}  profile_v{ver}  requests_used={reqs}"
        + ("  [PARTIAL]" if partial else "")
    )

    refl = obs.get("reflection") or {}
    if refl:
        modes = refl.get("modes") or []
        mode_txt = ",".join(modes) if modes else "(none)"
        lines.append(
            f"Reflection: state={refl.get('state', 'unknown')}  "
            f"confidence={refl.get('confidence', 0)}  "
            f"uncertainty={refl.get('uncertainty', '?')}  "
            f"encoding={refl.get('encoding') or '(none)'}  "
            f"contexts={','.join(refl.get('contexts') or []) or '(none)'}  "
            f"modes={mode_txt}"
        )
        same_req = (
            refl.get("same_request")
            if isinstance(refl.get("same_request"), dict)
            else None
        )
        if same_req:
            lines.append(
                f"  same_request: state={same_req.get('state', 'unknown')}  "
                f"confidence={same_req.get('confidence', 0)}  "
                f"contexts={','.join(same_req.get('contexts') or []) or '(none)'}"
            )
        cross = (
            refl.get("cross_flow")
            if isinstance(refl.get("cross_flow"), dict)
            else None
        )
        if cross:
            link_n = cross.get("link_count")
            if link_n is None:
                sinks_tmp = cross.get("sinks") or []
                link_n = len(sinks_tmp) if isinstance(sinks_tmp, list) else 0
            lines.append(
                f"  cross_flow: state={cross.get('state', 'unknown')}  "
                f"confidence={cross.get('confidence', 0)}  "
                f"link_count={link_n}  "
                f"contexts={','.join(cross.get('contexts') or []) or '(none)'}"
            )
            sinks = cross.get("sinks") or []
            if isinstance(sinks, list):
                for sink in sinks[:5]:
                    if not isinstance(sink, dict):
                        continue
                    reason = sink.get("reason") or ""
                    if not reason:
                        method = sink.get("sink_method") or sink.get("method") or ""
                        path = sink.get("sink_path") or sink.get("path") or ""
                        ctx = sink.get("sink_context") or sink.get("context") or "other"
                        enc = sink.get("encoding") or "raw"
                        reason = (
                            f"reflected on {method} {path}".strip()
                            + f" ({ctx}, {enc})"
                        )
                    lines.append(f"    sink: {reason}")
                if len(sinks) > 5:
                    lines.append(f"    … +{len(sinks) - 5} more sink(s)")
            lines.append(
                "  (stored/cross-page reflection is data-flow prioritization "
                "evidence — not confirmed XSS)"
            )

    acceptance = obs.get("acceptance") or {}
    classes = acceptance.get("classes") or {}
    if classes:
        by_outcome: dict[str, list[str]] = {}
        for cls, data in classes.items():
            outcome = data.get("outcome", "unknown") if isinstance(data, dict) else str(data)
            by_outcome.setdefault(outcome, []).append(cls)
        for outcome, cls_list in sorted(by_outcome.items()):
            lines.append(f"Acceptance [{outcome}]: {', '.join(sorted(cls_list))}")

    chars = acceptance.get("chars") or {}
    if chars and not classes:
        # Fall back to char-level summary when classes empty.
        accepted = [repr(c) if c == " " else c for c, d in chars.items()
                    if isinstance(d, dict) and d.get("outcome") in _SOFT_ACCEPT]
        rejected = [repr(c) if c == " " else c for c, d in chars.items()
                    if isinstance(d, dict) and d.get("outcome") == OUTCOME_REJECTED]
        if accepted:
            lines.append(f"Accepted chars: {' '.join(accepted[:40])}")
        if rejected:
            lines.append(f"Rejected chars: {' '.join(rejected[:40])}")

    length = obs.get("length") or {}
    if length.get("state") and length.get("state") != STATE_UNKNOWN:
        max_acc = length.get("max_accepted")
        lines.append(
            f"Length: state={length.get('state')}  max_accepted={max_acc}  "
            f"confidence={length.get('confidence', 0)}"
        )

    types = obs.get("types") or {}
    if types:
        by_outcome: dict[str, list[str]] = {}
        for tname, data in types.items():
            outcome = data.get("outcome", "unknown") if isinstance(data, dict) else str(data)
            by_outcome.setdefault(outcome, []).append(tname)
        for outcome, tlist in sorted(by_outcome.items()):
            lines.append(f"Types [{outcome}]: {', '.join(sorted(tlist))}")

    transforms = inferred.get("transforms") or []
    if transforms:
        lines.append(f"Transforms: {', '.join(transforms)}")

    tested = profile.get("tested") or {}
    if tested:
        rejected_keys = [
            k for k, v in tested.items()
            if isinstance(v, dict) and v.get("outcome") == OUTCOME_REJECTED
        ]
        if rejected_keys:
            lines.append(f"Tested-rejected: {', '.join(sorted(rejected_keys))}")

    caps = profile.get("capabilities") or []
    if caps:
        lines.append(f"Capabilities: {', '.join(caps)}")

    candidates = profile.get("candidates") or []
    if candidates:
        lines.append("Attack candidates (prioritization only — not confirmed vulns):")
        for cline in format_candidates_lines(candidates):
            lines.append(f"  {cline}")

    if synth.get("missing_analyses"):
        lines.append(
            "Missing analyses: " + ", ".join(synth["missing_analyses"])
        )

    return lines


# ---------------------------------------------------------------------------
# Internal — identity / baseline
# ---------------------------------------------------------------------------

def _resolve_identity(
    db_path: Path,
    param_uuid: str,
    probes: list[dict],
) -> dict[str, str]:
    """
    Purpose: Resolve host/location/name for a param_uuid from probes or profiles.
    """
    if probes:
        first = probes[0]
        return {
            "host": first.get("host") or "",
            "location": first.get("location") or "",
            "name": first.get("param_name") or "",
        }
    existing = iv_db.get_param_profile(db_path, param_uuid)
    if existing:
        return {
            "host": existing.get("host") or "",
            "location": existing.get("location") or "",
            "name": existing.get("name") or "",
        }
    return {"host": "", "location": "", "name": ""}


def _select_baseline(
    completed: list[dict],
) -> tuple[ResponseFingerprint | None, dict | None]:
    """
    Purpose:
        Prefer a completed baseline-analysis probe; else first completed probe
        with a usable body/status.
    """
    baselines = [p for p in completed if p.get("analysis") == "baseline"]
    candidates = baselines or completed
    for probe in candidates:
        try:
            fp = fingerprint_from_flow(_probe_as_flow(probe))
            return fp, probe
        except Exception:  # noqa: BLE001
            continue
    return None, None


def _probe_as_flow(probe: dict) -> dict:
    """
    Purpose:
        Map iv_probe_results JOIN row to fingerprint_from_flow input.
    """
    return {
        "id": probe.get("flow_id"),
        "flow_id": probe.get("flow_id"),
        "status_code": probe.get("status_code"),
        "content_type": probe.get("content_type") or "",
        "body": probe.get("body") or "",
        "response_body": probe.get("body") or "",
        "response_headers": probe.get("response_headers") or "{}",
        "duration_ms": probe.get("duration_ms"),
    }


# ---------------------------------------------------------------------------
# Internal — per-probe summary
# ---------------------------------------------------------------------------

def _summarize_probe(
    probe: dict,
    baseline_fp: ResponseFingerprint | None,
) -> dict[str, Any]:
    """
    Purpose:
        Fingerprint one probe, detect reflection, classify outcome vs baseline.
    """
    payload = probe.get("payload")
    payload_str = "" if payload is None else str(payload)
    body = probe.get("body") or ""
    ct = probe.get("content_type") or ""
    analysis = probe.get("analysis") or ""
    payload_type = probe.get("payload_type") or probe.get("payload_class") or ""
    flow_id = probe.get("flow_id") or ""

    flow = _probe_as_flow(probe)
    try:
        probe_fp = fingerprint_from_flow(flow)
    except Exception:  # noqa: BLE001
        probe_fp = None

    # Multiprobe: prefer canary-aware analyzer over whole-payload reflection.
    multiprobe_analysis: dict[str, Any] | None = None
    multiprobe_classes: list[str] = list(probe.get("multiprobe_classes") or [])
    multiprobe_class_outcomes: dict[str, Any] = dict(
        probe.get("multiprobe_class_outcomes") or {}
    )
    is_multiprobe_row = (
        analysis == "multiprobe"
        or payload_type == "multiprobe"
        or bool(probe.get("multiprobe_classes"))
        or bool(probe.get("multiprobe_class_outcomes"))
    )

    if is_multiprobe_row and (
        analysis == "multiprobe" or payload_type == "multiprobe"
    ):
        # Classify whole-probe fingerprint first so analyzer can use it when
        # nothing is reflected (lower confidence charset path).
        pre_outcome: str | None = None
        pre_conf: int | None = None
        if baseline_fp is not None and probe_fp is not None:
            pre = classify_outcome(
                baseline_fp,
                probe_fp,
                {"reflected": False, "encoding": "", "transforms": []},
            )
            pre_outcome = pre.get("outcome")
            pre_conf = pre.get("confidence")

        plan = parse_multiprobe_payload(payload_str)
        if plan is not None:
            mp = analyze_multiprobe_response(
                plan,
                body,
                ct,
                fingerprint_outcome=pre_outcome,
                fingerprint_confidence=pre_conf,
            )
            multiprobe_analysis = mp.to_dict()
            # Prefer analyzer results; keep pre-seeded classes if analyzer empty.
            if mp.multiprobe_classes:
                multiprobe_classes = list(mp.multiprobe_classes)
            if mp.class_outcomes:
                multiprobe_class_outcomes = dict(mp.class_outcomes)
            refl = {
                "reflected": mp.canary_reflected,
                "encoding": mp.canary_encoding,
                "transforms": list(mp.canary_transforms),
                "location": mp.location,
                "payload_in_body": mp.canary_reflected,
            }
        else:
            # Non-self-describing payload (tests / legacy rows): keep injected
            # multiprobe_classes and use whole-payload reflection.
            refl = detect_payload_reflection(payload_str, body, ct)
    else:
        refl = detect_payload_reflection(payload_str, body, ct)

    reflection_hints = {
        "reflected": refl["reflected"],
        "encoding": refl.get("encoding") or "",
        "transforms": refl.get("transforms") or [],
        "payload_in_body": refl.get("payload_in_body", refl["reflected"]),
    }

    outcome = OUTCOME_UNKNOWN
    confidence = 0
    reasons: list[str] = []
    delta: dict[str, Any] | None = None

    if baseline_fp is not None and probe_fp is not None:
        if analysis == "baseline":
            outcome = OUTCOME_ACCEPTED
            confidence = 95
            reasons = ["baseline probe"]
        else:
            classified = classify_outcome(baseline_fp, probe_fp, reflection_hints)
            outcome = classified["outcome"]
            confidence = classified["confidence"]
            reasons = classified["reasons"]
            delta = classified.get("delta")
    elif probe_fp is not None:
        # No baseline — weak status-only classification.
        if probe_fp.status_code is not None and probe_fp.status_code >= 400:
            outcome = OUTCOME_REJECTED
            confidence = 50
            reasons = ["no baseline; probe status >= 400"]
        else:
            outcome = OUTCOME_UNKNOWN
            confidence = 30
            reasons = ["no baseline fingerprint"]

    # Length index → payload length for length phase.
    length_value: int | None = None
    if analysis == "length":
        length_value = len(payload_str)
        # Module 6: detect truncation via longest reflected prefix of a
        # homogeneous length payload (e.g. "a" * N).  Distinguishes hard
        # reject from server-side field truncation when reflection exists.
        if payload_str and body and outcome in _SOFT_ACCEPT:
            prefix_len = _reflected_prefix_length(payload_str, body)
            if 0 < prefix_len < len(payload_str):
                outcome = OUTCOME_TRUNCATED
                confidence = max(int(confidence), 80)
                reasons = list(reasons) + [
                    f"reflected_prefix={prefix_len}<sent={len(payload_str)}"
                ]
                refl = dict(refl)
                refl["reflected_length"] = prefix_len
                refl["reflected"] = True
                refl["payload_in_body"] = True

    return {
        "analysis": analysis,
        "payload": payload_str,
        "payload_type": payload_type,
        "payload_index": probe.get("payload_index", 0),
        "flow_id": flow_id,
        "status_code": probe.get("status_code"),
        "content_type": ct,
        "outcome": outcome,
        "confidence": confidence,
        "reasons": reasons,
        "delta": delta,
        "reflection": refl,
        "fingerprint": probe_fp.to_dict() if probe_fp else None,
        "duration_ms": probe_fp.duration_ms if probe_fp else None,
        "length_value": length_value,
        # M4 multiprobe: class list + per-class outcomes for acceptance fold-in.
        "multiprobe_classes": multiprobe_classes,
        "multiprobe_class_outcomes": multiprobe_class_outcomes,
        "multiprobe_analysis": multiprobe_analysis,
    }


def _reflected_prefix_length(payload: str, body: str) -> int:
    """
    Purpose:
        Longest prefix of ``payload`` that appears as a contiguous substring
        of ``body``.  Used for length-probe truncation detection when the
        full payload is not reflected but a shorter run is.
    Side effects: None.
    """
    if not payload or not body:
        return 0
    if payload in body:
        return len(payload)
    # Homogeneous payloads (length probes use "a" * N): binary-search longest
    # run of the fill character that appears in the body.
    fill = payload[0]
    if payload == fill * len(payload):
        lo, hi = 0, len(payload)
        best = 0
        while lo <= hi:
            mid = (lo + hi) // 2
            if mid > 0 and (fill * mid) in body:
                best = mid
                lo = mid + 1
            else:
                hi = mid - 1
        return best
    # Heterogeneous: try progressively shorter prefixes (log steps).
    n = len(payload)
    step = max(1, n // 16)
    for length in range(n - step, 0, -step):
        if payload[:length] in body:
            # Fine-tune upward.
            end = min(n, length + step)
            best = length
            for fine in range(length + 1, end + 1):
                if payload[:fine] in body:
                    best = fine
                else:
                    break
            return best
    # Single-char fallback.
    if payload[0] in body:
        return 1
    return 0


# ---------------------------------------------------------------------------
# Internal — aggregates
# ---------------------------------------------------------------------------

def _fill_acceptance(profile: dict[str, Any], summaries: list[dict]) -> None:
    """
    Purpose:
        Aggregate character + multiprobe probes into observed.acceptance.
    """
    char_summaries = [s for s in summaries if s.get("analysis") == "characters"]
    multi_summaries = [
        s for s in summaries
        if s.get("analysis") == "multiprobe" or s.get("payload_type") == "multiprobe"
    ]
    chars: dict[str, Any] = {}
    class_outcomes: dict[str, list[tuple[str, int, str]]] = {}

    for s in char_summaries:
        ch = s.get("payload") or ""
        if len(ch) != 1 and ch != "\x00":
            # Legacy multiprobe-as-characters path.
            for mcls in s.get("multiprobe_classes") or []:
                class_outcomes.setdefault(str(mcls), []).append(
                    (s["outcome"], s["confidence"], s.get("flow_id") or "")
                )
            continue
        key = ch
        chars[key] = {
            "outcome": s["outcome"],
            "confidence": s["confidence"],
            "evidence_flow_ids": [s["flow_id"]] if s.get("flow_id") else [],
        }
        for cls in char_to_taxonomy_classes(ch):
            class_outcomes.setdefault(cls, []).append(
                (s["outcome"], s["confidence"], s.get("flow_id") or "")
            )

    # Multiprobe per-class outcomes (prefer analyzer results over whole-probe).
    multiprobe_source_classes: set[str] = set()
    for s in multi_summaries:
        flow = s.get("flow_id") or ""
        per_class = s.get("multiprobe_class_outcomes") or {}
        if per_class:
            for cls, entry in per_class.items():
                if not isinstance(entry, dict):
                    continue
                multiprobe_source_classes.add(str(cls))
                class_outcomes.setdefault(str(cls), []).append(
                    (
                        str(entry.get("outcome") or OUTCOME_UNKNOWN),
                        int(entry.get("confidence") or 0),
                        flow,
                    )
                )
        else:
            for mcls in s.get("multiprobe_classes") or []:
                multiprobe_source_classes.add(str(mcls))
                class_outcomes.setdefault(str(mcls), []).append(
                    (s["outcome"], s["confidence"], flow)
                )

    classes: dict[str, Any] = {}
    for cls, outcomes in class_outcomes.items():
        entry = _majority_outcome_entry(outcomes)
        if cls in multiprobe_source_classes:
            entry["source"] = "multiprobe"
        classes[cls] = entry

    profile["observed"]["acceptance"] = {
        "classes": classes,
        "chars": chars,
    }

    # Negative evidence for rejected classes.
    for cls, entry in classes.items():
        if entry.get("outcome") == OUTCOME_REJECTED:
            set_tested(
                profile,
                cls,
                outcome=OUTCOME_REJECTED,
                confidence=int(entry.get("confidence") or 0),
                evidence_flow_ids=entry.get("evidence_flow_ids"),
            )


def _fill_types(
    profile: dict[str, Any],
    summaries: list[dict],
    *,
    identity: dict[str, str] | None = None,
    db_path: Path | str | None = None,
) -> None:
    """
    Purpose:
        Aggregate type-phase probes into observed.types with confidence,
        conflict detection (Module 7), and tested.type:* negative evidence.
    """
    types: dict[str, Any] = {}
    for s in summaries:
        if s.get("analysis") != "types":
            continue
        tname = s.get("payload_type") or "unknown"
        if tname.startswith("_"):
            continue
        types[tname] = {
            "outcome": s["outcome"],
            "confidence": s["confidence"],
            "evidence_flow_ids": [s["flow_id"]] if s.get("flow_id") else [],
            "status_code": s.get("status_code"),
        }

    passive_semantic = "unknown"
    examples: list[str] = []
    if db_path and identity and identity.get("host"):
        passive_semantic, examples = _load_passive_type_fields(
            Path(db_path),
            host=identity["host"],
            location=identity.get("location") or "",
            name=identity.get("name") or profile.get("name") or "",
        )

    passive = resolve_passive_type(
        semantic_type=passive_semantic,
        examples=examples,
        param_name=str(profile.get("name") or (identity or {}).get("name") or ""),
    )
    inferred = profile.get("inferred") if isinstance(profile.get("inferred"), dict) else {}
    if isinstance(inferred, dict) and inferred.get("passive_type"):
        # Keep prior intermediate inference only when DB passive is unknown.
        if passive in ("unknown", "string"):
            passive = str(inferred.get("passive_type") or passive)

    synth = synthesize_type_state(types, passive_type=passive)
    profile["observed"]["types"] = types_summary_block(synth)
    merge_type_tested(profile, types)

    # Surface conflict under inferred for operators / later planners.
    if not isinstance(profile.get("inferred"), dict):
        profile["inferred"] = {}
    profile["inferred"]["passive_type"] = synth.passive_type
    profile["inferred"]["primary_type"] = synth.primary
    if synth.conflict_note:
        profile["inferred"]["type_conflict"] = synth.conflict_note


def _load_passive_type_fields(
    db_path: Path,
    *,
    host: str,
    location: str,
    name: str,
) -> tuple[str, list[str]]:
    """
    Purpose:
        Read parameters.semantic_type + example_values for synthesis.
    Output: (semantic_type, examples).
    Side effects: Read-only DB.
    """
    try:
        with sqlite3.connect(str(db_path)) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                """
                SELECT p.semantic_type, p.example_values
                FROM parameters p
                JOIN endpoints e ON e.id = p.endpoint_id
                WHERE e.host = ? AND p.location = ? AND p.name = ?
                ORDER BY p.seen_count DESC
                LIMIT 1
                """,
                (host, location, name),
            ).fetchone()
        if not row:
            return "unknown", []
        st = (row["semantic_type"] or "unknown").strip().lower() or "unknown"
        try:
            examples = json.loads(row["example_values"] or "[]")
        except (json.JSONDecodeError, TypeError):
            examples = []
        if not isinstance(examples, list):
            examples = []
        return st, [str(x) for x in examples if x is not None]
    except sqlite3.Error:
        return "unknown", []


def _fill_length(profile: dict[str, Any], summaries: list[dict]) -> None:
    """
    Purpose:
        Estimate max accepted length, truncation vs hard reject, confidence.
        Module 6: uses length_search.synthesize_length_state (binary/log method).
    """
    length_rows = [s for s in summaries if s.get("analysis") == "length"]
    if not length_rows:
        profile["observed"]["length"] = empty_characteristic(
            state=STATE_UNKNOWN,
            confidence=0,
            uncertainty=UNCERTAINTY_HIGH,
        )
        return

    evidence: list[str] = []
    reflected_prefix: dict[int, int] = {}
    for s in length_rows:
        if s.get("flow_id"):
            evidence.append(s["flow_id"])
        # Truncation via reflection: payload longer than what is echoed back.
        lv = s.get("length_value")
        if lv is None:
            lv = len(s.get("payload") or "")
        try:
            sent = int(lv)
        except (TypeError, ValueError):
            continue
        refl = s.get("reflection") or {}
        payload = s.get("payload") or ""
        body_hint = refl.get("reflected_length")
        if body_hint is not None:
            try:
                reflected_prefix[sent] = int(body_hint)
            except (TypeError, ValueError):
                pass
        elif (
            refl.get("reflected")
            and isinstance(payload, str)
            and payload
            and s.get("outcome") in (_SOFT_ACCEPT | {OUTCOME_TRUNCATED})
        ):
            # If only a proper prefix is reflected, treat as truncation bound.
            # detect_payload_reflection does not expose prefix length; when
            # outcome is truncated, use max_accepted heuristic via synthesizer.
            pass

    observed = parse_length_outcomes(length_rows)
    budget_tier = str(profile.get("budget_tier") or "standard")
    profile["observed"]["length"] = synthesize_length_state(
        observed,
        strategy=budget_tier,
        evidence_flow_ids=evidence,
        reflected_prefix_lengths=reflected_prefix or None,
    )


def _fill_validation_tested(profile: dict[str, Any], summaries: list[dict]) -> None:
    """
    Purpose:
        Map validation / semantic probes into tested[] (Module 7 negative
        evidence discipline).  Every completed validation family is recorded;
        rejects are first-class so attack modules can skip hopeless families.
    """
    semantic_obs: dict[str, Any] = {}
    for s in summaries:
        if s.get("analysis") != "validation":
            continue
        ptype = s.get("payload_type") or "validation"
        key = _VALIDATION_TAXONOMY_KEYS.get(ptype) or tested_key_for_payload_type(ptype)
        flows = [s["flow_id"]] if s.get("flow_id") else None
        # Always record validation family outcomes (positive or negative).
        set_tested(
            profile,
            key,
            outcome=s["outcome"],
            confidence=s["confidence"],
            evidence_flow_ids=flows,
        )
        # Alias null_byte → null taxonomy key when rejected.
        if ptype == "null_byte" and s["outcome"] == OUTCOME_REJECTED and key != "null":
            set_tested(
                profile,
                "null",
                outcome=OUTCOME_REJECTED,
                confidence=s["confidence"],
                evidence_flow_ids=flows,
            )
        # CRLF / unicode aliases for attack-module consumers.
        if ptype == "crlf":
            set_tested(
                profile,
                "crlf",
                outcome=s["outcome"],
                confidence=s["confidence"],
                evidence_flow_ids=flows,
            )
        semantic_obs[ptype] = {
            "outcome": s["outcome"],
            "confidence": s["confidence"],
            "evidence_flow_ids": flows or [],
        }

    if semantic_obs:
        if not isinstance(profile.get("observed"), dict):
            profile["observed"] = {}
        profile["observed"]["semantic"] = semantic_obs


def _fill_parser_and_normalization(
    profile: dict[str, Any],
    completed_probes: list[dict],
    summaries: list[dict],
) -> None:
    """
    Purpose:
        Module 8 — fold parser/normalization probe evidence into
        observed.parser, normalization_pipeline, inferred.parser_family,
        capabilities, and tested{} negatives.
    Side effects: Mutates profile.
    """
    # Index body text from completed probes (joined with flow in probe rows).
    body_by_flow: dict[str, str] = {}
    status_by_flow: dict[str, int | None] = {}
    for p in completed_probes:
        fid = p.get("flow_id")
        if not fid:
            continue
        body_by_flow[str(fid)] = str(p.get("body") or "")
        sc = p.get("status_code")
        try:
            status_by_flow[str(fid)] = int(sc) if sc is not None else None
        except (TypeError, ValueError):
            status_by_flow[str(fid)] = None

    rows: list[dict[str, Any]] = []
    for s in summaries:
        if s.get("analysis") != "parser":
            continue
        fid = s.get("flow_id")
        rows.append({
            "payload_type": s.get("payload_type"),
            "payload": s.get("payload"),
            "outcome": s.get("outcome"),
            "confidence": s.get("confidence"),
            "body": body_by_flow.get(str(fid or ""), ""),
            "status_code": status_by_flow.get(str(fid or "")),
            "flow_id": fid,
            "evidence_flow_ids": [fid] if fid else [],
            "analysis": "parser",
        })

    if not rows:
        return

    location = str(profile.get("location") or "query")
    synth = synthesize_parser_state(rows, location=location)
    apply_parser_synthesis_to_profile(profile, synth)

    # Enrich inferred.transforms when pipeline detected trim/case (legacy path).
    if synth.normalization_pipeline:
        if not isinstance(profile.get("inferred"), dict):
            profile["inferred"] = {}
        existing = list(profile["inferred"].get("transforms") or [])
        for stage in synth.normalization_pipeline:
            name = stage.get("stage")
            if name == "trim" and "trim" not in existing:
                existing.append("trim")
            if name == "case_fold":
                evidence = str(stage.get("evidence") or "")
                if "lower" in evidence and "lowercase" not in existing:
                    existing.append("lowercase")
                elif "upper" in evidence and "uppercase" not in existing:
                    existing.append("uppercase")
                elif "case_fold" not in existing and "lowercase" not in existing:
                    existing.append("case_fold")
            if name == "url_decode" and "url_decode" not in existing:
                existing.append("url_decode")
        profile["inferred"]["transforms"] = existing


def _fill_url_sink(
    profile: dict[str, Any],
    completed_probes: list[dict],
    summaries: list[dict],
    *,
    baseline_fp: ResponseFingerprint | None = None,
) -> None:
    """
    Purpose:
        URL Sink Discovery Phase 3 — fold url_sink canary probe evidence into
        observed.url_sink and tested.url_sink:* (characterization only).
    Side effects: Mutates profile.
    """
    body_by_flow: dict[str, str] = {}
    status_by_flow: dict[str, int | None] = {}
    headers_by_flow: dict[str, Any] = {}
    for p in completed_probes:
        fid = p.get("flow_id")
        if not fid:
            continue
        body_by_flow[str(fid)] = str(p.get("body") or "")
        sc = p.get("status_code")
        try:
            status_by_flow[str(fid)] = int(sc) if sc is not None else None
        except (TypeError, ValueError):
            status_by_flow[str(fid)] = None
        headers_by_flow[str(fid)] = p.get("response_headers")

    rows: list[dict[str, Any]] = []
    for s in summaries:
        if s.get("analysis") != "url_sink":
            continue
        fid = s.get("flow_id")
        # Prefer fingerprint extras when present on the summary.
        fp = s.get("fingerprint") or {}
        redirect = None
        error_sig = None
        duration = s.get("duration_ms")
        if isinstance(fp, dict):
            redirect = fp.get("redirect")
            error_sig = fp.get("error_signature")
            if duration is None:
                duration = fp.get("duration_ms")
        rows.append({
            "payload_type": s.get("payload_type"),
            "payload": s.get("payload"),
            "outcome": s.get("outcome"),
            "confidence": s.get("confidence"),
            "body": body_by_flow.get(str(fid or ""), ""),
            "status_code": status_by_flow.get(str(fid or "")),
            "response_headers": headers_by_flow.get(str(fid or "")),
            "redirect": redirect,
            "error_signature": error_sig,
            "duration_ms": duration,
            "flow_id": fid,
            "analysis": "url_sink",
        })

    if not rows:
        return

    baseline_ms: float | None = None
    if baseline_fp is not None and baseline_fp.duration_ms is not None:
        try:
            baseline_ms = float(baseline_fp.duration_ms)
        except (TypeError, ValueError):
            baseline_ms = None

    synth = synthesize_url_sink_state(rows, baseline_duration_ms=baseline_ms)
    apply_url_sink_synthesis_to_profile(profile, synth)


def _fill_transforms(profile: dict[str, Any], completed_probes: list[dict]) -> None:
    """
    Purpose:
        Reuse phases.analyze_transformations on multiprobe/identifier/character
        probes.
    """
    # Prefer multiprobe + identifier + characters + parser norm probes;
    # fall back to all with payloads.
    records = [
        p for p in completed_probes
        if p.get("analysis") in (
            "multiprobe", "identifier", "characters", "types", "parser",
        )
        and p.get("payload")
    ]
    if not records:
        records = [p for p in completed_probes if p.get("payload")]

    result = analyze_transformations(records)
    transforms = result.get("transformations") or []
    if not isinstance(profile.get("inferred"), dict):
        profile["inferred"] = {}
    profile["inferred"]["transforms"] = list(transforms)
    if result.get("evidence"):
        profile["inferred"]["transform_evidence"] = result["evidence"][:10]


def _fill_reflection(
    profile: dict[str, Any],
    completed_probes: list[dict],
    summaries: list[dict],
) -> None:
    """
    Purpose:
        Aggregate reflection state with conflict detection.
        Conflicting signals → state=conflicting, reduced confidence.
    """
    # Prefer multiprobe + identifier probes for reflection signal quality.
    id_summaries = [
        s for s in summaries
        if s.get("analysis") in ("multiprobe", "identifier")
    ]
    sample = id_summaries or [
        s for s in summaries
        if s.get("analysis") not in ("baseline", "length") and s.get("payload")
    ]

    reflected_yes = [s for s in sample if s.get("reflection", {}).get("reflected")]
    reflected_no = [s for s in sample if not s.get("reflection", {}).get("reflected")]

    encodings = [
        s["reflection"]["encoding"]
        for s in reflected_yes
        if s.get("reflection", {}).get("encoding")
    ]
    contexts = [
        s["reflection"]["location"]
        for s in reflected_yes
        if s.get("reflection", {}).get("location")
    ]
    evidence = [s["flow_id"] for s in reflected_yes if s.get("flow_id")]

    # Also run phases.analyze_reflection for compatibility fields.
    endpoint_id = ""
    param_name = profile.get("name") or ""
    for p in completed_probes:
        if p.get("endpoint_id"):
            endpoint_id = p["endpoint_id"]
            break
    bulk = analyze_reflection(completed_probes, param_name, endpoint_id)

    n_yes = len(reflected_yes)
    n_no = len(reflected_no)
    n = n_yes + n_no

    if n == 0:
        state = STATE_UNKNOWN
        conf = 0
        uncertainty = UNCERTAINTY_HIGH
    elif n_yes > 0 and n_no > 0:
        # Conflict: some probes reflected, some did not.
        ratio = n_yes / n
        if 0.3 <= ratio <= 0.7:
            state = STATE_CONFLICTING
            conf = max(20, int(50 - abs(0.5 - ratio) * 40))
            uncertainty = UNCERTAINTY_HIGH
        elif ratio > 0.7:
            state = "reflected"
            conf = min(85, 50 + int(ratio * 40))
            uncertainty = UNCERTAINTY_LOW
        else:
            state = "not_reflected"
            conf = min(85, 50 + int((1 - ratio) * 40))
            uncertainty = UNCERTAINTY_LOW
    elif n_yes > 0:
        state = "reflected"
        conf = min(95, 60 + n_yes * 4)
        uncertainty = UNCERTAINTY_NONE if n_yes >= 3 else UNCERTAINTY_LOW
    else:
        state = "not_reflected"
        conf = min(90, 55 + n_no * 3)
        uncertainty = UNCERTAINTY_NONE if n_no >= 3 else UNCERTAINTY_LOW

    # Encoding consensus
    encoding = ""
    if encodings:
        # Most common encoding.
        encoding = max(set(encodings), key=encodings.count)
        if len(set(encodings)) > 1 and state != STATE_CONFLICTING:
            conf = max(30, conf - 10)
            uncertainty = UNCERTAINTY_LOW if uncertainty == UNCERTAINTY_NONE else uncertainty

    # Prefer bulk encoding when we have no per-probe encoding.
    if not encoding and bulk.get("encoding"):
        encoding = bulk["encoding"]

    unique_contexts = sorted({c for c in contexts if c})
    if not unique_contexts and bulk.get("reflection_location"):
        unique_contexts = [bulk["reflection_location"]]

    # Map js location name
    mapped_contexts = []
    for c in unique_contexts:
        if c == "javascript":
            mapped_contexts.append("js")
        else:
            mapped_contexts.append(c)

    profile["observed"]["reflection"] = empty_characteristic(
        state=state,
        confidence=conf,
        uncertainty=uncertainty,
        evidence_flow_ids=evidence[:20] or list(bulk.get("evidence_flow_ids") or [])[:20],
        extra={
            "contexts": mapped_contexts,
            "encoding": encoding or bulk.get("encoding") or "",
            "reflection_count": bulk.get("reflection_count") or n_yes,
            "reflected_payloads": (bulk.get("reflected_payloads") or [])[:12],
        },
    )


def _fill_attempts(profile: dict[str, Any], summaries: list[dict]) -> None:
    """
    Purpose:
        Bounded mutation history from probe summaries (skip pure baseline).
    """
    non_baseline = [s for s in summaries if s.get("analysis") != "baseline"]
    # Prefer interesting outcomes; keep chronological order by analysis groups.
    for s in non_baseline[:MAX_ATTEMPTS]:
        hypothesis = _hypothesis_for_summary(s)
        delta = s.get("delta")
        delta_summary: str | dict | None = None
        if isinstance(delta, dict):
            changed = delta.get("changed") or []
            delta_summary = ",".join(changed) if changed else "identical"
        append_attempt(
            profile,
            payload=s.get("payload") or "",
            hypothesis=hypothesis,
            result=s.get("outcome") or OUTCOME_UNKNOWN,
            confidence=int(s.get("confidence") or 0),
            flow_id=s.get("flow_id") or None,
            fingerprint_delta=delta_summary,
        )


def _hypothesis_for_summary(s: dict) -> str:
    analysis = s.get("analysis") or "probe"
    ptype = s.get("payload_type") or ""
    if analysis == "characters":
        classes = char_to_taxonomy_classes(s.get("payload") or "")
        if classes:
            return f"charset.{classes[0]}_accepted"
        return "charset.char_accepted"
    if analysis == "types":
        return f"type.{ptype or 'unknown'}"
    if analysis == "length":
        return f"length.{s.get('length_value') or len(s.get('payload') or '')}"
    if analysis == "validation":
        return f"validation.{ptype or 'edge'}"
    if analysis == "identifier":
        return "identifier.reflection"
    if analysis == "multiprobe" or s.get("multiprobe_classes"):
        classes = s.get("multiprobe_classes") or []
        if classes:
            return "multiprobe." + "+".join(str(c) for c in classes[:4])
        return "multiprobe.canary_reflection"
    return f"{analysis}.{ptype or 'probe'}"


def _fill_surface(
    profile: dict[str, Any],
    identity: dict[str, str],
    completed: list[dict],
) -> None:
    """
    Purpose:
        Module 9: record uniform surface descriptor on observed.surface
        (location + kind) for path/header/cookie/body subtypes.
    Side effects: Mutates profile.
    """
    from talos.input_validation.surface import detect_surface_kind, surface_meta

    location = str(identity.get("location") or profile.get("location") or "")
    name = str(identity.get("name") or profile.get("name") or "")
    ct = ""
    baseline = (profile.get("observed") or {}).get("baseline_fingerprint") or {}
    if isinstance(baseline, dict):
        ct = str(baseline.get("content_type") or "")
    # Prefer request content-type from any completed probe flow if available.
    for probe in completed:
        rh = probe.get("request_headers")
        if not rh:
            continue
        try:
            hdrs = json.loads(rh) if isinstance(rh, str) else dict(rh)
        except (TypeError, ValueError):
            continue
        for k, v in hdrs.items():
            if str(k).lower() == "content-type":
                ct = (v if isinstance(v, str) else (v[0] if v else "")).lower()
                break
        if ct:
            break

    meta = surface_meta(
        location=location,
        param_name=name,
        content_type=ct,
        semantic_type="",
    )
    # Preserve skip info if already set (auth-artifact skip profiles).
    existing = (profile.get("observed") or {}).get("surface")
    if isinstance(existing, dict) and existing.get("skipped"):
        meta["skipped"] = True
        meta["skip_reason"] = existing.get("skip_reason", "")
        meta["skip_detail"] = existing.get("skip_detail", "")
    profile.setdefault("observed", {})["surface"] = meta


def _fill_capabilities(profile: dict[str, Any], location: str) -> None:
    """
    Purpose:
        Module 11 capability derivation + attack candidate scoring.

        Ensures ``observed.surface.kind`` is populated when missing (Module 9),
        then delegates to ``capabilities`` / ``candidates`` (central rules).

    Side effects: Mutates profile capabilities, candidates, and surface meta.
    """
    from talos.input_validation.surface import detect_surface_kind

    # Keep location identity on the profile for derive_capabilities.
    if location and not profile.get("location"):
        profile["location"] = location

    obs = profile.setdefault("observed", {})
    if not isinstance(obs, dict):
        profile["observed"] = {}
        obs = profile["observed"]

    surface_obs = obs.get("surface") if isinstance(obs.get("surface"), dict) else {}
    kind = str(surface_obs.get("kind") or "")
    baseline_fp = obs.get("baseline_fingerprint") or {}
    ct = ""
    if isinstance(baseline_fp, dict):
        ct = str(baseline_fp.get("content_type") or "")
    if not kind:
        kind = detect_surface_kind(
            location=location or str(profile.get("location") or ""),
            param_name=str(profile.get("name") or ""),
            content_type=ct,
            semantic_type="",
        )
        if kind:
            obs.setdefault("surface", {})
            if not isinstance(obs["surface"], dict):
                obs["surface"] = {}
            obs["surface"]["kind"] = kind
            obs["surface"]["location"] = location or str(profile.get("location") or "")

    enrich_profile_capabilities_and_candidates(profile)


def _missing_scan_analyses(completed: set[str]) -> list[str]:
    """
    Purpose:
        Compute which scan analyses are still missing for a full profile.

        Multiprobe covers identifier + characters for Module 4 volume reduction:
        if multiprobe is present, those phases are not required.  Conversely,
        legacy identifier/characters without multiprobe do not require multiprobe.
    Side effects: None.
    """
    missing = set(SCAN_ANALYSES) - set(completed)
    if "multiprobe" in completed:
        missing.discard("identifier")
        missing.discard("characters")
    if "identifier" in completed or "characters" in completed:
        missing.discard("multiprobe")
    # Length / types / validation remain optional for "partial" severity notes
    # but still listed when absent so operators know the matrix is incomplete.
    return sorted(missing)


def _fill_synthesis_meta(
    profile: dict[str, Any],
    all_probes: list[dict],
    summaries: list[dict],
) -> None:
    """
    Purpose:
        Record partial flags, missing analyses, and confidence notes.
    """
    completed_analyses = sorted({
        (p.get("analysis") or "")
        for p in all_probes
        if p.get("status") == iv_db.STATUS_COMPLETED and p.get("analysis")
    })
    missing = _missing_scan_analyses(set(completed_analyses))
    partial = bool(missing) or any(
        (profile.get("observed") or {}).get("reflection", {}).get("state") == STATE_CONFLICTING
        for _ in (0,)
    )

    # Also partial when confidence is globally low and few probes.
    # Multiprobe path: baseline + multiprobe (2) is enough for non-partial
    # when required analyses are present and no conflict.
    completed_count = sum(
        1 for p in all_probes if p.get("status") == iv_db.STATUS_COMPLETED
    )
    has_multiprobe = "multiprobe" in completed_analyses
    min_probes = 2 if has_multiprobe else 5
    if completed_count < min_probes:
        partial = True

    notes: list[str] = []
    refl_state = ((profile.get("observed") or {}).get("reflection") or {}).get("state")
    if refl_state == STATE_CONFLICTING:
        notes.append("conflicting reflection signals")
    if missing:
        notes.append("missing analyses: " + ",".join(missing))

    if not isinstance(profile.get("inferred"), dict):
        profile["inferred"] = {}
    profile["inferred"]["synthesis"] = {
        "partial": partial,
        "source": "offline_probes",
        "completed_probe_count": completed_count,
        "probe_row_count": len(all_probes),
        "completed_analyses": completed_analyses,
        "missing_analyses": missing,
        "classified_probe_count": len(summaries),
        "notes": notes,
    }


def _apply_multiprobe_extension_hooks(
    profile: dict[str, Any],
    summaries: list[dict],
) -> None:
    """
    Purpose:
        Fold Module 4 multiprobe per-class outcomes into acceptance.classes.

        Prefer ``multiprobe_class_outcomes`` from the analyzer; fall back to
        shared probe outcome for legacy ``multiprobe_classes`` lists.
        Also records multiprobe canary transforms into inferred.transforms.

    Side effects: May mutate profile observed.acceptance / inferred / tested.
    """
    multi = [
        s for s in summaries
        if s.get("multiprobe_classes")
        or s.get("multiprobe_class_outcomes")
        or s.get("analysis") == "multiprobe"
    ]
    if not multi:
        return

    acceptance = profile.setdefault("observed", {}).setdefault("acceptance", {})
    classes = acceptance.setdefault("classes", {})
    for s in multi:
        flow_ids = [s["flow_id"]] if s.get("flow_id") else []
        per_class = s.get("multiprobe_class_outcomes") or {}
        if per_class:
            for mcls, entry in per_class.items():
                key = str(mcls)
                if not isinstance(entry, dict):
                    continue
                outcome = str(entry.get("outcome") or OUTCOME_UNKNOWN)
                conf = int(entry.get("confidence") or 0)
                if key not in classes:
                    classes[key] = {
                        "outcome": outcome,
                        "confidence": conf,
                        "evidence_flow_ids": list(flow_ids),
                        "source": "multiprobe",
                        "encoding": entry.get("encoding") or "",
                    }
                else:
                    existing = classes[key]
                    # Prefer higher-confidence multiprobe observation.
                    if conf >= int(existing.get("confidence") or 0):
                        existing["outcome"] = outcome
                        existing["confidence"] = conf
                        existing["source"] = "multiprobe"
                        if entry.get("encoding"):
                            existing["encoding"] = entry["encoding"]
                        ids = list(existing.get("evidence_flow_ids") or [])
                        for fid in flow_ids:
                            if fid and fid not in ids:
                                ids.append(fid)
                        existing["evidence_flow_ids"] = ids[:20]
                if outcome == OUTCOME_REJECTED:
                    set_tested(
                        profile,
                        key,
                        outcome=OUTCOME_REJECTED,
                        confidence=conf,
                        evidence_flow_ids=flow_ids or None,
                    )
            continue

        # Legacy list-only path.
        for mcls in s.get("multiprobe_classes") or []:
            key = str(mcls)
            if key not in classes:
                classes[key] = {
                    "outcome": s["outcome"],
                    "confidence": max(0, int(s["confidence"]) - 5),
                    "evidence_flow_ids": list(flow_ids),
                    "source": "multiprobe",
                }
            elif s["outcome"] == OUTCOME_REJECTED:
                existing = classes[key]
                if existing.get("outcome") in _SOFT_ACCEPT:
                    existing["confidence"] = max(
                        20, int(existing.get("confidence") or 0) - 15
                    )
                    existing["uncertainty"] = UNCERTAINTY_LOW

    # Merge canary transform hints from multiprobe reflection.
    tx: set[str] = set()
    if isinstance(profile.get("inferred"), dict):
        for t in profile["inferred"].get("transforms") or []:
            tx.add(str(t))
    for s in multi:
        for t in (s.get("reflection") or {}).get("transforms") or []:
            tx.add(str(t))
        ma = s.get("multiprobe_analysis") or {}
        for t in ma.get("canary_transforms") or []:
            tx.add(str(t))
    if tx:
        if not isinstance(profile.get("inferred"), dict):
            profile["inferred"] = {}
        profile["inferred"]["transforms"] = sorted(tx)


def _majority_outcome_entry(
    outcomes: list[tuple[str, int, str]],
) -> dict[str, Any]:
    """
    Purpose:
        Collapse multiple (outcome, confidence, flow_id) into one class entry.
        Conflicts lower confidence and may set uncertainty.
    """
    if not outcomes:
        return {
            "outcome": OUTCOME_UNKNOWN,
            "confidence": 0,
            "uncertainty": UNCERTAINTY_HIGH,
            "evidence_flow_ids": [],
        }

    counts: dict[str, int] = {}
    conf_sum: dict[str, int] = {}
    flows: list[str] = []
    for outcome, conf, flow_id in outcomes:
        counts[outcome] = counts.get(outcome, 0) + 1
        conf_sum[outcome] = conf_sum.get(outcome, 0) + int(conf)
        if flow_id:
            flows.append(flow_id)

    winner = max(counts.keys(), key=lambda o: (counts[o], conf_sum.get(o, 0)))
    n = len(outcomes)
    win_n = counts[winner]
    avg_conf = conf_sum[winner] // max(1, win_n)

    if len(counts) == 1:
        uncertainty = UNCERTAINTY_NONE if n >= 2 else UNCERTAINTY_LOW
        conf = min(95, avg_conf + min(10, n * 2))
    elif win_n / n >= 0.7:
        uncertainty = UNCERTAINTY_LOW
        conf = max(30, avg_conf - 10)
    else:
        # Strong conflict among class members.
        uncertainty = UNCERTAINTY_HIGH
        conf = max(20, avg_conf - 25)
        # Prefer rejected if any reject when conflict is tight? keep majority.

    return {
        "outcome": winner,
        "confidence": conf,
        "uncertainty": uncertainty,
        "evidence_flow_ids": flows[:12],
        "sample_count": n,
    }
