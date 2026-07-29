"""
Module: talos.intruder.results

Purpose:
    Build metrics / fingerprint dicts from HTTP responses; export helpers.
"""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path
from typing import Any, Optional

from talos.input_validation.fingerprint import fingerprint_from_flow
from talos.intruder.models import AttemptResult


def build_metrics_from_response(
    *,
    status_code: Optional[int],
    response_headers: dict[str, str],
    response_body: Optional[bytes],
    duration_ms: Optional[float],
    variables: dict[str, str],
) -> dict[str, Any]:
    """
    Compute fingerprint + extended metrics (words, lines, reflection).
    """
    body = response_body or b""
    try:
        body_text = body.decode("utf-8")
    except UnicodeDecodeError:
        body_text = body.decode("latin-1", errors="replace")

    content_type = ""
    for k, v in (response_headers or {}).items():
        if k.lower() == "content-type":
            content_type = v
            break

    flow_like = {
        "status_code": status_code,
        "content_type": content_type,
        "response_body": body,
        "response_headers": response_headers or {},
        "duration_ms": duration_ms,
    }
    fp = fingerprint_from_flow(flow_like)
    words = len(body_text.split()) if body_text else 0
    lines = body_text.count("\n") + (1 if body_text else 0)

    reflections: list[str] = []
    for name, val in (variables or {}).items():
        if val and val in body_text:
            reflections.append(name)

    cookies_set = 0
    for k in (response_headers or {}):
        if k.lower() == "set-cookie":
            cookies_set += 1

    return {
        "status_code": status_code,
        "duration_ms": duration_ms,
        "body_length": fp.body_length,
        "body_hash": fp.body_hash,
        "word_count": words,
        "line_count": lines,
        "body_text": body_text,  # for match rules; strip before DB store
        "fingerprint": fp.to_dict(),
        "reflection": reflections,
        "cookies_set": cookies_set,
        "content_type": fp.content_type,
    }


def attempt_result_to_row(result: AttemptResult) -> dict[str, Any]:
    """Serialize AttemptResult for insert_results_batch (no body_text)."""
    metrics = dict(result.metrics or {})
    metrics.pop("body_text", None)
    return {
        "attempt_index": result.attempt_index,
        "variables": result.variables,
        "status_code": result.status_code,
        "success": result.success,
        "failure_reason": result.failure_reason,
        "duration_ms": result.duration_ms,
        "body_length": result.body_length,
        "word_count": result.word_count,
        "line_count": result.line_count,
        "body_hash": result.body_hash,
        "fingerprint": result.fingerprint,
        "metrics": metrics,
        "interesting": result.interesting,
        "match_tags": result.match_tags,
        "grepped": result.grepped,
        "flow_id": result.flow_id,
        "finding_id": getattr(result, "finding_id", None),
    }


def export_results_jsonl(rows: list[dict[str, Any]], path: Path) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, default=str) + "\n")
    return len(rows)


def export_results_csv(rows: list[dict[str, Any]], path: Path) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "attempt_index",
        "status_code",
        "success",
        "failure_reason",
        "duration_ms",
        "body_length",
        "body_hash",
        "interesting",
        "match_tags",
        "grepped",
        "variables",
        "flow_id",
        "finding_id",
    ]
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            out = {
                "attempt_index": row.get("attempt_index"),
                "status_code": row.get("status_code"),
                "success": row.get("success"),
                "failure_reason": row.get("failure_reason"),
                "duration_ms": row.get("duration_ms"),
                "body_length": row.get("body_length"),
                "body_hash": row.get("body_hash"),
                "interesting": row.get("interesting"),
                "match_tags": json.dumps(row.get("match_tags") or []),
                "grepped": json.dumps(row.get("grepped") or {}),
                "variables": json.dumps(row.get("variables") or {}),
                "flow_id": row.get("flow_id"),
                "finding_id": row.get("finding_id"),
            }
            writer.writerow(out)
    return len(rows)


def rows_to_csv_string(rows: list[dict[str, Any]]) -> str:
    buf = io.StringIO()
    fieldnames = [
        "attempt_index",
        "status_code",
        "success",
        "duration_ms",
        "body_length",
        "interesting",
        "variables",
    ]
    writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        writer.writerow({
            "attempt_index": row.get("attempt_index"),
            "status_code": row.get("status_code"),
            "success": row.get("success"),
            "duration_ms": row.get("duration_ms"),
            "body_length": row.get("body_length"),
            "interesting": row.get("interesting"),
            "variables": json.dumps(row.get("variables") or {}),
        })
    return buf.getvalue()
