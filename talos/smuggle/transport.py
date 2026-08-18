"""
Module: talos.smuggle.transport

Purpose:
    Raw HTTP/1.1 over TCP/TLS plus an optional NTLMv2 handshake on the
    same keep-alive socket.

    Smuggling probes cannot go through httpx (it normalizes CL/TE) or
    an intercepting upstream (it rewrites framing). Connections are
    always direct to the origin host.

Dependencies: socket, ssl, time, talos.proxy.ntlm / platform_auth,
              talos.projects.proxy_config
Data flow: engine → open_raw_connection → handshake_ntlm → send/read
Side effects: outbound TCP/TLS; NTLM Type 1/3 on matching hosts.
"""

from __future__ import annotations

import base64
import socket
import ssl
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from talos.configuration.model import PlatformAuthEntry
from talos.projects.proxy_config import load_proxy_transport
from talos.proxy.platform_auth import (
    authorization_scheme,
    encode_auth_header,
    match_platform_auth,
    parse_www_authenticate,
)
from talos.proxy.ntlm import NtlmContext, NtlmError
from talos.smuggle.payloads import render_http_request


class RawHttpError(Exception):
    """Connect / parse / handshake failure on a raw socket."""


@dataclass
class RawResponse:
    """
    Purpose:
        One HTTP/1.1 response read from a raw socket.
    """

    status: int
    reason: str
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: bytes = b""
    raw: bytes = b""
    elapsed_ms: int = 0
    timed_out: bool = False

    def header_value(self, name: str) -> Optional[str]:
        """Purpose: First matching header, case-insensitive."""
        want = name.lower()
        for key, value in self.headers:
            if key.lower() == want:
                return value
        return None


class RawHttpConnection:
    """
    Purpose:
        One keep-alive TCP/TLS socket that speaks HTTP/1.1 bytes.
    """

    def __init__(
        self,
        sock: socket.socket,
        *,
        timeout: float = 8.0,
    ) -> None:
        self._sock = sock
        self.timeout = timeout
        self._buf = bytearray()

    def sendall(self, data: bytes) -> None:
        """Purpose: Write request bytes. Side effects: socket send."""
        self._sock.settimeout(self.timeout)
        self._sock.sendall(data)

    def read_response(self, timeout: Optional[float] = None) -> RawResponse:
        """
        Purpose:
            Read one HTTP/1.1 response (headers + body).
        Output:
            RawResponse; timed_out=True when the deadline expires mid-read.
        """
        started = time.monotonic()
        deadline = timeout if timeout is not None else self.timeout
        try:
            header_blob = self._read_until(b"\r\n\r\n", deadline, started)
        except socket.timeout:
            return RawResponse(
                status=0,
                reason="timeout",
                timed_out=True,
                elapsed_ms=_elapsed_ms(started),
            )
        except OSError as exc:
            raise RawHttpError(f"read_error: {exc}") from exc

        if not header_blob:
            raise RawHttpError("empty_response")

        status, reason, headers = _parse_status_and_headers(header_blob)
        body = b""
        try:
            te = _header(headers, "transfer-encoding") or ""
            if "chunked" in te.lower():
                body = self._read_chunked(deadline, started)
            else:
                cl_raw = _header(headers, "content-length")
                if cl_raw is not None:
                    try:
                        length = max(0, int(cl_raw.strip()))
                    except ValueError:
                        length = 0
                    body = self._read_exact(length, deadline, started)
        except socket.timeout:
            return RawResponse(
                status=status,
                reason=reason,
                headers=headers,
                body=body,
                raw=header_blob + body,
                elapsed_ms=_elapsed_ms(started),
                timed_out=True,
            )

        return RawResponse(
            status=status,
            reason=reason,
            headers=headers,
            body=body,
            raw=header_blob + body,
            elapsed_ms=_elapsed_ms(started),
        )

    def close(self) -> None:
        """Purpose: Close the origin socket. Side effects: socket close."""
        try:
            self._sock.close()
        except OSError:
            pass

    def _read_until(self, marker: bytes, deadline: float, started: float) -> bytes:
        while marker not in self._buf:
            self._recv_more(deadline, started)
        idx = self._buf.index(marker) + len(marker)
        chunk = bytes(self._buf[:idx])
        del self._buf[:idx]
        return chunk

    def _read_exact(self, n: int, deadline: float, started: float) -> bytes:
        if n <= 0:
            return b""
        while len(self._buf) < n:
            self._recv_more(deadline, started)
        chunk = bytes(self._buf[:n])
        del self._buf[:n]
        return chunk

    def _read_chunked(self, deadline: float, started: float) -> bytes:
        parts = bytearray()
        while True:
            line = self._read_until(b"\r\n", deadline, started)
            size_token = line.split(b";", 1)[0].strip()
            try:
                size = int(size_token, 16)
            except ValueError:
                break
            if size == 0:
                # Consume trailing CRLF after the last chunk (and ignore trailers).
                if self._buf.startswith(b"\r\n"):
                    del self._buf[:2]
                return bytes(parts)
            parts.extend(self._read_exact(size, deadline, started))
            self._read_exact(2, deadline, started)  # CRLF after chunk data

    def _recv_more(self, deadline: float, started: float) -> None:
        remaining = deadline - (time.monotonic() - started)
        if remaining <= 0:
            raise socket.timeout("deadline")
        self._sock.settimeout(remaining)
        chunk = self._sock.recv(8192)
        if not chunk:
            raise RawHttpError("connection_closed")
        self._buf.extend(chunk)


def _elapsed_ms(started: float) -> int:
    return int((time.monotonic() - started) * 1000)


def _header(headers: list[tuple[str, str]], name: str) -> Optional[str]:
    want = name.lower()
    for key, value in headers:
        if key.lower() == want:
            return value
    return None


def _parse_status_and_headers(blob: bytes) -> tuple[int, str, list[tuple[str, str]]]:
    text = blob.decode("iso-8859-1", errors="replace")
    lines = text.split("\r\n")
    status = 0
    reason = ""
    if lines:
        parts = lines[0].split(None, 2)
        if len(parts) >= 2:
            try:
                status = int(parts[1])
            except ValueError:
                status = 0
        if len(parts) >= 3:
            reason = parts[2]
    headers: list[tuple[str, str]] = []
    for line in lines[1:]:
        if not line or ":" not in line:
            continue
        name, value = line.split(":", 1)
        headers.append((name.strip(), value.strip()))
    return status, reason, headers


def resolve_origin(url: str) -> tuple[str, int, bool, str]:
    """
    Purpose:
        Parse scheme/host/port for a direct origin connect.
    Output:
        (hostname, port, use_tls, host_header)
    """
    parsed = urlparse(url if "://" in (url or "") else f"https://{url}")
    host = parsed.hostname or ""
    if not host:
        raise RawHttpError("missing_host")
    use_tls = (parsed.scheme or "https").lower() == "https"
    port = parsed.port or (443 if use_tls else 80)
    host_header = parsed.netloc or host
    return host, port, use_tls, host_header


def open_raw_connection(
    url: str,
    *,
    timeout: float = 8.0,
) -> RawHttpConnection:
    """
    Purpose:
        TCP (+ TLS) connect direct to the origin. Never uses HTTP_PROXY.
    Side effects: outbound connect.
    """
    host, port, use_tls, _header = resolve_origin(url)
    raw = socket.create_connection((host, port), timeout=timeout)
    raw.settimeout(timeout)
    if use_tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            raw = ctx.wrap_socket(raw, server_hostname=host)
        except ssl.SSLError as exc:
            try:
                raw.close()
            except OSError:
                pass
            raise RawHttpError(f"tls_error: {exc}") from exc
    return RawHttpConnection(raw, timeout=timeout)


def match_ntlm_profile(db_path: Path, host: str) -> Optional[PlatformAuthEntry]:
    """
    Purpose:
        Enabled platform-auth row for this origin, when the master switch is on.
    Output:
        PlatformAuthEntry or None.
    """
    transport = load_proxy_transport(db_path)
    if not transport.platform_auth_enabled:
        return None
    return match_platform_auth(transport.platform_auth_entries, host)


def handshake_ntlm(
    conn: RawHttpConnection,
    *,
    path: str,
    host_header: str,
    entry: PlatformAuthEntry,
) -> None:
    """
    Purpose:
        Complete NTLMv2 Type 1/2/3 on an open keep-alive socket.
    Side effects: two extra GET requests on ``conn``.
    """
    if not (entry.username or "").strip() or not entry.password:
        raise RawHttpError("ntlm_credentials_missing")

    ctx = NtlmContext(
        username=entry.username,
        password=entry.password,
        domain=entry.domain or "",
        workstation=entry.domain_hostname or "",
    )
    scheme = authorization_scheme(entry)
    target = path if path.startswith("/") else f"/{path}"

    type1 = ctx.type1()
    auth1 = f"{scheme} {encode_auth_header(entry, type1)}"
    conn.sendall(
        render_http_request(
            "GET",
            target,
            [
                ("Host", host_header),
                ("Connection", "keep-alive"),
                ("Authorization", auth1),
            ],
        )
    )
    challenge = conn.read_response()
    if challenge.timed_out:
        raise RawHttpError("ntlm_type2_timeout")

    www = [
        value
        for name, value in challenge.headers
        if name.lower() == "www-authenticate"
    ]
    parsed = parse_www_authenticate(www)
    token = parsed.get(scheme.lower()) or parsed.get("ntlm") or parsed.get("negotiate")
    if not token:
        raise RawHttpError("ntlm_type2_missing")
    try:
        type2 = base64.b64decode(token)
        type3 = ctx.type3(type2)
    except (NtlmError, ValueError) as exc:
        raise RawHttpError(f"ntlm_type3_error: {exc}") from exc

    auth3 = f"{scheme} {encode_auth_header(entry, type3)}"
    conn.sendall(
        render_http_request(
            "GET",
            target,
            [
                ("Host", host_header),
                ("Connection", "keep-alive"),
                ("Authorization", auth3),
            ],
        )
    )
    authed = conn.read_response()
    if authed.timed_out:
        raise RawHttpError("ntlm_type3_timeout")
    if authed.status == 401:
        raise RawHttpError("ntlm_handshake_failed")


def session_headers_from_capture(
    headers: object,
    *,
    ntlm: bool,
) -> list[tuple[str, str]]:
    """
    Purpose:
        Copy captured session headers onto probes (cookies / bearer).
        Strip hop-by-hop framing and connection-bound NTLM tokens.
    """
    skip = {
        "host",
        "content-length",
        "transfer-encoding",
        "connection",
        "keep-alive",
        "proxy-connection",
        "te",
        "trailer",
        "upgrade",
        "expect",
        "user-agent",
    }
    pairs: list[tuple[str, str]] = []
    if isinstance(headers, dict):
        items = list(headers.items())
    elif isinstance(headers, (list, tuple)):
        items = [(str(k), str(v)) for k, v in headers]
    else:
        items = []
    for key, value in items:
        name = str(key)
        lower = name.lower()
        if lower in skip:
            continue
        if ntlm and lower == "authorization":
            continue
        text = str(value if value is not None else "")
        if lower == "authorization" and text.split(None, 1)[0].lower() in {
            "ntlm",
            "negotiate",
        }:
            continue
        pairs.append((name, text))
    return pairs
