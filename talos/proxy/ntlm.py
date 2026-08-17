"""
Module: talos.proxy.ntlm

Purpose:
    In-tree NTLMv2 Type 1 / Type 2 / Type 3 messages so Talos can complete
    IIS Windows Integrated Auth without Negotiate/Kerberos or extra packages.

    Tokens are raw NTLMSSP (not SPNEGO-wrapped). Callers choose the HTTP
    scheme (NTLM vs Negotiate) separately.

Dependencies: hashlib, hmac, os, struct, time
Data flow:
    NtlmContext.type1() → Authorization
    server Type 2 → NtlmContext.type3() → Authorization
Side effects: None (reads os.urandom for the client challenge).
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct
import time
from typing import Optional

NTLM_SIGNATURE = b"NTLMSSP\x00"

# MS-NLMP negotiate flags used for Type 1 / Type 3.
NTLMSSP_NEGOTIATE_UNICODE = 0x00000001
NTLMSSP_NEGOTIATE_OEM = 0x00000002
NTLMSSP_REQUEST_TARGET = 0x00000004
NTLMSSP_NEGOTIATE_NTLM = 0x00000200
NTLMSSP_NEGOTIATE_ALWAYS_SIGN = 0x00008000
NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY = 0x00080000
NTLMSSP_NEGOTIATE_TARGET_INFO = 0x00800000
NTLMSSP_NEGOTIATE_VERSION = 0x02000000
NTLMSSP_NEGOTIATE_128 = 0x20000000
NTLMSSP_NEGOTIATE_56 = 0x80000000

_TYPE1_FLAGS = (
    NTLMSSP_NEGOTIATE_UNICODE
    | NTLMSSP_NEGOTIATE_OEM
    | NTLMSSP_REQUEST_TARGET
    | NTLMSSP_NEGOTIATE_NTLM
    | NTLMSSP_NEGOTIATE_ALWAYS_SIGN
    | NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
    | NTLMSSP_NEGOTIATE_TARGET_INFO
    | NTLMSSP_NEGOTIATE_VERSION
    | NTLMSSP_NEGOTIATE_128
    | NTLMSSP_NEGOTIATE_56
)

# Windows 10 version blob (major, minor, build, reserved+revision).
_WINDOWS_VERSION = bytes([10, 0]) + struct.pack("<H", 19041) + b"\x00\x00\x00\x0f"


class NtlmError(ValueError):
    """Raised when a Type 2 challenge cannot be parsed."""


def _utf16le(text: str) -> bytes:
    return text.encode("utf-16-le")


def _md4(data: bytes) -> bytes:
    """
    Purpose:
        MD4 digest (RFC 1320). hashlib.md4 is absent on modern OpenSSL.
    Side effects: None.
    """
    try:
        return hashlib.new("md4", data).digest()
    except (ValueError, OSError):
        return _md4_pure(data)


def _md4_pure(data: bytes) -> bytes:
    """Pure-Python MD4 for hosts whose OpenSSL has no MD4."""

    def _f(x: int, y: int, z: int) -> int:
        return (x & y) | (~x & z)

    def _g(x: int, y: int, z: int) -> int:
        return (x & y) | (x & z) | (y & z)

    def _h(x: int, y: int, z: int) -> int:
        return x ^ y ^ z

    def _rol(value: int, bits: int) -> int:
        return ((value << bits) | (value >> (32 - bits))) & 0xFFFFFFFF

    message = data + b"\x80"
    message += b"\x00" * ((56 - (len(message) % 64)) % 64)
    message += struct.pack("<Q", len(data) * 8)

    a, b, c, d = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476

    for offset in range(0, len(message), 64):
        x = list(struct.unpack("<16I", message[offset : offset + 64]))
        aa, bb, cc, dd = a, b, c, d

        # Round 1 — rotate A,B,C,D through the F function.
        s1 = (3, 7, 11, 19)
        for n in range(16):
            a = _rol((a + _f(b, c, d) + x[n]) & 0xFFFFFFFF, s1[n % 4])
            a, b, c, d = d, a, b, c

        s2 = (3, 5, 9, 13)
        idx2 = (0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15)
        for n in range(16):
            a = _rol(
                (a + _g(b, c, d) + x[idx2[n]] + 0x5A827999) & 0xFFFFFFFF,
                s2[n % 4],
            )
            a, b, c, d = d, a, b, c

        s3 = (3, 9, 11, 15)
        idx3 = (0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15)
        for n in range(16):
            a = _rol(
                (a + _h(b, c, d) + x[idx3[n]] + 0x6ED9EBA1) & 0xFFFFFFFF,
                s3[n % 4],
            )
            a, b, c, d = d, a, b, c

        a = (a + aa) & 0xFFFFFFFF
        b = (b + bb) & 0xFFFFFFFF
        c = (c + cc) & 0xFFFFFFFF
        d = (d + dd) & 0xFFFFFFFF

    return struct.pack("<4I", a, b, c, d)


def _secbuf(length: int, offset: int) -> bytes:
    return struct.pack("<HHI", length, length, offset)


def _read_secbuf(data: bytes, offset: int) -> bytes:
    if offset + 8 > len(data):
        return b""
    length, _alloc, start = struct.unpack_from("<HHI", data, offset)
    end = start + length
    if start < 0 or end > len(data):
        return b""
    return data[start:end]


def ntowfv2(username: str, password: str, domain: str) -> bytes:
    """
    Purpose:
        NTOWFv2 = HMAC_MD5(MD4(UNICODE(pass)), UNICODE(Upper(user)+domain)).
    Side effects: None.
    """
    nt_hash = _md4(_utf16le(password))
    identity = _utf16le(username.upper() + domain)
    return hmac.new(nt_hash, identity, hashlib.md5).digest()


def _filetime_now() -> bytes:
    # 100-ns intervals between 1601-01-01 and the Unix epoch.
    unix_100ns = int(time.time() * 10_000_000)
    return struct.pack("<Q", unix_100ns + 116444736000000000)


class NtlmContext:
    """
    Purpose:
        One NTLMv2 handshake. type1() then type3(challenge_token).
    """

    def __init__(
        self,
        *,
        username: str,
        password: str,
        domain: str = "",
        workstation: str = "",
    ) -> None:
        self.username = username
        self.password = password
        self.domain = domain
        self.workstation = workstation or "WORKSTATION"
        self._complete = False

    @property
    def complete(self) -> bool:
        return self._complete

    def type1(self) -> bytes:
        """
        Purpose: Build an NTLMSSP Type 1 negotiate message.
        Output: raw token (not base64).
        """
        header_len = 40
        payload = b""
        domain_bytes = self.domain.encode("ascii", errors="replace")
        workstation_bytes = self.workstation.encode("ascii", errors="replace")
        domain_off = header_len
        workstation_off = domain_off + len(domain_bytes)
        payload = domain_bytes + workstation_bytes
        return (
            NTLM_SIGNATURE
            + struct.pack("<I", 1)
            + struct.pack("<I", _TYPE1_FLAGS)
            + _secbuf(len(domain_bytes), domain_off)
            + _secbuf(len(workstation_bytes), workstation_off)
            + _WINDOWS_VERSION
            + payload
        )

    def type3(self, type2_token: bytes) -> bytes:
        """
        Purpose: Build an NTLMSSP Type 3 authenticate message from Type 2.
        Output: raw token (not base64).
        """
        if not type2_token.startswith(NTLM_SIGNATURE):
            raise NtlmError("Type 2 token is not NTLMSSP")
        if len(type2_token) < 32:
            raise NtlmError("Type 2 token is truncated")
        msg_type = struct.unpack_from("<I", type2_token, 8)[0]
        if msg_type != 2:
            raise NtlmError(f"Expected NTLM Type 2, got type {msg_type}")

        flags = struct.unpack_from("<I", type2_token, 20)[0]
        challenge = type2_token[24:32]
        target_info = b""
        if len(type2_token) >= 48:
            target_info = _read_secbuf(type2_token, 40)
        if not target_info:
            # Terminating AvId=MsvAvEOL pair.
            target_info = b"\x00\x00\x00\x00"

        client_challenge = os.urandom(8)
        timestamp = _filetime_now()
        blob = (
            b"\x01\x01"
            + b"\x00\x00"
            + b"\x00\x00\x00\x00"
            + timestamp
            + client_challenge
            + b"\x00\x00\x00\x00"
            + target_info
        )
        response_key = ntowfv2(self.username, self.password, self.domain)
        nt_proof = hmac.new(response_key, challenge + blob, hashlib.md5).digest()
        nt_response = nt_proof + blob
        lm_proof = hmac.new(
            response_key, challenge + client_challenge, hashlib.md5
        ).digest()
        lm_response = lm_proof + client_challenge

        domain_bytes = _utf16le(self.domain)
        user_bytes = _utf16le(self.username)
        workstation_bytes = _utf16le(self.workstation)

        # Header is 64 bytes (no MIC) + 8-byte version when VERSION is set.
        header_len = 72
        offset = header_len
        lm_off = offset
        offset += len(lm_response)
        nt_off = offset
        offset += len(nt_response)
        domain_off = offset
        offset += len(domain_bytes)
        user_off = offset
        offset += len(user_bytes)
        workstation_off = offset

        type3_flags = flags | NTLMSSP_NEGOTIATE_UNICODE | NTLMSSP_NEGOTIATE_NTLM
        session_key = b""

        message = (
            NTLM_SIGNATURE
            + struct.pack("<I", 3)
            + _secbuf(len(lm_response), lm_off)
            + _secbuf(len(nt_response), nt_off)
            + _secbuf(len(domain_bytes), domain_off)
            + _secbuf(len(user_bytes), user_off)
            + _secbuf(len(workstation_bytes), workstation_off)
            + _secbuf(len(session_key), offset + len(workstation_bytes))
            + struct.pack("<I", type3_flags)
            + _WINDOWS_VERSION
            + lm_response
            + nt_response
            + domain_bytes
            + user_bytes
            + workstation_bytes
            + session_key
        )
        self._complete = True
        return message


def ntlm_message_type(token: bytes) -> Optional[int]:
    """
    Purpose: Return the NTLMSSP message type (1/2/3) or None if not NTLM.
    Side effects: None.
    """
    if not token.startswith(NTLM_SIGNATURE) or len(token) < 12:
        return None
    return int(struct.unpack_from("<I", token, 8)[0])
