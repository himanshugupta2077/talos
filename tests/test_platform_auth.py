"""
Tests for origin HTTP/1.1, keep-alive, and NTLMv2 platform authentication.
"""

from __future__ import annotations

import base64
import struct
from pathlib import Path
from unittest.mock import MagicMock

import httpx
import pytest

from talos.configuration.manager import ConfigurationManager, parse_platform_auth_entry
from talos.configuration.model import PlatformAuthEntry
from talos.projects.db import init_project_db
from talos.projects.manager import ProjectManager
from talos.projects.proxy_config import (
    add_platform_auth_entry,
    load_proxy_transport,
    remove_platform_auth_entry,
    set_http2,
    set_keep_alive,
)
from talos.proxy.cli import run_proxy_cli
from talos.proxy.launcher import build_mitmdump_command
from talos.proxy.ntlm import NTLM_SIGNATURE, NtlmContext, _md4, ntlm_message_type, ntowfv2
from talos.proxy.platform_auth import (
    HttpxPlatformAuth,
    authorization_scheme,
    filter_response_headers,
    host_matches,
    match_platform_auth,
    strip_negotiate_challenges,
)


@pytest.fixture
def data_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    d = tmp_path / "talos-data"
    d.mkdir()
    (d / "projects").mkdir()
    monkeypatch.setenv("TALOS_DATA_DIR", str(d))
    monkeypatch.setenv("TALOS_PROXY_AUTO_RESTART", "0")
    return d


@pytest.fixture
def db_path(data_dir: Path) -> Path:
    pdir = data_dir / "projects" / "demo"
    pdir.mkdir()
    path = pdir / "talos.db"
    init_project_db(path)
    return path


@pytest.fixture
def manager_with_project(db_path: Path) -> tuple[ProjectManager, MagicMock]:
    project = MagicMock()
    project.id = "demo"
    project.db_path = db_path
    project.data_dir = str(db_path.parent)
    project.scope = ["foresight-uat.chartercom.com"]
    project.constraints.store_bodies = True
    project.constraints.max_body_size = 1024
    manager = MagicMock(spec=ProjectManager)
    manager.active.return_value = project
    manager._root = db_path.parent.parent
    return manager, project


class TestMd4:
    def test_empty(self) -> None:
        assert _md4(b"").hex() == "31d6cfe0d16ae931b73c59d7e0c089c0"

    def test_a(self) -> None:
        assert _md4(b"a").hex() == "bde52cb31de33e46245e05fbdbd6fb24"


class TestHostMatch:
    def test_exact(self) -> None:
        assert host_matches("foresight-uat.chartercom.com", "Foresight-UAT.chartercom.com")
        assert not host_matches("other.example", "foresight-uat.chartercom.com")

    def test_strips_port(self) -> None:
        assert host_matches("app.example", "app.example:443")

    def test_wildcard(self) -> None:
        assert host_matches("*.chartercom.com", "foresight-uat.chartercom.com")
        assert not host_matches("*.chartercom.com", "chartercom.org")


class TestNtlmMessages:
    def test_type1_is_ntlmssp(self) -> None:
        ctx = NtlmContext(username="P3257806", password="testpassword", domain="")
        token = ctx.type1()
        assert ntlm_message_type(token) == 1
        assert token.startswith(NTLM_SIGNATURE)

    def test_type3_from_minimal_type2(self) -> None:
        challenge = bytes.fromhex("0123456789abcdef")
        type2 = (
            NTLM_SIGNATURE
            + struct.pack("<I", 2)
            + struct.pack("<HHI", 0, 0, 48)
            + struct.pack("<I", 0x00088201)
            + challenge
            + b"\x00" * 8
            + struct.pack("<HHI", 4, 4, 48)
            + b"\x00\x00\x00\x00"
        )
        ctx = NtlmContext(
            username="P3257806",
            password="testpassword",
            domain="",
            workstation="foresight-uat.chartercom.com",
        )
        type3 = ctx.type3(type2)
        assert ntlm_message_type(type3) == 3
        assert ctx.complete

    def test_ntowfv2_stable(self) -> None:
        a = ntowfv2("User", "Password", "Domain")
        b = ntowfv2("User", "Password", "Domain")
        assert a == b
        assert len(a) == 16


class TestNegotiateStrip:
    def test_keeps_ntlm(self) -> None:
        values = ["Negotiate", "NTLM"]
        assert strip_negotiate_challenges(values) == ["NTLM"]

    def test_keeps_ntlm_challenge(self) -> None:
        values = ["Negotiate abc", "NTLM TlRMTVNTUA=="]
        assert strip_negotiate_challenges(values) == ["NTLM TlRMTVNTUA=="]


class TestScheme:
    def test_default_is_ntlm(self) -> None:
        entry = parse_platform_auth_entry(
            {"host": "app.example", "auth_type": "ntlmv2", "username": "u"}
        )
        assert authorization_scheme(entry) == "NTLM"
        assert entry.negotiate is False
        assert entry.spnego is False

    def test_negotiate_type_enables_scheme(self) -> None:
        entry = parse_platform_auth_entry(
            {"host": "app.example", "auth_type": "negotiate"}
        )
        assert entry.negotiate is True
        assert authorization_scheme(entry) == "Negotiate"


class TestTransportConfig:
    def test_defaults(self, db_path: Path) -> None:
        t = load_proxy_transport(db_path)
        assert t.http2 is True
        assert t.keep_alive is True
        assert t.platform_auth_enabled is False
        assert t.platform_auth_entries == ()

    def test_set_http1_and_auth(self, db_path: Path) -> None:
        set_http2(db_path, False)
        set_keep_alive(db_path, True)
        entry = PlatformAuthEntry(
            host="foresight-uat.chartercom.com",
            auth_type="ntlmv2",
            username="P3257806",
            password="testpassword",
            domain="",
            domain_hostname="foresight-uat.chartercom.com",
            spnego=False,
            negotiate=False,
        )
        add_platform_auth_entry(db_path, entry)
        t = load_proxy_transport(db_path)
        assert t.http2 is False
        assert t.keep_alive is True
        assert t.platform_auth_enabled is True
        assert len(t.platform_auth_entries) == 1
        stored = t.platform_auth_entries[0]
        assert stored.username == "P3257806"
        assert stored.password == "testpassword"
        assert stored.domain_hostname == "foresight-uat.chartercom.com"
        assert stored.negotiate is False
        assert match_platform_auth(t.platform_auth_entries, "foresight-uat.chartercom.com")

    def test_replace_same_host(self, db_path: Path) -> None:
        add_platform_auth_entry(
            db_path,
            PlatformAuthEntry(host="app.example", username="a", password="1"),
        )
        add_platform_auth_entry(
            db_path,
            PlatformAuthEntry(host="APP.example", username="b", password="2"),
        )
        t = load_proxy_transport(db_path)
        assert len(t.platform_auth_entries) == 1
        assert t.platform_auth_entries[0].username == "b"

    def test_remove(self, db_path: Path) -> None:
        add_platform_auth_entry(
            db_path,
            PlatformAuthEntry(host="app.example", username="a", password="1"),
        )
        assert remove_platform_auth_entry(db_path, "app.example") is True
        assert load_proxy_transport(db_path).platform_auth_entries == ()


class TestLauncherHttp1:
    def test_http2_flag_present(self, tmp_path: Path) -> None:
        addon = tmp_path / "addon.py"
        addon.write_text("# stub\n")
        cmd = build_mitmdump_command(
            listen_host="127.0.0.1",
            port=8080,
            addon_path=addon,
            http2=False,
            keep_alive=True,
        )
        joined = " ".join(cmd)
        assert "--set" in cmd
        assert "http2=false" in joined
        assert "connection_strategy=eager" in joined

    def test_http2_true(self, tmp_path: Path) -> None:
        addon = tmp_path / "addon.py"
        addon.write_text("# stub\n")
        cmd = build_mitmdump_command(
            listen_host="127.0.0.1",
            port=8080,
            addon_path=addon,
            http2=True,
        )
        assert "http2=true" in " ".join(cmd)


class TestProxyAuthCli:
    def test_add_and_list(
        self,
        manager_with_project: tuple[ProjectManager, MagicMock],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        manager, project = manager_with_project
        run_proxy_cli(
            manager,
            [
                "auth",
                "add",
                "--host",
                "foresight-uat.chartercom.com",
                "--type",
                "ntlmv2",
                "--username",
                "P3257806",
                "--password",
                "testpassword",
                "--domain-hostname",
                "foresight-uat.chartercom.com",
            ],
        )
        out = capsys.readouterr().out
        assert "foresight-uat.chartercom.com" in out
        run_proxy_cli(manager, ["auth", "list", "--format", "json"])
        listed = capsys.readouterr().out
        assert "P3257806" in listed
        assert "testpassword" not in listed
        assert "password_set" in listed
        t = load_proxy_transport(project.db_path)
        assert t.http2 is True
        assert t.platform_auth_entries[0].password == "testpassword"

    def test_config_http1(
        self,
        manager_with_project: tuple[ProjectManager, MagicMock],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        manager, project = manager_with_project
        run_proxy_cli(manager, ["config", "--http1"])
        assert "HTTP/1.1" in capsys.readouterr().out
        assert load_proxy_transport(project.db_path).http2 is False


class TestResponseHeaderPairs:
    def test_string_pairs_raise_like_vdi(self) -> None:
        from mitmproxy import http

        with pytest.raises(TypeError, match="Header fields must be bytes"):
            http.Response.make(401, b"x", [("WWW-Authenticate", "NTLM")])

    def test_bytes_pairs_accepted_by_mitmproxy(self) -> None:
        from mitmproxy import http

        headers = httpx.Headers(
            [
                ("WWW-Authenticate", "NTLM"),
                ("WWW-Authenticate", "Negotiate"),
                ("Content-Type", "text/html"),
                ("Content-Length", "12"),
                ("Transfer-Encoding", "chunked"),
                ("Content-Encoding", "gzip"),
                ("Set-Cookie", "a=1"),
                ("Set-Cookie", "b=2"),
            ]
        )
        pairs = filter_response_headers(headers)
        assert all(isinstance(k, bytes) and isinstance(v, bytes) for k, v in pairs)
        lowered = [k.lower() for k, _ in pairs]
        assert b"content-length" not in lowered
        assert b"transfer-encoding" not in lowered
        assert b"content-encoding" not in lowered
        resp = http.Response.make(200, b"<html>ok</html>", pairs)
        assert resp.status_code == 200
        assert resp.content == b"<html>ok</html>"
        assert resp.headers.get_all("Set-Cookie") == ["a=1", "b=2"]
        assert resp.headers.get_all("WWW-Authenticate") == ["NTLM", "Negotiate"]
        assert resp.headers["Content-Type"] == "text/html"
        assert "content-encoding" not in [k.lower() for k in resp.headers.keys()]


class TestHttpxNtlmAuth:
    def test_sends_ntlm_not_negotiate(self) -> None:
        entry = PlatformAuthEntry(
            host="app.example",
            auth_type="ntlmv2",
            username="P3257806",
            password="testpassword",
            domain="",
            domain_hostname="app.example",
        )
        challenge = (
            NTLM_SIGNATURE
            + struct.pack("<I", 2)
            + struct.pack("<HHI", 0, 0, 48)
            + struct.pack("<I", 0x00088201)
            + bytes.fromhex("0123456789abcdef")
            + b"\x00" * 8
            + struct.pack("<HHI", 4, 4, 48)
            + b"\x00\x00\x00\x00"
        )
        type2_b64 = base64.b64encode(challenge).decode("ascii")
        seen: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            auth = request.headers.get("authorization", "")
            seen.append(auth)
            if not auth:
                return httpx.Response(
                    401, headers={"WWW-Authenticate": "NTLM"}, request=request
                )
            if auth.startswith("NTLM ") and ntlm_message_type(
                base64.b64decode(auth.split(None, 1)[1])
            ) == 1:
                return httpx.Response(
                    401,
                    headers={"WWW-Authenticate": f"NTLM {type2_b64}"},
                    request=request,
                )
            return httpx.Response(200, text="ok", request=request)

        transport = httpx.MockTransport(handler)
        client = httpx.Client(
            transport=transport,
            auth=HttpxPlatformAuth([entry]),
        )
        resp = client.get("https://app.example/api")
        assert resp.status_code == 200
        assert len(seen) == 3
        assert seen[0] == ""
        assert seen[1].startswith("NTLM ")
        assert seen[2].startswith("NTLM ")
        assert not any(h.startswith("Negotiate") for h in seen if h)


class TestLayeredDefaults:
    def test_effective_http2_default(self, data_dir: Path, db_path: Path) -> None:
        mgr = ConfigurationManager(data_dir)
        effective = mgr.load(project_data_dir=db_path.parent)
        assert effective.proxy.http2 is True
        assert effective.proxy.keep_alive is True
        assert effective.proxy.platform_auth.enabled is False
