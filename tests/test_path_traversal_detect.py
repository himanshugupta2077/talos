"""Path-traversal detector: new file-content signatures vs baseline."""

from talos.path_traversal.detect import (
    analyze_path_traversal_response,
    collect_signatures,
)
from talos.path_traversal.models import VERDICT_PATH_TRAVERSAL, VERDICT_SECURE


PASSWD = b"root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
WIN_INI = b"; for 16-bit app support\n[fonts]\n[extensions]\n[mci extensions]\n"
PHP_B64 = b"cm9vdDp4OjA6MDo=\n"


def test_collects_passwd_and_win_ini() -> None:
    hits = collect_signatures(PASSWD.decode())
    hints = {h[2] for h in hits}
    assert "unix_passwd" in hints
    win = collect_signatures(WIN_INI.decode())
    assert any(h[2] == "win_ini" for h in win)


def test_same_baseline_passwd_is_not_a_finding() -> None:
    verdict, hint, os_hint, _ = analyze_path_traversal_response(
        baseline_body=PASSWD,
        probe_body=PASSWD,
    )
    assert verdict == VERDICT_SECURE
    assert hint == ""
    assert os_hint is None


def test_new_passwd_vs_clean_baseline_is_lfi() -> None:
    verdict, hint, os_hint, evidence = analyze_path_traversal_response(
        baseline_body=b"<html>ok</html>",
        probe_body=PASSWD,
    )
    assert verdict == VERDICT_PATH_TRAVERSAL
    assert hint == "unix_passwd"
    assert os_hint == "unix"
    assert "root" in evidence.lower() or "0:0" in evidence


def test_localhost_on_a_web_page_is_not_hosts_leak() -> None:
    page = b"<html>connect to localhost to debug</html>"
    verdict, hint, _, _ = analyze_path_traversal_response(
        baseline_body=b"ok",
        probe_body=page,
    )
    assert verdict == VERDICT_SECURE
    assert hint == ""


def test_php_filter_base64_is_lfi() -> None:
    verdict, hint, os_hint, _ = analyze_path_traversal_response(
        baseline_body=b"{}",
        probe_body=PHP_B64,
    )
    assert verdict == VERDICT_PATH_TRAVERSAL
    assert hint == "php_filter"
    assert os_hint == "php"


def test_win_ini_banner_is_lfi() -> None:
    verdict, hint, os_hint, _ = analyze_path_traversal_response(
        baseline_body=b"404 not found",
        probe_body=WIN_INI,
    )
    assert verdict == VERDICT_PATH_TRAVERSAL
    assert hint == "win_ini"
    assert os_hint == "windows"
