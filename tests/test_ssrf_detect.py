"""SSRF detector: new fetch signatures vs baseline; payload echo is not a hit."""

from talos.ssrf.detect import analyze_ssrf_response
from talos.ssrf.models import VERDICT_SECURE, VERDICT_SSRF

AWS_META = b"ami-id\nami-0abcdef1234567890\ninstance-id\ni-0123456789abcdef0\n"
PASSWD = b"root:x:0:0:root:/root:/bin/bash\n"
COLLAB_BODY = b"<html>Burp Collaborator Server</html>"


def test_new_aws_metadata_is_ssrf() -> None:
    verdict, hint, sink, _ = analyze_ssrf_response(
        baseline_body=b"<html>ok</html>",
        probe_body=AWS_META,
        payload_sent="http://169.254.169.254/latest/meta-data/",
    )
    assert verdict == VERDICT_SSRF
    assert sink == "cloud"
    assert hint in {"aws_ami", "aws_instance", "aws_meta_index"}


def test_same_baseline_metadata_is_secure() -> None:
    verdict, hint, sink, _ = analyze_ssrf_response(
        baseline_body=AWS_META,
        probe_body=AWS_META,
        payload_sent="http://169.254.169.254/latest/meta-data/",
    )
    assert verdict == VERDICT_SECURE
    assert hint == ""
    assert sink is None


def test_payload_echo_of_collaborator_host_is_not_ssrf() -> None:
    payload = "http://abc.oastify.com/ssrf/token"
    page = f"<html>invalid url {payload}</html>".encode()
    verdict, _, _, _ = analyze_ssrf_response(
        baseline_body=b"<html>ok</html>",
        probe_body=page,
        payload_sent=payload,
        oast_token="token12",
    )
    assert verdict == VERDICT_SECURE


def test_collaborator_http_body_without_echo_is_ssrf() -> None:
    verdict, hint, sink, _ = analyze_ssrf_response(
        baseline_body=b"<html>ok</html>",
        probe_body=COLLAB_BODY,
        payload_sent="http://abc.oastify.com/ssrf/aabbccdd",
    )
    assert verdict == VERDICT_SSRF
    assert sink == "oast"
    assert hint == "collaborator_http"


def test_file_ssrf_passwd_is_ssrf() -> None:
    verdict, hint, sink, _ = analyze_ssrf_response(
        baseline_body=b"not found",
        probe_body=PASSWD,
        payload_sent="file:///etc/passwd",
    )
    assert verdict == VERDICT_SSRF
    assert sink == "file"
    assert hint == "unix_passwd"


def test_aws_identity_json_is_ssrf() -> None:
    body = (
        b'{"accountId":"123456789012","architecture":"x86_64",'
        b'"availabilityZone":"us-east-1a","instanceId":"i-abc",'
        b'"region":"us-east-1"}'
    )
    verdict, hint, sink, _ = analyze_ssrf_response(
        baseline_body=b"{}",
        probe_body=body,
        payload_sent="http://169.254.169.254/latest/dynamic/instance-identity/document",
    )
    assert verdict == VERDICT_SSRF
    assert sink == "cloud"
    assert hint == "aws_identity"
