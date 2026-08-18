"""Verdict logic for HTTP request smuggling."""

from talos.smuggle.detect import analyze_smuggle_exchange
from talos.smuggle.models import VERDICT_SECURE, VERDICT_SMUGGLE


def test_poisoned_followup_is_smuggle() -> None:
    verdict, signal, evidence, hint = analyze_smuggle_exchange(
        canary_path="/talos-hrs-aa",
        baseline_status=200,
        probe_status=200,
        followup_status=404,
    )
    assert verdict == VERDICT_SMUGGLE
    assert signal == "poisoned_followup"
    assert "404" in evidence
    assert hint == "desync"


def test_same_status_is_secure() -> None:
    verdict, signal, evidence, hint = analyze_smuggle_exchange(
        canary_path="/talos-hrs-aa",
        baseline_status=200,
        probe_status=400,
        followup_status=200,
    )
    assert verdict == VERDICT_SECURE
    assert signal == ""
    assert evidence == ""
    assert hint == ""


def test_canary_in_body_is_smuggle() -> None:
    verdict, signal, _, _ = analyze_smuggle_exchange(
        canary_path="/talos-hrs-zz",
        baseline_status=200,
        probe_status=200,
        followup_status=200,
        followup_body=b"Not Found: /talos-hrs-zz",
    )
    assert verdict == VERDICT_SMUGGLE
    assert signal == "canary_reflected"


def test_extra_response_is_smuggle() -> None:
    verdict, signal, _, _ = analyze_smuggle_exchange(
        canary_path="/talos-hrs-aa",
        baseline_status=200,
        probe_status=200,
        followup_status=200,
        extra_response=True,
    )
    assert verdict == VERDICT_SMUGGLE
    assert signal == "extra_response"


def test_timeout_alone_is_not_a_finding() -> None:
    verdict, signal, _, _ = analyze_smuggle_exchange(
        canary_path="/talos-hrs-aa",
        baseline_status=200,
        probe_status=None,
        followup_status=200,
        probe_timed_out=True,
    )
    assert verdict == VERDICT_SECURE
    assert signal == ""
