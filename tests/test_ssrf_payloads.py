"""SSRF payload catalogue: families, collaborator placeholders, OAST gating."""

import pytest

from talos.ssrf.models import FAMILY_OAST
from talos.ssrf.payloads import (
    generate_ssrf_payloads,
    normalize_collaborator,
    render_payload,
)


def test_default_catalogue_skips_oast() -> None:
    payloads = generate_ssrf_payloads()
    assert payloads
    assert all(not item.requires_collaborator for item in payloads)
    families = {item.family for item in payloads}
    assert "loopback" in families
    assert "cloud" in families
    assert "protocol" in families
    assert FAMILY_OAST not in families


def test_oast_requires_collaborator() -> None:
    with pytest.raises(ValueError, match="collaborator"):
        generate_ssrf_payloads(families=["oast"])


def test_oast_payloads_render_unique_subdomain() -> None:
    payloads = generate_ssrf_payloads(
        families=["oast"], collaborator="abc.oastify.com"
    )
    assert payloads
    sent = render_payload(
        payloads[0],
        "https://app.example.com/hook",
        collaborator="abc.oastify.com",
        token="deadbeef",
    )
    assert "abc.oastify.com" in sent
    assert "deadbeef" in sent or "oast" in payloads[0].technique


def test_normalize_collaborator_strips_scheme() -> None:
    assert normalize_collaborator("https://xyz.oastify.com/") == "xyz.oastify.com"
    assert normalize_collaborator("xyz.burpcollaborator.net") == "xyz.burpcollaborator.net"
    with pytest.raises(ValueError):
        normalize_collaborator("localhost")
    with pytest.raises(ValueError):
        normalize_collaborator("not-a-host")


def test_family_filter() -> None:
    cloud = generate_ssrf_payloads(families=["cloud"])
    assert cloud
    assert all(item.family == "cloud" for item in cloud)
    assert any("169.254.169.254" in item.payload for item in cloud)
