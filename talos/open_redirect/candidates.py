"""
Module: talos.open_redirect.candidates

Purpose:
    Select captured flows the operator asked to scan. Same eligibility
    as SSRF (in-scope, not logout / dangerous / excluded).
"""

from talos.ssrf.candidates import (  # noqa: F401
    SsrfCandidate as OpenRedirectCandidate,
    normalize_flow_ids,
    select_ssrf_candidates_for_flows as select_open_redirect_candidates_for_flows,
)
