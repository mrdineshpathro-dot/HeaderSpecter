"""Tests for the Content-Security-Policy parser and analyzer."""

from __future__ import annotations

from headerspecter.csp import analyze_csp, parse_csp
from headerspecter.findings import Severity
from headerspecter.headers import HeaderBag


def ids(analysis) -> set[str]:
    """Collect finding ids from a CSP analysis."""
    return {finding.id for finding in analysis.findings}


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #
def test_parse_basic_policy():
    policy = parse_csp("default-src 'self'; script-src 'self' https://cdn.example.com; object-src 'none'")
    assert policy.directives["default-src"] == ["'self'"]
    assert policy.directives["script-src"] == ["'self'", "https://cdn.example.com"]
    assert policy.directives["object-src"] == ["'none'"]
    assert policy.report_only is False


def test_parse_is_case_insensitive_for_directive_names():
    policy = parse_csp("DEFAULT-SRC 'self'; Script-Src 'none'")
    assert set(policy.directives) == {"default-src", "script-src"}


def test_parse_handles_empty_segments_and_whitespace():
    policy = parse_csp("  default-src 'self' ;; ; script-src 'self'  ")
    assert policy.directives["default-src"] == ["'self'"]
    assert policy.directives["script-src"] == ["'self'"]


def test_parse_keeps_first_duplicate_directive():
    policy = parse_csp("script-src 'self'; script-src 'unsafe-inline'")
    assert policy.directives["script-src"] == ["'self'"]
    assert policy.duplicate_directives == ["script-src"]


def test_effective_falls_back_to_default_src():
    policy = parse_csp("default-src 'self'")
    values, origin = policy.effective("img-src")
    assert values == ["'self'"]
    assert origin == "default-src"


def test_effective_does_not_fall_back_for_non_fetch_directives():
    policy = parse_csp("default-src 'self'")
    assert policy.effective("base-uri") == (None, None)
    assert policy.effective("frame-ancestors") == (None, None)


# --------------------------------------------------------------------------- #
# Analysis
# --------------------------------------------------------------------------- #
def test_missing_csp_is_high(empty_bag, https_context):
    analysis = analyze_csp(empty_bag, https_context)
    assert analysis.present is False
    assert "HS-100" in ids(analysis)
    assert analysis.check.status is Severity.HIGH


def test_strong_policy_has_no_high_findings(strong_bag, https_context):
    analysis = analyze_csp(strong_bag, https_context)
    assert analysis.present and analysis.enforced
    assert analysis.strict is True
    assert analysis.uses_nonce is True
    severities = {finding.severity for finding in analysis.findings}
    assert Severity.HIGH not in severities
    assert Severity.CRITICAL not in severities
    # Core hardening directives are all present:
    for directive in ("object-src", "base-uri", "frame-ancestors", "form-action"):
        assert directive in analysis.merged


def test_weak_policy_flags_the_expected_issues(weak_bag, https_context):
    analysis = analyze_csp(weak_bag, https_context)
    found = ids(analysis)
    assert "HS-101" in found  # unsafe-inline
    assert "HS-102" in found  # unsafe-eval
    assert "HS-103" in found  # wildcard
    assert "HS-105" in found  # base-uri
    assert "HS-109" in found  # data: in script-src
    assert "HS-117" in found  # frame-ancestors *
    assert "HS-120" in found  # report-uri only


def test_unsafe_inline_with_nonce_is_downgraded(https_context):
    bag = HeaderBag(
        [
            (
                "Content-Security-Policy",
                "default-src 'self'; script-src 'self' 'unsafe-inline' 'nonce-Kj8vQ2mZp1Xw7bNc4RtY9f'; "
                "object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'",
            )
        ]
    )
    analysis = analyze_csp(bag, https_context)
    unsafe = [finding for finding in analysis.findings if finding.id == "HS-101"]
    assert unsafe and unsafe[0].severity is Severity.INFO


def test_weak_nonce_is_detected(https_context):
    bag = HeaderBag([("Content-Security-Policy", "script-src 'nonce-abc123'")])
    analysis = analyze_csp(bag, https_context)
    assert "HS-122" in ids(analysis)


def test_strong_nonce_is_accepted(https_context):
    bag = HeaderBag([("Content-Security-Policy", "script-src 'nonce-Kj8vQ2mZp1Xw7bNc4RtY9f'")])
    analysis = analyze_csp(bag, https_context)
    assert "HS-122" not in ids(analysis)


def test_report_only_policy_is_flagged(https_context):
    bag = HeaderBag([("Content-Security-Policy-Report-Only", "default-src 'self'")])
    analysis = analyze_csp(bag, https_context)
    assert analysis.present is True
    assert analysis.enforced is False
    assert "HS-110" in ids(analysis)


def test_multiple_policies_are_reported(https_context):
    bag = HeaderBag(
        [
            ("Content-Security-Policy", "default-src 'self'"),
            ("Content-Security-Policy", "script-src 'self'"),
        ]
    )
    analysis = analyze_csp(bag, https_context)
    assert "HS-116" in ids(analysis)
    assert "script-src" in analysis.merged and "default-src" in analysis.merged


def test_unknown_directive_is_flagged(https_context):
    bag = HeaderBag([("Content-Security-Policy", "default-src 'self'; scrpit-src 'self'")])
    analysis = analyze_csp(bag, https_context)
    assert "HS-115" in ids(analysis)


def test_large_allowlist_is_flagged(https_context):
    hosts = " ".join(f"https://cdn{index}.example.com" for index in range(20))
    bag = HeaderBag([("Content-Security-Policy", f"default-src 'self' {hosts}")])
    analysis = analyze_csp(bag, https_context)
    assert "HS-111" in ids(analysis)
    assert len(analysis.host_sources) == 20


def test_http_sources_are_flagged(https_context):
    bag = HeaderBag([("Content-Security-Policy", "default-src 'self' http://cdn.example.com")])
    analysis = analyze_csp(bag, https_context)
    found = ids(analysis)
    assert "HS-108" in found
    assert "HS-121" in found  # no upgrade-insecure-requests


def test_sandbox_escape_combination(https_context):
    bag = HeaderBag([("Content-Security-Policy", "sandbox allow-scripts allow-same-origin")])
    analysis = analyze_csp(bag, https_context)
    assert "HS-118" in ids(analysis)


def test_object_src_inherited_from_restrictive_default(https_context):
    bag = HeaderBag([("Content-Security-Policy", "default-src 'none'; base-uri 'self'; frame-ancestors 'none'")])
    analysis = analyze_csp(bag, https_context)
    assert "HS-104" not in ids(analysis)


def test_directive_rows_cover_display_order(strong_bag, https_context):
    analysis = analyze_csp(strong_bag, https_context)
    rendered = {row.directive for row in analysis.directive_rows}
    assert {"default-src", "script-src", "object-src", "frame-ancestors"} <= rendered


def test_to_dict_is_json_serialisable(strong_bag, https_context):
    import json

    analysis = analyze_csp(strong_bag, https_context)
    payload = json.loads(json.dumps(analysis.to_dict()))
    assert payload["present"] is True
    assert payload["strict"] is True
