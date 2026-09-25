"""Tests for the analysis orchestrator, custom policies and the report model."""

from __future__ import annotations

import json

import pytest
from conftest import EMPTY_HEADERS, STRONG_HEADERS, WEAK_HEADERS, scan_from

from headerspecter.analyzer import HTTPUpgradeProbe, analyze_response, build_recommendations
from headerspecter.findings import CHECKS, Severity, sort_findings
from headerspecter.policy import HeaderPolicy, PolicyError
from headerspecter.redirects import RedirectHop
from headerspecter.tls import TLSInfo


# --------------------------------------------------------------------------- #
# Catalogue integrity
# --------------------------------------------------------------------------- #
def test_every_check_has_complete_metadata():
    for check_id, check in CHECKS.items():
        assert check_id.startswith("HS-")
        assert check.title and check.impact and check.recommendation
        assert check.category
        assert isinstance(check.severity, Severity)
        assert check.impact.endswith(".") or check.impact.endswith(")")


def test_check_ids_are_unique_and_sorted():
    ids = list(CHECKS)
    assert len(ids) == len(set(ids))
    assert ids == sorted(ids)


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #
def test_strong_target_is_graded_highly(strong_result):
    analysis = strong_result.analysis
    assert analysis is not None
    assert strong_result.ok
    assert strong_result.score >= 90
    assert strong_result.grade in {"A+", "A"}
    assert analysis.counts["CRITICAL"] == 0
    assert analysis.counts["HIGH"] == 0
    assert len(analysis.header_checks) == 9  # the nine core headers


def test_weak_target_collects_many_findings(weak_result):
    ids = {finding.id for finding in weak_result.analysis.findings}
    assert {"HS-002", "HS-101", "HS-311", "HS-400"} <= ids
    assert weak_result.score < 40
    assert weak_result.analysis.recommendations


def test_empty_target_reports_all_missing_headers(empty_result):
    ids = {finding.id for finding in empty_result.analysis.findings}
    assert {"HS-001", "HS-100", "HS-200", "HS-210", "HS-220", "HS-230", "HS-300"} <= ids


def test_plaintext_http_is_reported_once():
    result = scan_from(EMPTY_HEADERS, url="http://example.com/")
    http_findings = [f for f in result.analysis.findings if f.id == "HS-007"]
    assert len(http_findings) == 1
    assert http_findings[0].severity is Severity.HIGH


def test_https_target_has_no_plaintext_finding(strong_result):
    assert all(finding.id != "HS-007" for finding in strong_result.analysis.findings)


def test_http_upgrade_probe_creates_finding():
    probe = HTTPUpgradeProbe(performed=True, url="http://example.com/", status_code=200, redirects_to_https=False)
    result = analyze_response(
        target="https://example.com",
        url="https://example.com/",
        headers=STRONG_HEADERS,
        status_code=200,
        http_probe=probe,
    )
    assert "HS-009" in {finding.id for finding in result.analysis.findings}


def test_tls_findings_are_merged():
    info = TLSInfo(enabled=True, handshake_ok=True, verified=True, hostname_valid=True, protocol="TLSv1")
    result = analyze_response(
        target="https://example.com",
        url="https://example.com/",
        headers=STRONG_HEADERS,
        status_code=200,
        tls_info=info,
    )
    assert "HS-013" in {finding.id for finding in result.analysis.findings}
    assert result.analysis.tls is info


def test_redirect_hops_feed_the_analysis():
    hops = [RedirectHop(1, "http://example.com/", 301, "https://example.com/", set_cookies=["a=1; Path=/"])]
    result = analyze_response(
        target="http://example.com",
        url="http://example.com/",
        final_url="https://example.com/",
        headers=STRONG_HEADERS,
        status_code=200,
        redirect_hops=hops,
    )
    assert result.analysis.redirects.count == 1
    assert result.analysis.cookies.count == 2  # response cookie + redirect cookie


def test_findings_are_sorted_by_severity(weak_result):
    ranks = [finding.severity.rank for finding in weak_result.analysis.findings]
    assert ranks == sorted(ranks)


def test_sort_findings_is_stable_for_equal_severity():
    findings = sort_findings(scan_from(WEAK_HEADERS).analysis.findings)
    ids = [f.id for f in findings if f.severity is Severity.MEDIUM]
    assert ids == sorted(ids)


def test_recommendations_are_deduplicated_and_capped(weak_result):
    recommendations = build_recommendations(weak_result.analysis.findings, limit=5)
    assert len(recommendations) <= 5
    assert len(set(recommendations)) == len(recommendations)


def test_scan_result_serialises_completely(weak_result):
    payload = json.loads(json.dumps(weak_result.to_dict()))
    assert payload["tool"] == "HeaderSpecter"
    assert payload["analysis"]["cookies"]["count"] == 2
    assert payload["analysis"]["csp"]["present"] is True
    assert payload["analysis"]["score"]["deductions"]
    assert payload["headers"][0]["name"] == "Date"


def test_raw_headers_text_round_trip(strong_result):
    text = strong_result.raw_headers_text()
    assert text.startswith("HTTP/2 200 OK")
    assert "Content-Security-Policy:" in text


def test_bonus_flags_are_applied(strong_result):
    bonuses = {bonus.key for bonus in strong_result.analysis.score.bonuses}
    assert {"hsts_preload", "csp_nonce_or_hash", "cross_origin_isolated"} == bonuses


# --------------------------------------------------------------------------- #
# Custom policy
# --------------------------------------------------------------------------- #
def make_policy(**kwargs) -> HeaderPolicy:
    """Build a policy from a mapping."""
    return HeaderPolicy.from_mapping({"name": "test", **kwargs})


def test_policy_required_headers():
    policy = make_policy(required=["x-frame-options", "content-security-policy"])
    result = scan_from(EMPTY_HEADERS, policy=policy)
    policy_findings = [f for f in result.analysis.findings if f.id == "HS-900"]
    assert len(policy_findings) == 2
    assert "X-Frame-Options" in policy_findings[0].title or "Content-Security-Policy" in policy_findings[0].title


def test_policy_forbidden_headers():
    policy = make_policy(forbidden=["x-powered-by"])
    result = scan_from(WEAK_HEADERS, policy=policy)
    assert "HS-901" in {f.id for f in result.analysis.findings}


def test_policy_value_matching_literal_and_regex():
    policy = make_policy(
        values={
            "x-frame-options": ["DENY"],
            "referrer-policy": "re:^strict-origin",
        }
    )
    ok = scan_from(STRONG_HEADERS, policy=policy)
    assert "HS-902" not in {f.id for f in ok.analysis.findings}

    bad = scan_from(WEAK_HEADERS, policy=policy)
    violations = [f for f in bad.analysis.findings if f.id == "HS-902"]
    assert len(violations) == 2


def test_policy_severity_override_by_id_and_header():
    policy = make_policy(severity={"HS-100": "critical", "server": "high"})
    result = scan_from(WEAK_HEADERS, policy=policy)
    server_findings = [f for f in result.analysis.findings if f.header == "server"]
    assert server_findings and server_findings[0].severity is Severity.HIGH

    missing_csp = scan_from(EMPTY_HEADERS, policy=policy)
    csp_finding = next(f for f in missing_csp.analysis.findings if f.id == "HS-100")
    assert csp_finding.severity is Severity.CRITICAL


def test_policy_name_is_recorded():
    policy = make_policy(required=["server"])
    result = scan_from(STRONG_HEADERS, policy=policy)
    assert result.analysis.policy_name == "test"


def test_policy_loads_from_yaml(tmp_path):
    path = tmp_path / "policy.yaml"
    path.write_text(
        "name: Example\nrequired:\n  - content-security-policy\nforbidden:\n  - x-powered-by\nmin_score: 75\n",
        encoding="utf-8",
    )
    policy = HeaderPolicy.load(path)
    assert policy.name == "Example"
    assert policy.required == ["content-security-policy"]
    assert policy.min_score == 75.0


def test_policy_loads_from_json(tmp_path):
    path = tmp_path / "policy.json"
    path.write_text(json.dumps({"name": "J", "required": ["server"]}), encoding="utf-8")
    policy = HeaderPolicy.load(path)
    assert policy.name == "J"


def test_policy_missing_file():
    with pytest.raises(PolicyError):
        HeaderPolicy.load("/nonexistent/policy.yaml")


def test_policy_invalid_yaml(tmp_path):
    path = tmp_path / "bad.yaml"
    path.write_text("name: [unclosed\n", encoding="utf-8")
    with pytest.raises(PolicyError):
        HeaderPolicy.load(path)


def test_shipped_example_policy_is_valid():
    policy = HeaderPolicy.load("examples/policy.yaml")
    assert policy.name
    assert policy.required and policy.forbidden
    assert policy.min_score == 80
    config = policy.scoring_config()
    assert config.severity_weights["CRITICAL"] == 30.0


def test_shipped_example_policy_applies_cleanly():
    policy = HeaderPolicy.load("examples/policy.yaml")
    strong = scan_from(STRONG_HEADERS, policy=policy)
    weak = scan_from(WEAK_HEADERS, policy=policy)
    assert strong.score > weak.score
    assert "HS-901" in {f.id for f in weak.analysis.findings}  # x-powered-by is forbidden
