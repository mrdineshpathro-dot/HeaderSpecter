"""Tests for the header registry and the per-header analyzers."""

from __future__ import annotations

import pytest

from headerspecter.findings import Severity
from headerspecter.headers import (
    HeaderBag,
    analyze_caching,
    analyze_content_type_options,
    analyze_cross_origin,
    analyze_deprecated,
    analyze_disclosure,
    analyze_frame_options,
    analyze_hsts,
    analyze_permissions_policy,
    analyze_referrer_policy,
    normalize_header_name,
    parse_permissions_policy,
)


# --------------------------------------------------------------------------- #
# HeaderBag
# --------------------------------------------------------------------------- #
def test_header_bag_is_case_insensitive():
    bag = HeaderBag([("Content-TYPE", "text/html")])
    assert bag.get("content-type") == "text/html"
    assert bag.has("CONTENT-TYPE")
    assert "content-type" in bag


def test_header_bag_keeps_multiple_values():
    bag = HeaderBag([("Set-Cookie", "a=1"), ("Set-Cookie", "b=2")])
    assert bag.get_all("set-cookie") == ["a=1", "b=2"]
    assert bag.count("set-cookie") == 2
    assert bag.joined("set-cookie") == "a=1, b=2"
    assert bag.get("set-cookie") == "a=1"


def test_header_bag_raw_text_round_trip():
    bag = HeaderBag([("Server", "nginx"), ("X-Test", "1")])
    assert bag.raw_text() == "Server: nginx\nX-Test: 1"
    assert bag.names() == ["Server", "X-Test"]


def test_normalize_header_name():
    assert normalize_header_name("strict-transport-security") == "Strict-Transport-Security"
    assert normalize_header_name("X-XSS-PROTECTION") == "X-XSS-Protection"
    assert normalize_header_name("x-custom-thing") == "X-Custom-Thing"


# --------------------------------------------------------------------------- #
# HSTS
# --------------------------------------------------------------------------- #
def test_hsts_missing_on_https(empty_bag, https_context):
    analysis = analyze_hsts(empty_bag, https_context)
    assert analysis.present is False
    assert {f.id for f in analysis.findings} == {"HS-001"}
    assert analysis.check.state == "MISSING"


def test_hsts_missing_on_http_is_deferred_to_the_transport_check(empty_bag, http_context):
    # Over plaintext HTTP the missing policy is implied by HS-007, which the
    # orchestrator raises once per target (see test_analyzer).
    analysis = analyze_hsts(empty_bag, http_context)
    assert analysis.findings == []
    assert analysis.check.state == "MISSING"


def test_hsts_strong_policy(strong_bag, https_context):
    analysis = analyze_hsts(strong_bag, https_context)
    assert analysis.max_age == 63072000
    assert analysis.include_subdomains is True
    assert analysis.preload is True
    assert analysis.findings == []
    assert analysis.check.status is Severity.PASS


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("max-age=300", "HS-002"),
        ("max-age=0", "HS-008"),
        ("includeSubDomains", "HS-005"),
        ("max-age=31536000; bogus-token", "HS-005"),
    ],
)
def test_hsts_problem_values(value, expected, https_context):
    analysis = analyze_hsts(HeaderBag([("Strict-Transport-Security", value)]), https_context)
    assert expected in {f.id for f in analysis.findings}


def test_hsts_quoted_max_age_is_parsed(https_context):
    analysis = analyze_hsts(HeaderBag([("Strict-Transport-Security", 'max-age="31536000"')]), https_context)
    assert analysis.max_age == 31536000


def test_hsts_over_http_is_ignored_by_browsers(http_context):
    analysis = analyze_hsts(
        HeaderBag([("Strict-Transport-Security", "max-age=31536000; includeSubDomains")]), http_context
    )
    assert "HS-006" in {f.id for f in analysis.findings}


# --------------------------------------------------------------------------- #
# X-Frame-Options
# --------------------------------------------------------------------------- #
def test_xfo_missing_without_frame_ancestors(empty_bag, https_context):
    check, findings, _ = analyze_frame_options(empty_bag, https_context, None)
    assert check.state == "MISSING"
    assert {f.id for f in findings} == {"HS-200"}


def test_xfo_absent_but_frame_ancestors_present(empty_bag, https_context):
    check, findings, _ = analyze_frame_options(empty_bag, https_context, ["'none'"])
    assert check.status is Severity.PASS
    assert findings == []


def test_xfo_allow_from_is_obsolete(https_context):
    bag = HeaderBag([("X-Frame-Options", "ALLOW-FROM https://partner.example.com")])
    check, findings, _ = analyze_frame_options(bag, https_context, None)
    assert "HS-202" in {f.id for f in findings}
    assert check.status is Severity.MEDIUM


def test_xfo_invalid_value(https_context):
    bag = HeaderBag([("X-Frame-Options", "ALLOWALL")])
    _, findings, _ = analyze_frame_options(bag, https_context, None)
    assert "HS-201" in {f.id for f in findings}


def test_xfo_conflicting_with_frame_ancestors(https_context):
    bag = HeaderBag([("X-Frame-Options", "DENY")])
    _, findings, _ = analyze_frame_options(bag, https_context, ["https://partner.example.com"])
    assert "HS-204" in {f.id for f in findings}


def test_xfo_only_recommends_csp(https_context):
    bag = HeaderBag([("X-Frame-Options", "SAMEORIGIN")])
    _, findings, _ = analyze_frame_options(bag, https_context, None)
    assert "HS-203" in {f.id for f in findings}


# --------------------------------------------------------------------------- #
# X-Content-Type-Options / Referrer-Policy
# --------------------------------------------------------------------------- #
def test_content_type_options(strong_bag, empty_bag, https_context):
    good, findings = analyze_content_type_options(strong_bag, https_context)
    assert good.status is Severity.PASS and findings == []

    missing, findings = analyze_content_type_options(empty_bag, https_context)
    assert missing.state == "MISSING"
    assert {f.id for f in findings} == {"HS-210"}

    invalid, findings = analyze_content_type_options(HeaderBag([("X-Content-Type-Options", "sniff")]), https_context)
    assert {f.id for f in findings} == {"HS-211"}


@pytest.mark.parametrize(
    ("value", "expected_severity"),
    [
        ("strict-origin-when-cross-origin", Severity.PASS),
        ("no-referrer", Severity.PASS),
        ("same-origin", Severity.PASS),
        ("unsafe-url", Severity.MEDIUM),
        ("no-referrer-when-downgrade", Severity.LOW),
        ("origin", Severity.LOW),
    ],
)
def test_referrer_policy_values(value, expected_severity, https_context):
    check, _ = analyze_referrer_policy(HeaderBag([("Referrer-Policy", value)]), https_context)
    assert check.status is expected_severity


def test_referrer_policy_uses_last_valid_token(https_context):
    bag = HeaderBag([("Referrer-Policy", "no-referrer, strict-origin-when-cross-origin")])
    check, findings = analyze_referrer_policy(bag, https_context)
    assert check.status is Severity.PASS
    assert findings == []


def test_referrer_policy_unknown_token(https_context):
    bag = HeaderBag([("Referrer-Policy", "super-secure")])
    _, findings = analyze_referrer_policy(bag, https_context)
    assert "HS-222" in {f.id for f in findings}


def test_referrer_policy_missing(empty_bag, https_context):
    check, findings = analyze_referrer_policy(empty_bag, https_context)
    assert check.state == "MISSING"
    assert {f.id for f in findings} == {"HS-220"}


# --------------------------------------------------------------------------- #
# Permissions-Policy
# --------------------------------------------------------------------------- #
def test_parse_permissions_policy():
    directives, malformed = parse_permissions_policy('camera=(), geolocation=(self "https://a.example"), usb=*')
    assert directives["camera"] == []
    assert directives["geolocation"] == ["self", "https://a.example"]
    assert directives["usb"] == ["*"]
    assert malformed == []


def test_parse_permissions_policy_detects_legacy_syntax():
    _, malformed = parse_permissions_policy("camera 'none'; microphone 'none'")
    assert malformed


def test_permissions_policy_wildcards(https_context):
    bag = HeaderBag([("Permissions-Policy", "camera=*, microphone=*, geolocation=()")])
    analysis = analyze_permissions_policy(bag, https_context)
    assert set(analysis.unrestricted) == {"camera", "microphone"}
    assert "geolocation" in analysis.restricted
    assert {f.id for f in analysis.findings} >= {"HS-231"}


def test_permissions_policy_missing(empty_bag, https_context):
    analysis = analyze_permissions_policy(empty_bag, https_context)
    assert analysis.present is False
    assert {f.id for f in analysis.findings} == {"HS-230"}


def test_permissions_policy_strong(strong_bag, https_context):
    analysis = analyze_permissions_policy(strong_bag, https_context)
    assert analysis.present is True
    assert analysis.unrestricted == []
    assert analysis.findings == []


def test_feature_policy_is_deprecated(https_context):
    bag = HeaderBag([("Feature-Policy", "camera 'none'"), ("Permissions-Policy", "camera=()")])
    analysis = analyze_permissions_policy(bag, https_context)
    assert "HS-234" in {f.id for f in analysis.findings}


# --------------------------------------------------------------------------- #
# Cross-origin isolation
# --------------------------------------------------------------------------- #
def test_cross_origin_isolated(strong_bag, https_context):
    analysis = analyze_cross_origin(strong_bag, https_context)
    assert analysis.cross_origin_isolated is True
    assert analysis.findings == []


def test_cross_origin_missing(empty_bag, https_context):
    analysis = analyze_cross_origin(empty_bag, https_context)
    found = {f.id for f in analysis.findings}
    assert {"HS-300", "HS-302", "HS-304"} <= found


def test_coep_without_coop_is_incomplete(https_context):
    bag = HeaderBag([("Cross-Origin-Embedder-Policy", "require-corp")])
    analysis = analyze_cross_origin(bag, https_context)
    assert analysis.cross_origin_isolated is False
    assert "HS-305" in {f.id for f in analysis.findings}


def test_invalid_cross_origin_value(https_context):
    bag = HeaderBag([("Cross-Origin-Opener-Policy", "same-origin-allow-everything")])
    analysis = analyze_cross_origin(bag, https_context)
    assert "HS-306" in {f.id for f in analysis.findings}


def test_corp_cross_origin_is_informational(https_context):
    bag = HeaderBag([("Cross-Origin-Resource-Policy", "cross-origin")])
    analysis = analyze_cross_origin(bag, https_context)
    assert "HS-303" in {f.id for f in analysis.findings}


# --------------------------------------------------------------------------- #
# Disclosure / caching / deprecated
# --------------------------------------------------------------------------- #
def test_disclosure_detects_versions(weak_bag, https_context):
    items, findings = analyze_disclosure(weak_bag, https_context)
    headers = {item.header for item in items}
    assert {"Server", "X-Powered-By", "Via"} <= headers
    assert {"HS-500", "HS-501", "HS-503"} <= {f.id for f in findings}


def test_disclosure_clean_target(strong_bag, https_context):
    items, findings = analyze_disclosure(strong_bag, https_context)
    assert items == []
    assert findings == []


def test_caching_flags_cacheable_cookie_response(weak_bag, https_context):
    rows, findings = analyze_caching(weak_bag, https_context)
    assert "HS-601" in {f.id for f in findings}
    assert rows


def test_caching_missing_header(empty_bag, https_context):
    _, findings = analyze_caching(empty_bag, https_context)
    assert "HS-600" in {f.id for f in findings}


def test_deprecated_headers(https_context):
    bag = HeaderBag(
        [
            ("Public-Key-Pins", 'pin-sha256="abc"; max-age=100'),
            ("Expect-CT", "max-age=86400"),
            ("X-XSS-Protection", "1"),
            ("X-Permitted-Cross-Domain-Policies", "all"),
        ]
    )
    checks, findings = analyze_deprecated(bag, https_context)
    found = {f.id for f in findings}
    assert {"HS-513", "HS-512", "HS-511", "HS-515"} <= found
    assert any(check.state == "DEPRECATED" for check in checks)


def test_xss_protection_zero_is_only_informational(https_context):
    _, findings = analyze_deprecated(HeaderBag([("X-XSS-Protection", "0")]), https_context)
    ids = {f.id for f in findings}
    assert "HS-510" in ids
    assert "HS-511" not in ids
