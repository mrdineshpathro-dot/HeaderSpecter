"""Tests for the cookie security analyzer."""

from __future__ import annotations

from headerspecter.cookies import analyze_cookies, parse_set_cookie, summarize
from headerspecter.findings import Severity
from headerspecter.headers import HeaderBag


def test_parse_attributes():
    cookie = parse_set_cookie(
        "sid=deadbeefcafe; Path=/app; Domain=example.com; Secure; HttpOnly; SameSite=Strict; Max-Age=3600"
    )
    assert cookie.name == "sid"
    assert cookie.secure is True
    assert cookie.http_only is True
    assert cookie.same_site == "Strict"
    assert cookie.domain == "example.com"
    assert cookie.path == "/app"
    assert cookie.max_age == 3600
    assert cookie.session_like is True


def test_cookie_value_is_redacted():
    cookie = parse_set_cookie("token=supersecretvalue123456; Secure")
    assert "supersecretvalue" not in cookie.value_preview
    assert cookie.value_preview.startswith("supe")
    assert "redacted" in cookie.value_preview
    assert "supersecretvalue" not in str(cookie.to_dict())


def test_parse_handles_leading_dot_domain_and_case():
    cookie = parse_set_cookie("a=1; domain=.Example.COM; secure; httponly; samesite=none")
    assert cookie.domain == "example.com"
    assert cookie.secure and cookie.http_only
    assert cookie.same_site == "None"


def test_parse_cookie_without_value():
    cookie = parse_set_cookie("flag; Secure")
    assert cookie.name == "flag"
    assert cookie.value_preview == "(empty)"


def test_expires_lifetime_is_computed():
    cookie = parse_set_cookie("a=1; Expires=Wed, 09 Jun 2100 10:18:14 GMT")
    assert cookie.lifetime_seconds is not None
    assert cookie.lifetime_seconds > 0


def test_secure_cookie_on_https_has_no_findings(https_context):
    bag = HeaderBag([("Set-Cookie", "__Host-session=abc; Path=/; Secure; HttpOnly; SameSite=Lax")])
    analysis = analyze_cookies(bag, https_context)
    assert analysis.count == 1
    assert analysis.findings == []
    assert analysis.cookies[0].status is Severity.PASS


def test_insecure_cookie_flags(https_context):
    bag = HeaderBag([("Set-Cookie", "sessionid=abc; Path=/")])
    analysis = analyze_cookies(bag, https_context)
    found = {finding.id for finding in analysis.findings}
    assert {"HS-400", "HS-401", "HS-402"} <= found
    assert analysis.cookies[0].status is Severity.HIGH


def test_samesite_none_without_secure(https_context):
    bag = HeaderBag([("Set-Cookie", "a=1; SameSite=None; HttpOnly")])
    analysis = analyze_cookies(bag, https_context)
    assert "HS-403" in {finding.id for finding in analysis.findings}


def test_broad_domain_scope(https_context):
    bag = HeaderBag([("Set-Cookie", "a=1; Domain=example.com; Secure; HttpOnly; SameSite=Lax")])
    context = https_context
    context.host = "app.example.com"
    analysis = analyze_cookies(bag, context)
    assert "HS-404" in {finding.id for finding in analysis.findings}


def test_host_prefix_violation(https_context):
    bag = HeaderBag([("Set-Cookie", "__Host-a=1; Domain=example.com; Path=/admin; Secure; HttpOnly; SameSite=Lax")])
    analysis = analyze_cookies(bag, https_context)
    assert "HS-405" in {finding.id for finding in analysis.findings}


def test_secure_prefix_violation(https_context):
    bag = HeaderBag([("Set-Cookie", "__Secure-a=1; HttpOnly; SameSite=Lax")])
    analysis = analyze_cookies(bag, https_context)
    assert "HS-405" in {finding.id for finding in analysis.findings}


def test_long_lifetime(https_context):
    bag = HeaderBag([("Set-Cookie", "a=1; Max-Age=63072000; Secure; HttpOnly; SameSite=Lax")])
    analysis = analyze_cookies(bag, https_context)
    assert "HS-406" in {finding.id for finding in analysis.findings}


def test_cookie_over_http(http_context):
    bag = HeaderBag([("Set-Cookie", "a=1; HttpOnly; SameSite=Lax")])
    analysis = analyze_cookies(bag, http_context)
    assert "HS-407" in {finding.id for finding in analysis.findings}


def test_redirect_cookies_are_included(https_context):
    bag = HeaderBag([])
    analysis = analyze_cookies(bag, https_context, [("https://example.com/login", "tmp=1; Path=/")])
    assert analysis.count == 1
    assert analysis.cookies[0].source.startswith("redirect:")


def test_multiple_cookies_are_analysed_individually(https_context):
    bag = HeaderBag(
        [
            ("Set-Cookie", "good=1; Secure; HttpOnly; SameSite=Lax"),
            ("Set-Cookie", "bad=2"),
        ]
    )
    analysis = analyze_cookies(bag, https_context)
    assert analysis.count == 2
    assert analysis.insecure_count == 1
    stats = summarize(analysis.cookies)
    assert stats == {"total": 2, "secure": 1, "http_only": 1, "same_site": 1, "issues": 1}


def test_finding_titles_identify_the_cookie(https_context):
    bag = HeaderBag([("Set-Cookie", "alpha=1"), ("Set-Cookie", "beta=2")])
    analysis = analyze_cookies(bag, https_context)
    titles = " ".join(finding.title for finding in analysis.findings)
    assert "alpha" in titles and "beta" in titles
