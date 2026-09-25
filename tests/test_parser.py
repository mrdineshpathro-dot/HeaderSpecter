"""Tests for URL/raw-header parsing, CORS, TLS helpers, redirects and the CLI."""

from __future__ import annotations

import io
import json

import pytest

from headerspecter.analyzer import analyze_raw_headers, analyze_response
from headerspecter.cli import build_parser, main
from headerspecter.cors import analyze_cors
from headerspecter.headers import HeaderBag
from headerspecter.redirects import RedirectHop, analyze_redirects
from headerspecter.reporter import compare_payloads, to_csv, to_json, to_markdown
from headerspecter.scanner import classify_error
from headerspecter.tls import TLSInfo, analyze_tls, match_hostname
from headerspecter.utils import (
    InvalidTargetError,
    normalize_url,
    parse_raw_headers,
    read_targets,
    registrable_suffix,
)


# --------------------------------------------------------------------------- #
# URL normalisation
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("example.com", "https://example.com/"),
        ("http://example.com", "http://example.com/"),
        ("HTTPS://Example.COM/Path", "https://example.com/Path"),
        ("https://example.com:443/x", "https://example.com/x"),
        ("http://example.com:80/", "http://example.com/"),
        ("https://example.com:8443/", "https://example.com:8443/"),
        ("https://example.com/a?b=1#frag", "https://example.com/a?b=1"),
        ("  https://example.com/  ", "https://example.com/"),
        ("'example.com'", "https://example.com/"),
        ("//example.com/x", "https://example.com/x"),
        ("127.0.0.1:8080", "https://127.0.0.1:8080/"),
        ("http://localhost:3000", "http://localhost:3000/"),
    ],
)
def test_normalize_url(raw, expected):
    assert normalize_url(raw) == expected


@pytest.mark.parametrize("raw", ["", "   ", "ftp://example.com", "http://", "https://-bad-.com."])
def test_normalize_url_rejects_bad_input(raw):
    with pytest.raises(InvalidTargetError):
        normalize_url(raw)


def test_read_targets_skips_comments_and_dedupes():
    lines = [
        "# comment",
        "",
        "example.com",
        "https://example.com/",
        "https://other.example ",
        "not a url!!",
    ]
    targets, errors = read_targets(lines)
    assert targets == ["https://example.com/", "https://other.example/"]
    assert errors and errors[0][0] == "not a url!!"


def test_registrable_suffix():
    assert registrable_suffix("www.shop.example.co.uk") == "example.co.uk"
    assert registrable_suffix("example.com") == "example.com"
    assert registrable_suffix("a.b.example.com") == "example.com"


# --------------------------------------------------------------------------- #
# Raw header parsing
# --------------------------------------------------------------------------- #
def test_parse_raw_headers_with_status_line():
    text = "HTTP/1.1 301 Moved Permanently\r\nLocation: https://example.com/\r\nServer: nginx\r\n\r\n<html>"
    meta, headers = parse_raw_headers(text)
    assert meta["status_code"] == 301
    assert meta["reason"] == "Moved Permanently"
    assert meta["http_version"] == "HTTP/1.1"
    assert headers == [("Location", "https://example.com/"), ("Server", "nginx")]


def test_parse_raw_headers_without_status_line():
    meta, headers = parse_raw_headers("X-A: 1\nX-B: 2")
    assert meta == {}
    assert headers == [("X-A", "1"), ("X-B", "2")]


def test_parse_raw_headers_folded_lines():
    _, headers = parse_raw_headers("Content-Security-Policy: default-src 'self';\n   script-src 'self'")
    assert headers == [("Content-Security-Policy", "default-src 'self'; script-src 'self'")]


def test_analyze_raw_headers_offline(tmp_path):
    text = (tmp_path / "raw.txt")
    text.write_text("HTTP/2 200 OK\ncontent-security-policy: default-src 'self'\n", encoding="utf-8")
    result = analyze_raw_headers(text.read_text(), url="https://example.com/")
    assert result.status_code == 200
    assert result.analysis is not None
    assert result.analysis.csp is not None and result.analysis.csp.present


# --------------------------------------------------------------------------- #
# CORS
# --------------------------------------------------------------------------- #
def test_cors_absent_is_pass(empty_bag, https_context):
    analysis = analyze_cors(empty_bag, https_context)
    assert analysis.present is False
    assert analysis.findings == []


def test_cors_wildcard_with_credentials(weak_bag, https_context):
    analysis = analyze_cors(weak_bag, https_context)
    found = {finding.id for finding in analysis.findings}
    assert "HS-311" in found
    assert "HS-316" in found  # unsafe methods
    assert "HS-317" in found  # wildcard headers


def test_cors_origin_reflection_with_credentials(https_context):
    probe = HeaderBag(
        [
            ("Access-Control-Allow-Origin", https_context.probe_origin),
            ("Access-Control-Allow-Credentials", "true"),
        ]
    )
    analysis = analyze_cors(HeaderBag([]), https_context, probe)
    assert analysis.reflects_origin is True
    assert "HS-312" in {finding.id for finding in analysis.findings}


def test_cors_origin_reflection_without_credentials(https_context):
    probe = HeaderBag([("Access-Control-Allow-Origin", https_context.probe_origin)])
    analysis = analyze_cors(HeaderBag([]), https_context, probe)
    assert "HS-313" in {finding.id for finding in analysis.findings}


def test_cors_null_origin(https_context):
    analysis = analyze_cors(HeaderBag([("Access-Control-Allow-Origin", "null")]), https_context)
    assert "HS-314" in {finding.id for finding in analysis.findings}


def test_cors_explicit_origin_needs_vary(https_context):
    analysis = analyze_cors(HeaderBag([("Access-Control-Allow-Origin", "https://app.example.com")]), https_context)
    assert "HS-318" in {finding.id for finding in analysis.findings}

    with_vary = analyze_cors(
        HeaderBag([("Access-Control-Allow-Origin", "https://app.example.com"), ("Vary", "Origin")]),
        https_context,
    )
    assert "HS-318" not in {finding.id for finding in with_vary.findings}


def test_cors_multiple_origin_values(https_context):
    bag = HeaderBag(
        [
            ("Access-Control-Allow-Origin", "https://a.example"),
            ("Access-Control-Allow-Origin", "https://b.example"),
        ]
    )
    analysis = analyze_cors(bag, https_context)
    assert "HS-315" in {finding.id for finding in analysis.findings}


# --------------------------------------------------------------------------- #
# Redirects
# --------------------------------------------------------------------------- #
def test_redirect_chain_upgrade_is_positive():
    hops = [
        RedirectHop(1, "http://example.com/", 301, "https://example.com/"),
        RedirectHop(2, "https://example.com/", 301, "https://www.example.com/"),
    ]
    analysis = analyze_redirects(hops, "https://www.example.com/", 200, "http://example.com/")
    assert analysis.upgraded_to_https is True
    assert analysis.downgraded_to_http is False
    assert analysis.cross_host is True
    assert analysis.count == 2


def test_redirect_downgrade_is_flagged():
    hops = [RedirectHop(1, "https://example.com/", 302, "http://example.com/legacy")]
    analysis = analyze_redirects(hops, "http://example.com/legacy", 200, "https://example.com/")
    assert analysis.downgraded_to_http is True
    assert "HS-700" in {finding.id for finding in analysis.findings}


def test_long_redirect_chain():
    hops = [RedirectHop(index, f"https://example.com/{index}", 302) for index in range(1, 7)]
    analysis = analyze_redirects(hops, "https://example.com/final", 200, "https://example.com/1")
    assert "HS-701" in {finding.id for finding in analysis.findings}


def test_redirect_loop_detection():
    hops = [
        RedirectHop(1, "https://example.com/a", 302),
        RedirectHop(2, "https://example.com/b", 302),
        RedirectHop(3, "https://example.com/a", 302),
    ]
    analysis = analyze_redirects(hops, "https://example.com/b", 200, "https://example.com/a")
    assert analysis.looped is True


def test_error_status_is_reported():
    analysis = analyze_redirects([], "https://example.com/", 503, "https://example.com/")
    assert "HS-704" in {finding.id for finding in analysis.findings}


# --------------------------------------------------------------------------- #
# TLS helpers
# --------------------------------------------------------------------------- #
def test_match_hostname_exact_and_wildcard():
    cert = {"subjectAltName": (("DNS", "example.com"), ("DNS", "*.example.com"))}
    assert match_hostname(cert, "example.com")
    assert match_hostname(cert, "api.example.com")
    assert not match_hostname(cert, "a.b.example.com")
    assert not match_hostname(cert, "notexample.com")


def test_match_hostname_falls_back_to_common_name():
    cert = {"subject": ((("commonName", "example.com"),),)}
    assert match_hostname(cert, "example.com")


def test_analyze_tls_expired_certificate():
    info = TLSInfo(
        enabled=True,
        handshake_ok=True,
        verified=False,
        hostname_valid=True,
        protocol="TLSv1.2",
        not_after="Jan  1 00:00:00 2020 GMT",
        expired=True,
        days_remaining=-500,
        host="example.com",
        error="certificate has expired",
    )
    rows, findings = analyze_tls(info, is_https=True)
    ids = {finding.id for finding in findings}
    assert "HS-010" in ids  # expired
    assert "HS-014" in ids  # chain not validated
    assert "HS-015" in ids  # not TLS 1.3
    assert rows


def test_analyze_tls_healthy_certificate():
    info = TLSInfo(
        enabled=True,
        handshake_ok=True,
        verified=True,
        hostname_valid=True,
        protocol="TLSv1.3",
        cipher="TLS_AES_256_GCM_SHA384",
        issuer="O=Let's Encrypt, CN=R3",
        not_after="Dec 10 00:00:00 2026 GMT",
        days_remaining=200,
        host="example.com",
    )
    _, findings = analyze_tls(info, is_https=True)
    assert findings == []


def test_analyze_tls_obsolete_protocol():
    info = TLSInfo(enabled=True, handshake_ok=True, verified=True, hostname_valid=True, protocol="TLSv1")
    _, findings = analyze_tls(info, is_https=True)
    assert "HS-013" in {finding.id for finding in findings}


def test_analyze_tls_http_target():
    rows, findings = analyze_tls(None, is_https=False)
    assert findings == []
    assert rows[0][0] == "HTTPS"


# --------------------------------------------------------------------------- #
# Error classification
# --------------------------------------------------------------------------- #
def test_classify_error_maps_httpx_exceptions():
    import httpx

    assert classify_error(httpx.ConnectTimeout("t"))[0] == "timeout"
    assert classify_error(httpx.TooManyRedirects("loop"))[0] == "redirect-loop"
    assert classify_error(httpx.ProxyError("proxy"))[0] == "proxy"
    kind, message, hint = classify_error(httpx.ConnectError("[Errno -2] Name or service not known"))
    assert kind == "dns"
    assert "DNS" in message
    assert hint


# --------------------------------------------------------------------------- #
# Reporting / diffing
# --------------------------------------------------------------------------- #
def test_json_report_round_trip(strong_result):
    payload = json.loads(to_json([strong_result]))
    assert payload["tool"] == "HeaderSpecter"
    assert payload["analysis"]["score"]["score"] == strong_result.score


def test_json_batch_envelope(strong_result, weak_result):
    payload = json.loads(to_json([strong_result, weak_result]))
    assert payload["target_count"] == 2
    assert len(payload["results"]) == 2


def test_csv_report_has_one_row_per_finding(weak_result):
    lines = to_csv([weak_result]).strip().splitlines()
    assert lines[0].startswith("target,final_url,status_code")
    assert len(lines) - 1 == len(weak_result.analysis.findings)


def test_markdown_report_contains_sections(weak_result):
    markdown = to_markdown([weak_result])
    assert "# HeaderSpecter Security Report" in markdown
    assert "### Findings" in markdown
    assert "### Cookies" in markdown


def test_html_report_is_standalone(weak_result):
    from headerspecter.html_report import render_html

    html = render_html([weak_result])
    assert html.startswith("<!DOCTYPE html>")
    assert "<style>" in html
    assert "http://cdn" not in html.split("<style>")[1].split("</style>")[0]
    assert "cdn.jsdelivr" not in html and "<script" not in html


def test_compare_payloads_detects_changes(strong_result, weak_result):
    diff = compare_payloads(strong_result.to_dict(), weak_result.to_dict())
    assert diff.has_changes
    assert any(name == "Server" for name, _ in diff.added)
    assert any(name == "Cross-Origin-Opener-Policy" for name, _ in diff.removed)
    assert any(name == "Content-Security-Policy" for name, _, _ in diff.changed)
    assert diff.score_delta is not None and diff.score_delta < 0
    assert diff.new_findings


def test_compare_identical_scans_has_no_changes(strong_result):
    diff = compare_payloads(strong_result.to_dict(), strong_result.to_dict())
    assert diff.has_changes is False


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def test_parser_accepts_core_flags():
    parser = build_parser()
    args = parser.parse_args(["https://example.com", "--threads", "20", "--timeout", "5", "--json"])
    assert args.target == "https://example.com"
    assert args.threads == 20
    assert args.timeout == 5.0
    assert args.json is True


def test_cli_version_exits_ok(capsys):
    assert main(["--version"]) == 0
    assert "HeaderSpecter" in capsys.readouterr().out


def test_cli_help_exits_ok(capsys):
    assert main(["--help"]) == 0
    assert "Usage:" in capsys.readouterr().out


def test_cli_offline_raw_analysis(tmp_path, capsys):
    raw = tmp_path / "headers.txt"
    raw.write_text(
        "HTTP/1.1 200 OK\nContent-Security-Policy: default-src 'self'\nX-Content-Type-Options: nosniff\n",
        encoding="utf-8",
    )
    out_json = tmp_path / "report.json"
    code = main(["--from-raw", str(raw), "-u", "https://example.com", "--json", "-o", str(out_json)])
    assert code == 0
    assert out_json.exists()
    payload = json.loads(out_json.read_text())
    assert payload["analysis"]["csp"]["present"] is True


def test_cli_fail_on_threshold(tmp_path):
    raw = tmp_path / "headers.txt"
    raw.write_text("HTTP/1.1 200 OK\nServer: nginx\n", encoding="utf-8")
    assert main(["--from-raw", str(raw), "-u", "https://example.com", "--quiet", "--fail-on", "high"]) == 2
    assert main(["--from-raw", str(raw), "-u", "https://example.com", "--quiet", "--fail-on", "critical"]) == 0


def test_cli_min_score_threshold(tmp_path):
    raw = tmp_path / "headers.txt"
    raw.write_text("HTTP/1.1 200 OK\nServer: nginx\n", encoding="utf-8")
    assert main(["--from-raw", str(raw), "-u", "https://example.com", "--quiet", "--min-score", "99"]) == 2


def test_cli_quiet_mode_prints_one_line(tmp_path, capsys):
    raw = tmp_path / "headers.txt"
    raw.write_text("HTTP/1.1 200 OK\nX-Content-Type-Options: nosniff\n", encoding="utf-8")
    assert main(["--from-raw", str(raw), "-u", "https://example.com", "--quiet", "--no-color"]) == 0
    out = capsys.readouterr().out.strip().splitlines()
    assert len(out) == 1
    assert "score" in out[0] and "grade" in out[0]


def test_cli_reports_missing_target(capsys, monkeypatch):
    monkeypatch.setattr("sys.stdin", io.StringIO(""))
    code = main(["--stdin"])
    captured = capsys.readouterr()
    assert code == 1
    assert "No target supplied" in captured.out


def test_cli_invalid_policy(tmp_path, capsys):
    policy = tmp_path / "policy.yaml"
    policy.write_text("severity:\n  HS-100: not-a-severity\n", encoding="utf-8")
    code = main(["https://example.com", "--policy", str(policy), "--quiet"])
    assert code == 1
    assert "Invalid severity" in capsys.readouterr().out


def test_analysis_is_deterministic():
    headers = [("X-Content-Type-Options", "nosniff"), ("Server", "nginx/1.2.3")]
    first = analyze_response(target="t", url="https://example.com/", headers=headers, status_code=200)
    second = analyze_response(target="t", url="https://example.com/", headers=headers, status_code=200)
    assert [f.id for f in first.analysis.findings] == [f.id for f in second.analysis.findings]
    assert first.score == second.score
