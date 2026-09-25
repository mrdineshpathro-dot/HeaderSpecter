"""Scanner tests using mocked HTTP transport (no real network traffic)."""

from __future__ import annotations

import httpx
import pytest
import respx

from headerspecter.config import ScanConfig
from headerspecter.scanner import Scanner

pytestmark = pytest.mark.asyncio

BASE_CONFIG = ScanConfig(
    timeout=5.0,
    retries=1,
    concurrency=4,
    extra_probes=False,
    tls_probe=False,
    http2=False,
)


@respx.mock
async def test_scan_captures_headers_and_analysis():
    respx.get("https://example.com/").mock(
        return_value=httpx.Response(
            200,
            headers=[
                ("Content-Type", "text/html"),
                ("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload"),
                ("X-Content-Type-Options", "nosniff"),
            ],
            text="<html></html>",
        )
    )
    async with Scanner(BASE_CONFIG) as scanner:
        result = await scanner.scan("https://example.com")

    assert result.ok
    assert result.status_code == 200
    assert result.analysis is not None
    assert result.score is not None
    assert result.header_bag().get("x-content-type-options") == "nosniff"
    assert result.analysis.hsts is not None and result.analysis.hsts.preload is True


@respx.mock
async def test_scan_follows_and_records_redirects():
    respx.get("http://example.com/").mock(
        return_value=httpx.Response(301, headers={"Location": "https://example.com/"})
    )
    respx.get("https://example.com/").mock(
        return_value=httpx.Response(
            200, headers={"Set-Cookie": "a=1; Secure; HttpOnly; SameSite=Lax"}, text="ok"
        )
    )
    async with Scanner(BASE_CONFIG) as scanner:
        result = await scanner.scan("http://example.com")

    assert result.final_url == "https://example.com/"
    assert result.analysis is not None
    redirects = result.analysis.redirects
    assert redirects is not None
    assert redirects.count == 1
    assert redirects.upgraded_to_https is True


@respx.mock
async def test_scan_records_cookies_set_during_redirects():
    respx.get("https://example.com/").mock(
        return_value=httpx.Response(
            302, headers=[("Location", "https://example.com/next"), ("Set-Cookie", "temp=1; Path=/")]
        )
    )
    respx.get("https://example.com/next").mock(return_value=httpx.Response(200, text="done"))
    async with Scanner(BASE_CONFIG) as scanner:
        result = await scanner.scan("https://example.com")

    cookies = result.analysis.cookies
    assert cookies is not None and cookies.count == 1
    assert cookies.cookies[0].source.startswith("redirect:")


@respx.mock
async def test_scan_handles_dns_failure_gracefully():
    respx.get("https://nx.invalid/").mock(
        side_effect=httpx.ConnectError("[Errno -2] Name or service not known")
    )
    async with Scanner(BASE_CONFIG) as scanner:
        result = await scanner.scan("https://nx.invalid")

    assert result.ok is False
    assert result.error_kind == "dns"
    assert result.hint
    assert result.grade == "ERR"
    assert result.to_dict()["error_kind"] == "dns"


@respx.mock
async def test_scan_retries_transport_errors():
    route = respx.get("https://flaky.example/")
    route.side_effect = [httpx.ConnectError("boom"), httpx.Response(200, text="ok")]
    async with Scanner(ScanConfig(retries=2, retry_backoff=0.0, extra_probes=False, tls_probe=False, http2=False)) as scanner:
        result = await scanner.scan("https://flaky.example")

    assert result.ok
    assert route.call_count == 2


@respx.mock
async def test_scan_many_preserves_order_and_reports_progress():
    for index in range(4):
        respx.get(f"https://host{index}.example/").mock(return_value=httpx.Response(200, text="ok"))
    targets = [f"https://host{index}.example/" for index in range(4)]

    seen: list[str] = []
    async with Scanner(BASE_CONFIG) as scanner:
        results = await scanner.scan_many(targets, on_result=lambda result: seen.append(result.url))

    assert [result.url for result in results] == targets
    assert len(seen) == 4


@respx.mock
async def test_cors_probe_detects_reflection():
    def responder(request: httpx.Request) -> httpx.Response:
        origin = request.headers.get("Origin")
        headers = {"Content-Type": "application/json"}
        if origin:
            headers["Access-Control-Allow-Origin"] = origin
            headers["Access-Control-Allow-Credentials"] = "true"
        return httpx.Response(200, headers=headers, text="{}")

    respx.get("https://api.example/").mock(side_effect=responder)
    respx.head("http://api.example/").mock(return_value=httpx.Response(301, headers={"Location": "https://api.example/"}))

    config = ScanConfig(extra_probes=True, tls_probe=False, http2=False, retries=0)
    async with Scanner(config) as scanner:
        result = await scanner.scan("https://api.example")

    cors = result.analysis.cors
    assert cors is not None
    assert cors.reflects_origin is True
    assert "HS-312" in {finding.id for finding in result.analysis.findings}


@respx.mock
async def test_http_upgrade_probe_flags_missing_redirect():
    respx.get("https://plain.example/").mock(return_value=httpx.Response(200, text="ok"))
    respx.head("http://plain.example/").mock(return_value=httpx.Response(200, text="ok"))

    config = ScanConfig(extra_probes=True, tls_probe=False, http2=False, retries=0)
    async with Scanner(config) as scanner:
        result = await scanner.scan("https://plain.example")

    assert result.http_probe is not None and result.http_probe.redirects_to_https is False
    assert "HS-009" in {finding.id for finding in result.analysis.findings}


@respx.mock
async def test_custom_headers_and_user_agent_are_sent():
    route = respx.get("https://example.com/").mock(return_value=httpx.Response(200, text="ok"))
    config = ScanConfig(
        user_agent="HeaderSpecter-Test/1.0",
        extra_headers={"X-Audit": "hs"},
        extra_probes=False,
        tls_probe=False,
        http2=False,
    )
    async with Scanner(config) as scanner:
        await scanner.scan("https://example.com")

    request = route.calls[0].request
    assert request.headers["user-agent"] == "HeaderSpecter-Test/1.0"
    assert request.headers["x-audit"] == "hs"


@respx.mock
async def test_scan_records_error_for_timeout():
    respx.get("https://slow.example/").mock(side_effect=httpx.ReadTimeout("too slow"))
    async with Scanner(ScanConfig(retries=0, extra_probes=False, tls_probe=False, http2=False)) as scanner:
        result = await scanner.scan("https://slow.example")

    assert result.error_kind == "timeout"
    assert "timed out" in (result.error or "").lower()
