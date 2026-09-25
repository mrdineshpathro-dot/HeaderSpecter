"""Shared fixtures: realistic response header sets for offline testing."""

from __future__ import annotations

import pytest

from headerspecter.analyzer import ScanResult, analyze_response
from headerspecter.headers import AnalysisContext, HeaderBag

STRONG_HEADERS: list[tuple[str, str]] = [
    ("Date", "Thu, 25 Sep 2026 10:14:31 GMT"),
    ("Content-Type", "text/html; charset=utf-8"),
    (
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self' 'nonce-Kj8vQ2mZp1Xw7bNc4RtY9f' 'strict-dynamic'; "
        "style-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'self'; "
        "form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests; report-to csp-endpoint",
    ),
    ("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload"),
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "strict-origin-when-cross-origin"),
    (
        "Permissions-Policy",
        "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), "
        "microphone=(), payment=(), usb=(), display-capture=(), midi=(), serial=(), "
        "bluetooth=(), hid=(), idle-detection=(), screen-wake-lock=()",
    ),
    ("Cross-Origin-Opener-Policy", "same-origin"),
    ("Cross-Origin-Resource-Policy", "same-origin"),
    ("Cross-Origin-Embedder-Policy", "require-corp"),
    ("X-Permitted-Cross-Domain-Policies", "none"),
    ("Cache-Control", "no-store"),
    ("Set-Cookie", "__Host-session=2f1c9d0a7b; Path=/; Secure; HttpOnly; SameSite=Lax"),
]

WEAK_HEADERS: list[tuple[str, str]] = [
    ("Date", "Thu, 25 Sep 2026 10:14:31 GMT"),
    ("Content-Type", "text/html; charset=UTF-8"),
    ("Server", "nginx/1.18.0 (Ubuntu)"),
    ("X-Powered-By", "PHP/7.4.3"),
    ("Strict-Transport-Security", "max-age=300"),
    (
        "Content-Security-Policy",
        "default-src * 'unsafe-inline' 'unsafe-eval'; script-src * 'unsafe-inline' 'unsafe-eval' data:; "
        "style-src * 'unsafe-inline'; frame-ancestors *; report-uri /csp-report",
    ),
    ("X-Frame-Options", "ALLOW-FROM https://partner.example.com"),
    ("X-XSS-Protection", "1; mode=block"),
    ("Referrer-Policy", "unsafe-url"),
    ("Access-Control-Allow-Origin", "*"),
    ("Access-Control-Allow-Credentials", "true"),
    ("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, TRACE"),
    ("Access-Control-Allow-Headers", "*"),
    ("Cache-Control", "public, max-age=86400"),
    ("Set-Cookie", "PHPSESSID=9b2f1ad4c8e7; path=/; domain=example.com"),
    ("Set-Cookie", "tracking_id=7de91c; path=/; Max-Age=63072000; SameSite=None"),
    ("Expect-CT", "max-age=86400, enforce"),
    ("Via", "1.1 edge-cache-04.internal.lab"),
]

EMPTY_HEADERS: list[tuple[str, str]] = [
    ("Date", "Thu, 25 Sep 2026 10:14:31 GMT"),
    ("Content-Type", "text/html"),
    ("Content-Length", "1256"),
]

LEGACY_HEADERS: list[tuple[str, str]] = [
    ("Public-Key-Pins", 'pin-sha256="d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM="; max-age=5184000'),
    ("Expect-CT", "max-age=86400, enforce"),
    ("X-XSS-Protection", "1"),
    ("Pragma", "no-cache"),
    ("Feature-Policy", "camera 'none'; microphone 'none'"),
    ("X-Permitted-Cross-Domain-Policies", "all"),
    ("Server", "Apache/2.4.29 (Ubuntu)"),
    ("X-Generator", "Drupal 7 (https://www.drupal.org)"),
]


@pytest.fixture
def https_context() -> AnalysisContext:
    """Analysis context for an HTTPS target."""
    return AnalysisContext(
        url="https://example.com/",
        final_url="https://example.com/",
        host="example.com",
        is_https=True,
        status_code=200,
        probe_origin="https://headerspecter.invalid",
    )


@pytest.fixture
def http_context() -> AnalysisContext:
    """Analysis context for a plaintext HTTP target."""
    return AnalysisContext(
        url="http://example.com/",
        final_url="http://example.com/",
        host="example.com",
        is_https=False,
        status_code=200,
        probe_origin="https://headerspecter.invalid",
    )


@pytest.fixture
def strong_bag() -> HeaderBag:
    """Header bag with a hardened configuration."""
    return HeaderBag(STRONG_HEADERS)


@pytest.fixture
def weak_bag() -> HeaderBag:
    """Header bag with a weak configuration."""
    return HeaderBag(WEAK_HEADERS)


@pytest.fixture
def empty_bag() -> HeaderBag:
    """Header bag without any security headers."""
    return HeaderBag(EMPTY_HEADERS)


def scan_from(headers: list[tuple[str, str]], url: str = "https://example.com/", **kwargs) -> ScanResult:
    """Build a full :class:`ScanResult` from a header list (no network)."""
    return analyze_response(
        target=url,
        url=url,
        final_url=url,
        status_code=200,
        reason="OK",
        http_version="HTTP/2",
        elapsed_ms=123.4,
        headers=headers,
        **kwargs,
    )


@pytest.fixture
def strong_result() -> ScanResult:
    """Fully analysed hardened target."""
    return scan_from(STRONG_HEADERS)


@pytest.fixture
def weak_result() -> ScanResult:
    """Fully analysed weak target."""
    return scan_from(WEAK_HEADERS)


@pytest.fixture
def empty_result() -> ScanResult:
    """Fully analysed target with no security headers."""
    return scan_from(EMPTY_HEADERS)
