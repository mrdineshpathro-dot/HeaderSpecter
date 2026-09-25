"""Asynchronous scanning engine.

The scanner is a thin, well-behaved HTTP client around :mod:`httpx`:

* one main request per target (headers only — response bodies are not fully
  downloaded),
* an optional passive ``Origin`` probe used by the CORS analyzer,
* an optional plaintext-HTTP request used to verify HTTPS enforcement,
* a standard TLS handshake for certificate/protocol posture.

Concurrency is bounded by a semaphore, an optional delay throttles batch runs
and transport errors are retried with exponential backoff.  Nothing here is
aggressive: HeaderSpecter is an auditing tool, not a stress tester.
"""

from __future__ import annotations

import asyncio
import logging
import random
import ssl
import time
from collections.abc import Awaitable, Callable, Iterable, Sequence
from typing import Any

import httpx

from .analyzer import HTTPUpgradeProbe, ScanResult, analyze_response
from .config import DEFAULT_REQUEST_HEADERS, ScanConfig, ScoringConfig
from .policy import HeaderPolicy
from .redirects import RedirectHop
from .tls import TLSInfo, inspect_tls
from .utils import host_of, is_https, iso_now, normalize_url, port_of

LOGGER = logging.getLogger("headerspecter.scanner")

__all__ = ["Scanner", "scan_single", "scan_many"]

#: Never read more than this from a response body (headers are what we need).
MAX_BODY_PEEK = 32 * 1024


class Scanner:
    """Async scanner that turns targets into :class:`ScanResult` objects."""

    def __init__(
        self,
        config: ScanConfig | None = None,
        policy: HeaderPolicy | None = None,
        scoring: ScoringConfig | None = None,
    ) -> None:
        """Create a scanner bound to a configuration, policy and scoring model."""
        self.config = config or ScanConfig()
        self.policy = policy
        self.scoring = scoring
        self._client: httpx.AsyncClient | None = None
        self._semaphore = asyncio.Semaphore(max(1, self.config.concurrency))

    # ------------------------------------------------------------------ #
    # Lifecycle
    # ------------------------------------------------------------------ #
    async def __aenter__(self) -> Scanner:
        """Open the shared HTTP client."""
        self._client = self._build_client()
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        """Close the shared HTTP client."""
        await self.aclose()

    async def aclose(self) -> None:
        """Close the underlying HTTP client."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    def _build_client(self) -> httpx.AsyncClient:
        cfg = self.config
        headers = dict(DEFAULT_REQUEST_HEADERS)
        headers["User-Agent"] = cfg.user_agent
        headers.update(cfg.extra_headers)

        kwargs: dict[str, Any] = {
            "headers": headers,
            "timeout": httpx.Timeout(cfg.timeout, connect=min(cfg.timeout, 10.0)),
            "follow_redirects": cfg.follow_redirects,
            "max_redirects": cfg.max_redirects,
            "verify": cfg.verify_tls,
            "limits": httpx.Limits(
                max_connections=max(4, cfg.concurrency * 2),
                max_keepalive_connections=max(2, cfg.concurrency),
            ),
        }
        if cfg.proxy:
            kwargs["proxy"] = cfg.proxy
        if cfg.http2:
            try:  # h2 is an optional dependency
                import h2  # noqa: F401

                kwargs["http2"] = True
            except ImportError:
                LOGGER.debug("h2 not installed — HTTP/2 negotiation disabled")
        return httpx.AsyncClient(**kwargs)

    @property
    def client(self) -> httpx.AsyncClient:
        """The live HTTP client (created on demand)."""
        if self._client is None:
            self._client = self._build_client()
        return self._client

    # ------------------------------------------------------------------ #
    # Scanning
    # ------------------------------------------------------------------ #
    async def scan(self, target: str, normalize: bool = True) -> ScanResult:
        """Scan one target and return a fully analysed result."""
        url = normalize_url(target) if normalize else target
        async with self._semaphore:
            if self.config.delay > 0:
                await asyncio.sleep(self.config.delay)
            return await self._scan_one(target, url)

    async def scan_many(
        self,
        targets: Sequence[str],
        on_result: Callable[[ScanResult], None] | None = None,
        normalize: bool = True,
    ) -> list[ScanResult]:
        """Scan many targets concurrently, preserving input order."""
        results: list[ScanResult | None] = [None] * len(targets)

        async def worker(index: int, target: str) -> None:
            result = await self.scan(target, normalize=normalize)
            results[index] = result
            if on_result is not None:
                on_result(result)

        await asyncio.gather(*(worker(index, target) for index, target in enumerate(targets)))
        return [result for result in results if result is not None]

    # ------------------------------------------------------------------ #
    # Internals
    # ------------------------------------------------------------------ #
    async def _scan_one(self, target: str, url: str) -> ScanResult:
        cfg = self.config
        started = time.perf_counter()
        try:
            response, hops, elapsed_ms, body_bytes = await self._request_with_retries(url)
        except httpx.HTTPError as exc:
            return self._failure(target, url, exc)
        except ssl.SSLError as exc:  # pragma: no cover - surfaced through httpx normally
            return self._failure(target, url, exc)

        final_url = str(response.url)
        headers = [(name, value) for name, value in response.headers.multi_items()]

        tls_info: TLSInfo | None = None
        probe_headers: list[tuple[str, str]] | None = None
        http_probe: HTTPUpgradeProbe | None = None

        tasks: dict[str, Awaitable[Any]] = {}
        if cfg.tls_probe and is_https(final_url):
            tasks["tls"] = self._inspect_tls(final_url)
        if cfg.extra_probes:
            tasks["cors"] = self._cors_probe(final_url)
            if is_https(final_url):
                tasks["http"] = self._http_upgrade_probe(final_url)

        if tasks:
            gathered = await asyncio.gather(*tasks.values(), return_exceptions=True)
            for key, value in zip(tasks.keys(), gathered, strict=False):
                if isinstance(value, BaseException):
                    LOGGER.debug("%s probe failed for %s: %s", key, url, value)
                    continue
                if key == "tls":
                    tls_info = value
                elif key == "cors":
                    probe_headers = value
                elif key == "http":
                    http_probe = value

        result = analyze_response(
            target=target,
            url=url,
            final_url=final_url,
            status_code=response.status_code,
            reason=response.reason_phrase or "",
            http_version=response.http_version,
            elapsed_ms=elapsed_ms,
            headers=headers,
            request_headers=dict(response.request.headers),
            redirect_hops=hops,
            tls_info=tls_info,
            probe_headers=probe_headers,
            probe_origin=cfg.probe_origin if cfg.extra_probes else "",
            http_probe=http_probe,
            policy=self.policy,
            scoring=self.scoring,
            cert_expiry_warning_days=cfg.cert_expiry_warning_days,
            meta={
                "scanner": "httpx",
                "proxy": cfg.proxy,
                "user_agent": cfg.user_agent,
                "body_bytes_read": body_bytes,
                "total_ms": round((time.perf_counter() - started) * 1000, 2),
                "probes": sorted(tasks.keys()),
            },
        )
        result.scanned_at = iso_now()
        return result

    async def _request_with_retries(
        self, url: str
    ) -> tuple[httpx.Response, list[RedirectHop], float, int]:
        """Issue the main request, retrying transport failures."""
        cfg = self.config
        attempt = 0
        last_error: Exception | None = None
        while attempt <= cfg.retries:
            if attempt:
                backoff = cfg.retry_backoff * (2 ** (attempt - 1)) + random.uniform(0, 0.1)
                LOGGER.debug("retry %s/%s for %s in %.2fs", attempt, cfg.retries, url, backoff)
                await asyncio.sleep(backoff)
            try:
                start = time.perf_counter()
                async with self.client.stream(
                    cfg.method,
                    url,
                    follow_redirects=cfg.follow_redirects,
                ) as response:
                    body_bytes = 0
                    async for chunk in response.aiter_raw():
                        body_bytes += len(chunk)
                        if body_bytes >= MAX_BODY_PEEK:
                            break
                    elapsed_ms = (time.perf_counter() - start) * 1000
                    hops = _build_hops(response)
                    return response, hops, elapsed_ms, body_bytes
            except (httpx.TransportError, httpx.RemoteProtocolError) as exc:
                last_error = exc
                attempt += 1
                continue
        assert last_error is not None  # noqa: S101 - loop always sets it
        raise last_error

    async def _inspect_tls(self, url: str) -> TLSInfo:
        """Run the blocking TLS inspection in a worker thread."""
        host = host_of(url)
        port = port_of(url)
        return await asyncio.to_thread(inspect_tls, host, port, min(self.config.timeout, 15.0))

    async def _cors_probe(self, url: str) -> list[tuple[str, str]] | None:
        """Send one GET with an ``Origin`` header to observe CORS behaviour."""
        try:
            async with self.client.stream(
                "GET",
                url,
                headers={"Origin": self.config.probe_origin},
                follow_redirects=self.config.follow_redirects,
            ) as response:
                async for _ in response.aiter_raw():
                    break
                return [(name, value) for name, value in response.headers.multi_items()]
        except httpx.HTTPError as exc:
            LOGGER.debug("CORS probe failed for %s: %s", url, exc)
            return None

    async def _http_upgrade_probe(self, https_url: str) -> HTTPUpgradeProbe:
        """Check whether the plaintext endpoint redirects to HTTPS."""
        host = host_of(https_url)
        http_url = f"http://{host}/"
        probe = HTTPUpgradeProbe(performed=True, url=http_url)
        try:
            response = await self.client.request(
                "HEAD",
                http_url,
                follow_redirects=False,
                timeout=httpx.Timeout(min(self.config.timeout, 8.0)),
            )
        except httpx.HTTPError as exc:
            probe.error = str(exc)
            return probe
        probe.status_code = response.status_code
        location = response.headers.get("location")
        probe.location = location
        if response.is_redirect and location:
            probe.redirects_to_https = location.lower().startswith("https://") or (
                location.startswith("//") and is_https(https_url)
            )
        return probe

    def _failure(self, target: str, url: str, exc: BaseException) -> ScanResult:
        """Translate an exception into a user-friendly failed scan result."""
        kind, message, hint = classify_error(exc)
        LOGGER.debug("scan failed for %s: %s", url, exc, exc_info=True)
        return ScanResult(
            target=target,
            url=url,
            final_url=url,
            error=message,
            error_kind=kind,
            hint=hint,
            scanned_at=iso_now(),
            meta={"proxy": self.config.proxy},
        )


def _build_hops(response: httpx.Response) -> list[RedirectHop]:
    """Turn ``response.history`` into :class:`RedirectHop` objects."""
    hops: list[RedirectHop] = []
    for index, previous in enumerate(response.history, start=1):
        hops.append(
            RedirectHop(
                index=index,
                url=str(previous.url),
                status_code=previous.status_code,
                location=previous.headers.get("location"),
                elapsed_ms=previous.elapsed.total_seconds() * 1000 if previous.elapsed else None,
                set_cookies=previous.headers.get_list("set-cookie"),
            )
        )
    return hops


def classify_error(exc: BaseException) -> tuple[str, str, str | None]:
    """Map an exception onto ``(kind, message, hint)`` for friendly output."""
    text = str(exc) or exc.__class__.__name__

    if isinstance(exc, httpx.TooManyRedirects):
        return "redirect-loop", "Redirect loop detected (too many redirects)", "Raise --max-redirects or inspect the chain with --redirects"
    if isinstance(exc, httpx.ProxyError):
        return "proxy", f"Proxy error: {text}", "Check that the proxy in --proxy is running and reachable"
    if isinstance(exc, httpx.ConnectTimeout):
        return "timeout", "Connection timed out", "Try increasing --timeout or check network reachability"
    if isinstance(exc, httpx.ReadTimeout):
        return "timeout", "Read timed out waiting for the response", "Try increasing --timeout"
    if isinstance(exc, httpx.PoolTimeout):
        return "timeout", "Timed out waiting for a free connection", "Lower --threads or increase --timeout"
    if isinstance(exc, httpx.TimeoutException):
        return "timeout", f"Request timed out: {text}", "Try increasing --timeout"
    if isinstance(exc, httpx.UnsupportedProtocol):
        return "invalid-url", f"Unsupported URL: {text}", "Targets must use http:// or https://"
    if isinstance(exc, httpx.RemoteProtocolError):
        return "protocol", f"Malformed HTTP response: {text}", "The server may be misbehaving; retry or use --debug"
    if isinstance(exc, httpx.ConnectError):
        lowered = text.lower()
        if "name or service not known" in lowered or "nodename nor servname" in lowered or "temporary failure in name resolution" in lowered or "getaddrinfo" in lowered:
            return "dns", "DNS resolution failed", "Check the hostname spelling and your resolver"
        if "refused" in lowered:
            return "refused", "Connection refused by the target", "Confirm the port/service is open"
        if "wrong_version_number" in lowered or "record layer failure" in lowered:
            return (
                "tls",
                "TLS handshake failed — the port does not appear to speak HTTPS",
                "The service may be plaintext: retry with an explicit http:// URL",
            )
        if "ssl" in lowered or "certificate" in lowered:
            return "tls", f"TLS connection failed: {text}", "Inspect the certificate with --tls or openssl s_client"
        if "unreachable" in lowered:
            return "unreachable", "Network unreachable", "Check routing, VPN or firewall rules"
        if "all connection attempts failed" in lowered:
            return (
                "refused",
                "Could not establish a connection to the target",
                "Check that the host is up and the port is open (firewall, service not listening)",
            )
        return "connect", f"Connection failed: {text}", None
    if isinstance(exc, ssl.SSLError):
        return "tls", f"TLS error: {text}", "The endpoint may require a different TLS configuration"
    if isinstance(exc, httpx.ReadError):
        return "reset", "Connection reset while reading the response", "Retry with --retries 3"
    if isinstance(exc, httpx.HTTPError):
        return "http", f"HTTP error: {text}", None
    return "error", text, None


# --------------------------------------------------------------------------- #
# Convenience wrappers
# --------------------------------------------------------------------------- #
async def scan_single(
    target: str,
    config: ScanConfig | None = None,
    policy: HeaderPolicy | None = None,
    scoring: ScoringConfig | None = None,
) -> ScanResult:
    """Scan one target (async convenience wrapper)."""
    async with Scanner(config, policy, scoring) as scanner:
        return await scanner.scan(target)


async def scan_many(
    targets: Iterable[str],
    config: ScanConfig | None = None,
    policy: HeaderPolicy | None = None,
    scoring: ScoringConfig | None = None,
    on_result: Callable[[ScanResult], None] | None = None,
) -> list[ScanResult]:
    """Scan many targets concurrently (async convenience wrapper)."""
    target_list = list(targets)
    async with Scanner(config, policy, scoring) as scanner:
        return await scanner.scan_many(target_list, on_result=on_result)
