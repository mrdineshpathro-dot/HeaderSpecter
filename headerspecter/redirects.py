"""Redirect chain analyzer.

Builds a readable view of every hop the client followed and flags the security
relevant transitions: plaintext hops, HTTPS → HTTP downgrades, cross-host jumps
and excessively long (or looping) chains.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from .findings import Finding, Severity, make_finding
from .utils import host_of, same_site

__all__ = ["RedirectHop", "RedirectAnalysis", "analyze_redirects"]

#: More hops than this is considered excessive.
MAX_REASONABLE_HOPS = 3


@dataclass(slots=True)
class RedirectHop:
    """One response in the redirect chain."""

    index: int
    url: str
    status_code: int
    location: str | None = None
    elapsed_ms: float | None = None
    set_cookies: list[str] = field(default_factory=list)

    @property
    def scheme(self) -> str:
        """Scheme of this hop's URL."""
        return urlparse(self.url).scheme.lower()

    @property
    def host(self) -> str:
        """Hostname of this hop's URL."""
        return host_of(self.url)

    def to_dict(self) -> dict[str, Any]:
        """JSON-serialisable representation."""
        return {
            "index": self.index,
            "url": self.url,
            "status_code": self.status_code,
            "location": self.location,
            "elapsed_ms": self.elapsed_ms,
            "scheme": self.scheme,
            "host": self.host,
            "set_cookies": len(self.set_cookies),
        }


@dataclass(slots=True)
class RedirectAnalysis:
    """Aggregated redirect posture."""

    hops: list[RedirectHop] = field(default_factory=list)
    count: int = 0
    upgraded_to_https: bool = False
    downgraded_to_http: bool = False
    cross_host: bool = False
    looped: bool = False
    final_url: str = ""
    final_status: int | None = None
    rows: list[tuple[str, Severity, str]] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """JSON-serialisable representation."""
        return {
            "count": self.count,
            "upgraded_to_https": self.upgraded_to_https,
            "downgraded_to_http": self.downgraded_to_http,
            "cross_host": self.cross_host,
            "looped": self.looped,
            "final_url": self.final_url,
            "final_status": self.final_status,
            "hops": [hop.to_dict() for hop in self.hops],
        }


def analyze_redirects(
    hops: Sequence[RedirectHop],
    final_url: str,
    final_status: int | None,
    start_url: str,
) -> RedirectAnalysis:
    """Analyse a redirect chain (``hops`` excludes the final response)."""
    analysis = RedirectAnalysis(
        hops=list(hops),
        count=len(hops),
        final_url=final_url,
        final_status=final_status,
    )

    if not hops:
        analysis.rows.append(("Redirects", Severity.PASS, "none — direct response"))
    else:
        analysis.rows.append(("Redirects", Severity.INFO, f"{len(hops)} hop(s)"))

    chain_urls = [hop.url for hop in hops] + [final_url]
    seen: set[str] = set()
    for url in chain_urls:
        if url in seen:
            analysis.looped = True
            break
        seen.add(url)

    start_host = host_of(start_url)
    previous_scheme = urlparse(start_url).scheme.lower()

    for index, url in enumerate(chain_urls):
        scheme = urlparse(url).scheme.lower()
        host = host_of(url)
        if previous_scheme == "http" and scheme == "https":
            analysis.upgraded_to_https = True
        if previous_scheme == "https" and scheme == "http":
            analysis.downgraded_to_http = True
            analysis.findings.append(
                make_finding(
                    "HS-700",
                    reason=f"Hop {index} redirects from HTTPS to plaintext HTTP: {url}",
                    value=url,
                )
            )
            analysis.rows.append(("Downgrade", Severity.HIGH, f"HTTPS → HTTP at hop {index}"))
        if host and start_host and host != start_host:
            analysis.cross_host = True
        previous_scheme = scheme

    if analysis.upgraded_to_https:
        analysis.rows.append(("HTTP → HTTPS upgrade", Severity.PASS, "plaintext request was redirected to HTTPS"))

    if analysis.cross_host:
        final_host = host_of(final_url)
        related = same_site(start_host, final_host)
        analysis.findings.append(
            make_finding(
                "HS-702",
                severity=Severity.INFO,
                reason=f"The chain leaves the original host ({start_host} → {final_host})."
                + ("" if related else " The destination is on a different registrable domain."),
                value=final_url,
            )
        )
        analysis.rows.append(
            (
                "Host change",
                Severity.INFO,
                f"{start_host} → {final_host}" + ("" if related else " (different site)"),
            )
        )

    if analysis.count > MAX_REASONABLE_HOPS or analysis.looped:
        analysis.findings.append(
            make_finding(
                "HS-701",
                reason=(
                    f"The chain contains a loop ({analysis.count} hops)."
                    if analysis.looped
                    else f"The chain contains {analysis.count} hops before reaching the final response."
                ),
                value=" → ".join(chain_urls[:6]) + (" …" if len(chain_urls) > 6 else ""),
            )
        )
        analysis.rows.append(
            ("Chain length", Severity.LOW, f"{analysis.count} hops" + (" with a loop" if analysis.looped else ""))
        )

    if final_status is not None:
        if 500 <= final_status < 600:
            analysis.findings.append(
                make_finding(
                    "HS-704",
                    reason=f"The final response status is {final_status}.",
                    value=str(final_status),
                )
            )
        elif not 200 <= final_status < 400:
            analysis.findings.append(
                make_finding(
                    "HS-703",
                    reason=f"The final response status is {final_status}, so these headers may belong to an error page.",
                    value=str(final_status),
                )
            )

    return analysis
