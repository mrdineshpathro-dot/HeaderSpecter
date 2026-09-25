"""Cookie security analyzer.

Parses every ``Set-Cookie`` header returned by the target (including cookies
set during the redirect chain) and evaluates the classic attribute hardening
rules: ``Secure``, ``HttpOnly``, ``SameSite``, scope (``Domain``/``Path``),
lifetime and the ``__Secure-`` / ``__Host-`` cookie prefixes.

Cookie *values* are never stored in full: only a short, redacted preview is
kept so that generated reports are safe to share.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any

from .findings import Finding, Severity, make_finding
from .headers import AnalysisContext, HeaderBag
from .utils import registrable_suffix

__all__ = [
    "CookieInfo",
    "CookieAnalysis",
    "parse_set_cookie",
    "analyze_cookies",
    "SESSION_COOKIE_PATTERN",
]

#: Cookie names that usually carry authentication or session state.
SESSION_COOKIE_PATTERN = re.compile(
    r"(sess|sid|auth|token|jwt|login|remember|csrf|xsrf|identity|user|account)",
    re.IGNORECASE,
)

_ONE_YEAR_SECONDS = 31_536_000
_LONG_LIFETIME_SECONDS = 15_552_000  # ~180 days


@dataclass(slots=True)
class CookieInfo:
    """One parsed cookie plus its security attributes."""

    name: str
    value_preview: str
    secure: bool = False
    http_only: bool = False
    same_site: str | None = None
    domain: str | None = None
    path: str | None = None
    max_age: int | None = None
    expires: str | None = None
    lifetime_seconds: int | None = None
    prefix: str | None = None
    session_like: bool = False
    source: str = "response"
    raw: str = ""
    status: Severity = Severity.PASS
    issues: list[str] = field(default_factory=list)

    @property
    def flags(self) -> list[str]:
        """Human readable attribute list used by the reporters."""
        flags: list[str] = []
        flags.append("Secure" if self.secure else "no Secure")
        flags.append("HttpOnly" if self.http_only else "no HttpOnly")
        flags.append(f"SameSite={self.same_site}" if self.same_site else "no SameSite")
        return flags

    def to_dict(self) -> dict[str, Any]:
        """JSON-serialisable representation (value stays redacted)."""
        return {
            "name": self.name,
            "value_preview": self.value_preview,
            "secure": self.secure,
            "http_only": self.http_only,
            "same_site": self.same_site,
            "domain": self.domain,
            "path": self.path,
            "max_age": self.max_age,
            "expires": self.expires,
            "lifetime_seconds": self.lifetime_seconds,
            "prefix": self.prefix,
            "session_like": self.session_like,
            "source": self.source,
            "status": self.status.value,
            "issues": list(self.issues),
        }


@dataclass(slots=True)
class CookieAnalysis:
    """Aggregated cookie posture."""

    cookies: list[CookieInfo] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    @property
    def count(self) -> int:
        """Number of cookies analysed."""
        return len(self.cookies)

    @property
    def insecure_count(self) -> int:
        """Cookies with at least one issue."""
        return sum(1 for cookie in self.cookies if cookie.issues)

    def to_dict(self) -> dict[str, Any]:
        """JSON-serialisable representation."""
        return {
            "count": self.count,
            "insecure_count": self.insecure_count,
            "cookies": [cookie.to_dict() for cookie in self.cookies],
        }


def _redact(value: str, keep: int = 4) -> str:
    """Redact a cookie value, keeping a short prefix for identification."""
    value = value.strip()
    if not value:
        return "(empty)"
    if len(value) <= keep:
        return "*" * len(value)
    return f"{value[:keep]}…({len(value)} chars, redacted)"


def parse_set_cookie(raw: str, source: str = "response") -> CookieInfo:
    """Parse one ``Set-Cookie`` header value.

    >>> cookie = parse_set_cookie("id=abc123; Secure; HttpOnly; SameSite=Lax; Path=/")
    >>> cookie.name, cookie.secure, cookie.http_only, cookie.same_site
    ('id', True, True, 'Lax')
    """
    parts = [segment.strip() for segment in raw.split(";")]
    name_value = parts[0] if parts else ""
    if "=" in name_value:
        name, _, value = name_value.partition("=")
    else:
        name, value = name_value, ""
    name = name.strip()

    cookie = CookieInfo(
        name=name or "(unnamed)",
        value_preview=_redact(value),
        raw=raw.strip(),
        source=source,
    )

    lowered_name = name.lower()
    if lowered_name.startswith("__host-"):
        cookie.prefix = "__Host-"
    elif lowered_name.startswith("__secure-"):
        cookie.prefix = "__Secure-"
    cookie.session_like = bool(SESSION_COOKIE_PATTERN.search(name))

    for attribute in parts[1:]:
        if not attribute:
            continue
        key, _, attr_value = attribute.partition("=")
        key = key.strip().lower()
        attr_value = attr_value.strip()
        if key == "secure":
            cookie.secure = True
        elif key == "httponly":
            cookie.http_only = True
        elif key == "samesite":
            cookie.same_site = attr_value.strip().capitalize() if attr_value else None
        elif key == "domain":
            cookie.domain = attr_value.lstrip(".").lower() or None
        elif key == "path":
            cookie.path = attr_value or None
        elif key == "max-age":
            try:
                cookie.max_age = int(attr_value)
            except ValueError:
                cookie.max_age = None
        elif key == "expires":
            cookie.expires = attr_value or None

    cookie.lifetime_seconds = _lifetime_seconds(cookie)
    return cookie


def _lifetime_seconds(cookie: CookieInfo) -> int | None:
    """Best-effort cookie lifetime in seconds (``None`` for session cookies)."""
    if cookie.max_age is not None:
        return cookie.max_age
    if not cookie.expires:
        return None
    try:
        expires_at = parsedate_to_datetime(cookie.expires)
    except (TypeError, ValueError, IndexError):
        return None
    if expires_at is None:
        return None
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    return int((expires_at - datetime.now(timezone.utc)).total_seconds())


def analyze_cookies(
    bag: HeaderBag,
    ctx: AnalysisContext,
    redirect_cookies: Sequence[tuple[str, str]] | None = None,
) -> CookieAnalysis:
    """Analyse every cookie set by the response (and by redirect hops)."""
    analysis = CookieAnalysis()
    raw_cookies: list[tuple[str, str]] = [("response", value) for value in bag.get_all("set-cookie")]
    for source_url, value in redirect_cookies or []:
        raw_cookies.append((f"redirect:{source_url}", value))

    for source, raw in raw_cookies:
        cookie = parse_set_cookie(raw, source=source)
        analysis.findings.extend(_evaluate_cookie(cookie, ctx))
        analysis.cookies.append(cookie)
    return analysis


def _evaluate_cookie(cookie: CookieInfo, ctx: AnalysisContext) -> list[Finding]:
    """Apply the cookie hardening rules and annotate ``cookie`` in place."""
    findings: list[Finding] = []
    label = f"{cookie.name} ({'set on ' + cookie.source if cookie.source != 'response' else 'response'})"
    worst = Severity.PASS

    def record(finding: Finding, issue: str) -> None:
        nonlocal worst
        findings.append(finding)
        cookie.issues.append(issue)
        if finding.severity.rank < worst.rank:
            worst = finding.severity

    if not ctx.is_https:
        record(
            make_finding(
                "HS-407",
                title=f"Cookie set over plaintext HTTP ({cookie.name})",
                reason=f"Cookie '{cookie.name}' was set over a plaintext HTTP response.",
                value=cookie.raw,
                metadata={"cookie": cookie.name},
            ),
            "set over HTTP",
        )

    if not cookie.secure:
        severity = Severity.HIGH if ctx.is_https or cookie.session_like else Severity.MEDIUM
        record(
            make_finding(
                "HS-400",
                severity=severity,
                title=f"Cookie without Secure attribute ({cookie.name})",
                reason=f"Cookie '{cookie.name}' is missing the Secure attribute.",
                value=cookie.raw,
                metadata={"cookie": cookie.name},
            ),
            "missing Secure",
        )

    if not cookie.http_only:
        severity = Severity.MEDIUM if cookie.session_like else Severity.LOW
        record(
            make_finding(
                "HS-401",
                severity=severity,
                title=f"Cookie without HttpOnly attribute ({cookie.name})",
                reason=f"Cookie '{cookie.name}' is readable by JavaScript (no HttpOnly attribute)."
                + (" The name suggests it carries session state." if cookie.session_like else ""),
                value=cookie.raw,
                metadata={"cookie": cookie.name},
            ),
            "missing HttpOnly",
        )

    same_site = (cookie.same_site or "").lower()
    if not same_site:
        record(
            make_finding(
                "HS-402",
                title=f"Cookie without SameSite attribute ({cookie.name})",
                reason=f"Cookie '{cookie.name}' does not set SameSite explicitly.",
                value=cookie.raw,
                metadata={"cookie": cookie.name},
            ),
            "missing SameSite",
        )
    elif same_site == "none" and not cookie.secure:
        record(
            make_finding(
                "HS-403",
                title=f"SameSite=None cookie without Secure ({cookie.name})",
                reason=f"Cookie '{cookie.name}' uses SameSite=None without the Secure attribute; browsers reject it.",
                value=cookie.raw,
                metadata={"cookie": cookie.name},
            ),
            "SameSite=None without Secure",
        )

    if cookie.domain:
        host = ctx.host
        registrable = registrable_suffix(cookie.domain)
        if cookie.domain == registrable and host and host != cookie.domain:
            record(
                make_finding(
                    "HS-404",
                    title=f"Cookie scoped to a broad parent domain ({cookie.name})",
                    reason=f"Cookie '{cookie.name}' is scoped to the parent domain '{cookie.domain}', so every "
                    "subdomain receives it.",
                    value=cookie.raw,
                    metadata={"cookie": cookie.name},
                ),
                "broad Domain scope",
            )

    if cookie.prefix == "__Host-":
        violations: list[str] = []
        if not cookie.secure:
            violations.append("Secure is required")
        if cookie.domain:
            violations.append("Domain must not be set")
        if (cookie.path or "/") != "/":
            violations.append("Path must be /")
        if violations:
            record(
                make_finding(
                    "HS-405",
                    title=f"Cookie prefix requirements not met ({cookie.name})",
                    reason=f"Cookie '{cookie.name}' uses the __Host- prefix but " + "; ".join(violations) + ".",
                    value=cookie.raw,
                    metadata={"cookie": cookie.name},
                ),
                "__Host- prefix violation",
            )
    elif cookie.prefix == "__Secure-" and not cookie.secure:
        record(
            make_finding(
                "HS-405",
                title=f"Cookie prefix requirements not met ({cookie.name})",
                reason=f"Cookie '{cookie.name}' uses the __Secure- prefix without the Secure attribute.",
                value=cookie.raw,
                metadata={"cookie": cookie.name},
            ),
            "__Secure- prefix violation",
        )

    if cookie.lifetime_seconds is not None and cookie.lifetime_seconds > _LONG_LIFETIME_SECONDS:
        days = cookie.lifetime_seconds // 86400
        record(
            make_finding(
                "HS-406",
                title=f"Long-lived persistent cookie ({cookie.name})",
                reason=f"Cookie '{cookie.name}' persists for roughly {days} days.",
                value=cookie.raw,
                metadata={"cookie": cookie.name, "days": days},
            ),
            f"long lifetime (~{days} days)",
        )

    cookie.status = worst
    _ = label  # retained for future verbose output
    return findings


def summarize(cookies: Iterable[CookieInfo]) -> dict[str, int]:
    """Aggregate counters used by the summary tables."""
    cookies = list(cookies)
    return {
        "total": len(cookies),
        "secure": sum(1 for c in cookies if c.secure),
        "http_only": sum(1 for c in cookies if c.http_only),
        "same_site": sum(1 for c in cookies if c.same_site),
        "issues": sum(1 for c in cookies if c.issues),
    }
