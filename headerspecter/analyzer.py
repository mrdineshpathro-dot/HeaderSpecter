"""Analysis orchestrator and result model.

:func:`analyze_response` is the heart of HeaderSpecter: it takes everything
captured for a target (status line, headers, redirect chain, TLS handshake,
optional probes) and produces a fully populated :class:`ScanResult`.

The function performs **no I/O**, which means the entire analysis engine can be
unit tested from fixtures and the same code path powers live scans, the
``--from-raw`` offline mode and the interactive "Analyze Raw Headers" menu.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from . import __version__
from .config import ScoringConfig
from .cookies import CookieAnalysis, analyze_cookies
from .cors import CORSAnalysis, analyze_cors
from .csp import CSPAnalysis, analyze_csp
from .findings import Finding, Severity, make_finding, severity_counts, sort_findings
from .headers import (
    CORE_HEADER_ORDER,
    AnalysisContext,
    CrossOriginAnalysis,
    DisclosureItem,
    HeaderBag,
    HeaderCheck,
    HSTSAnalysis,
    PermissionsPolicyAnalysis,
    analyze_caching,
    analyze_content_type_options,
    analyze_cross_origin,
    analyze_deprecated,
    analyze_disclosure,
    analyze_frame_options,
    analyze_hsts,
    analyze_permissions_policy,
    analyze_referrer_policy,
)
from .policy import HeaderPolicy
from .redirects import RedirectAnalysis, RedirectHop, analyze_redirects
from .scoring import ScoreResult, compute_score
from .tls import TLSInfo, analyze_tls
from .utils import host_of, is_https, iso_now

__all__ = [
    "AnalysisResult",
    "ScanResult",
    "HTTPUpgradeProbe",
    "analyze_response",
    "build_recommendations",
]

#: Maximum number of "→" recommendation lines shown in the terminal summary.
MAX_RECOMMENDATIONS = 8


@dataclass(slots=True)
class HTTPUpgradeProbe:
    """Result of the optional plaintext-HTTP upgrade probe."""

    performed: bool = False
    url: str = ""
    status_code: int | None = None
    location: str | None = None
    redirects_to_https: bool = False
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """JSON-serialisable representation."""
        return {
            "performed": self.performed,
            "url": self.url,
            "status_code": self.status_code,
            "location": self.location,
            "redirects_to_https": self.redirects_to_https,
            "error": self.error,
        }


@dataclass(slots=True)
class AnalysisResult:
    """All analyzer outputs for a single response."""

    context: AnalysisContext
    findings: list[Finding] = field(default_factory=list)
    header_checks: list[HeaderCheck] = field(default_factory=list)
    extra_checks: list[HeaderCheck] = field(default_factory=list)
    csp: CSPAnalysis | None = None
    hsts: HSTSAnalysis | None = None
    permissions: PermissionsPolicyAnalysis | None = None
    cross_origin: CrossOriginAnalysis | None = None
    cookies: CookieAnalysis | None = None
    cors: CORSAnalysis | None = None
    redirects: RedirectAnalysis | None = None
    tls: TLSInfo | None = None
    tls_rows: list[tuple[str, Severity, str]] = field(default_factory=list)
    framing_rows: list[tuple[str, Severity, str]] = field(default_factory=list)
    caching_rows: list[tuple[str, Severity, str]] = field(default_factory=list)
    disclosure: list[DisclosureItem] = field(default_factory=list)
    score: ScoreResult | None = None
    recommendations: list[str] = field(default_factory=list)
    policy_name: str | None = None

    @property
    def counts(self) -> dict[str, int]:
        """Finding counts per severity."""
        return severity_counts(self.findings)

    @property
    def issues(self) -> list[Finding]:
        """Findings excluding PASS entries."""
        return [finding for finding in self.findings if finding.is_issue]

    def to_dict(self) -> dict[str, Any]:
        """JSON-serialisable representation."""
        return {
            "counts": self.counts,
            "score": self.score.to_dict() if self.score else None,
            "header_checks": [check.to_dict() for check in self.header_checks],
            "extra_checks": [check.to_dict() for check in self.extra_checks],
            "findings": [finding.to_dict() for finding in self.findings],
            "csp": self.csp.to_dict() if self.csp else None,
            "hsts": self.hsts.to_dict() if self.hsts else None,
            "permissions_policy": self.permissions.to_dict() if self.permissions else None,
            "cross_origin": self.cross_origin.to_dict() if self.cross_origin else None,
            "cookies": self.cookies.to_dict() if self.cookies else None,
            "cors": self.cors.to_dict() if self.cors else None,
            "redirects": self.redirects.to_dict() if self.redirects else None,
            "tls": self.tls.to_dict() if self.tls else None,
            "tls_checks": _rows_to_dicts(self.tls_rows),
            "framing_checks": _rows_to_dicts(self.framing_rows),
            "caching_checks": _rows_to_dicts(self.caching_rows),
            "disclosure": [item.to_dict() for item in self.disclosure],
            "recommendations": list(self.recommendations),
            "policy": self.policy_name,
        }


@dataclass(slots=True)
class ScanResult:
    """Everything HeaderSpecter knows about one scanned target."""

    target: str
    url: str
    final_url: str = ""
    status_code: int | None = None
    reason: str = ""
    http_version: str = ""
    elapsed_ms: float = 0.0
    headers: list[tuple[str, str]] = field(default_factory=list)
    request_headers: dict[str, str] = field(default_factory=dict)
    analysis: AnalysisResult | None = None
    error: str | None = None
    error_kind: str | None = None
    hint: str | None = None
    scanned_at: str = field(default_factory=iso_now)
    http_probe: HTTPUpgradeProbe | None = None
    meta: dict[str, Any] = field(default_factory=dict)

    # -- convenience -------------------------------------------------------
    @property
    def ok(self) -> bool:
        """True when the target was reachable and analysed."""
        return self.error is None and self.analysis is not None

    @property
    def score(self) -> float | None:
        """Numeric security score (``None`` for failed scans)."""
        if self.analysis and self.analysis.score:
            return self.analysis.score.score
        return None

    @property
    def grade(self) -> str:
        """Letter grade (``ERR`` for failed scans)."""
        if self.analysis and self.analysis.score:
            return self.analysis.score.grade
        return "ERR"

    @property
    def host(self) -> str:
        """Hostname of the final URL (falls back to the requested URL)."""
        return host_of(self.final_url or self.url)

    @property
    def counts(self) -> dict[str, int]:
        """Finding counts per severity."""
        return self.analysis.counts if self.analysis else {}

    def header_bag(self) -> HeaderBag:
        """Rebuild a :class:`HeaderBag` from the stored headers."""
        return HeaderBag(self.headers)

    def raw_headers_text(self) -> str:
        """Re-render the response head exactly as received."""
        status_line = ""
        if self.status_code is not None:
            version = self.http_version or "HTTP/1.1"
            status_line = f"{version} {self.status_code} {self.reason}".strip() + "\n"
        return status_line + "\n".join(f"{name}: {value}" for name, value in self.headers)

    def to_dict(self) -> dict[str, Any]:
        """Full JSON-serialisable representation (the ``--json`` schema)."""
        return {
            "tool": "HeaderSpecter",
            "version": __version__,
            "schema": 1,
            "target": self.target,
            "url": self.url,
            "final_url": self.final_url,
            "scanned_at": self.scanned_at,
            "status_code": self.status_code,
            "reason": self.reason,
            "http_version": self.http_version,
            "elapsed_ms": round(self.elapsed_ms, 2),
            "ok": self.ok,
            "error": self.error,
            "error_kind": self.error_kind,
            "hint": self.hint,
            "score": self.score,
            "grade": self.grade,
            "headers": [{"name": name, "value": value} for name, value in self.headers],
            "request_headers": dict(self.request_headers),
            "http_probe": self.http_probe.to_dict() if self.http_probe else None,
            "analysis": self.analysis.to_dict() if self.analysis else None,
            "meta": dict(self.meta),
        }


def _rows_to_dicts(rows: Sequence[tuple[str, Severity, str]]) -> list[dict[str, str]]:
    return [{"label": label, "status": status.value, "detail": detail} for label, status, detail in rows]


def analyze_response(
    *,
    target: str,
    url: str,
    final_url: str | None = None,
    status_code: int | None = None,
    reason: str = "",
    http_version: str = "",
    elapsed_ms: float = 0.0,
    headers: Sequence[tuple[str, str]] = (),
    request_headers: Mapping[str, str] | None = None,
    redirect_hops: Sequence[RedirectHop] = (),
    tls_info: TLSInfo | None = None,
    probe_headers: Sequence[tuple[str, str]] | None = None,
    probe_origin: str = "",
    http_probe: HTTPUpgradeProbe | None = None,
    policy: HeaderPolicy | None = None,
    scoring: ScoringConfig | None = None,
    cert_expiry_warning_days: int = 30,
    meta: Mapping[str, Any] | None = None,
) -> ScanResult:
    """Run every analyzer over a captured response and build a scan result."""
    resolved_final = final_url or url
    bag = HeaderBag(headers)
    ctx = AnalysisContext(
        url=url,
        final_url=resolved_final,
        host=host_of(resolved_final) or host_of(url),
        is_https=is_https(resolved_final),
        status_code=status_code,
        scheme_upgraded=is_https(resolved_final) and not is_https(url),
        probe_origin=probe_origin,
        content_type=(bag.get("content-type") or "").split(";")[0].strip(),
    )

    findings: list[Finding] = []
    result = AnalysisResult(context=ctx)

    # ---- Content-Security-Policy ----------------------------------------
    csp = analyze_csp(bag, ctx)
    result.csp = csp
    findings.extend(csp.findings)

    # ---- Strict-Transport-Security --------------------------------------
    hsts = analyze_hsts(bag, ctx)
    result.hsts = hsts
    findings.extend(hsts.findings)

    # ---- X-Content-Type-Options -----------------------------------------
    xcto_check, xcto_findings = analyze_content_type_options(bag, ctx)
    findings.extend(xcto_findings)

    # ---- Framing ---------------------------------------------------------
    xfo_check, xfo_findings, framing_rows = analyze_frame_options(bag, ctx, csp.frame_ancestors)
    findings.extend(xfo_findings)
    result.framing_rows = framing_rows

    # ---- Referrer-Policy -------------------------------------------------
    referrer_check, referrer_findings = analyze_referrer_policy(bag, ctx)
    findings.extend(referrer_findings)

    # ---- Permissions-Policy ---------------------------------------------
    permissions = analyze_permissions_policy(bag, ctx)
    result.permissions = permissions
    findings.extend(permissions.findings)

    # ---- Cross-origin isolation -----------------------------------------
    cross_origin = analyze_cross_origin(bag, ctx)
    result.cross_origin = cross_origin
    findings.extend(cross_origin.findings)

    # ---- Cookies ---------------------------------------------------------
    redirect_cookies = [(hop.url, cookie) for hop in redirect_hops for cookie in hop.set_cookies]
    cookies = analyze_cookies(bag, ctx, redirect_cookies)
    result.cookies = cookies
    findings.extend(cookies.findings)

    # ---- CORS ------------------------------------------------------------
    probe_bag = HeaderBag(probe_headers) if probe_headers is not None else None
    cors = analyze_cors(bag, ctx, probe_bag)
    result.cors = cors
    findings.extend(cors.findings)

    # ---- Information disclosure -----------------------------------------
    disclosure, disclosure_findings = analyze_disclosure(bag, ctx)
    result.disclosure = disclosure
    findings.extend(disclosure_findings)

    # ---- Caching ---------------------------------------------------------
    caching_rows, caching_findings = analyze_caching(bag, ctx)
    result.caching_rows = caching_rows
    findings.extend(caching_findings)

    # ---- Deprecated / legacy headers ------------------------------------
    deprecated_checks, deprecated_findings = analyze_deprecated(bag, ctx)
    findings.extend(deprecated_findings)

    # ---- TLS -------------------------------------------------------------
    result.tls = tls_info
    tls_rows, tls_findings = analyze_tls(tls_info, ctx.is_https, warn_days=cert_expiry_warning_days)
    result.tls_rows = tls_rows
    findings.extend(tls_findings)

    # ---- Redirects -------------------------------------------------------
    redirects = analyze_redirects(redirect_hops, resolved_final, status_code, url)
    result.redirects = redirects
    findings.extend(redirects.findings)

    # ---- Plaintext transport --------------------------------------------
    if not ctx.is_https:
        findings.append(
            make_finding(
                "HS-007",
                reason=f"The target was served over plaintext HTTP ({resolved_final}); "
                "no transport encryption protects the response or its cookies.",
                value=resolved_final,
            )
        )

    # ---- Plaintext HTTP upgrade probe ------------------------------------
    if (
        http_probe
        and http_probe.performed
        and not http_probe.redirects_to_https
        and http_probe.status_code is not None
        and http_probe.status_code < 400
    ):
        findings.append(
            make_finding(
                "HS-009",
                reason=f"{http_probe.url} answered with {http_probe.status_code} without redirecting to HTTPS.",
                value=http_probe.location or str(http_probe.status_code),
            )
        )

    # ---- Header summary table -------------------------------------------
    checks_by_header: dict[str, HeaderCheck] = {}
    for check in [
        csp.check,
        hsts.check,
        xcto_check,
        xfo_check,
        referrer_check,
        permissions.check,
        *cross_origin.checks,
    ]:
        if check is not None:
            checks_by_header[check.header.lower()] = check
    result.header_checks = [
        checks_by_header[name] for name in CORE_HEADER_ORDER if name in checks_by_header
    ]
    extra_checks = [check for key, check in checks_by_header.items() if key not in CORE_HEADER_ORDER]
    if cors.check is not None:
        extra_checks.append(cors.check)
    extra_checks.extend(deprecated_checks)
    result.extra_checks = extra_checks

    # ---- Custom policy ---------------------------------------------------
    if policy is not None:
        findings.extend(policy.evaluate(bag))
        findings = policy.apply_severity_overrides(findings)
        result.policy_name = policy.name

    # ---- Score -----------------------------------------------------------
    result.findings = sort_findings(findings)
    scoring_config = policy.scoring_config(scoring) if policy is not None else (scoring or ScoringConfig())
    result.score = compute_score(
        result.findings,
        scoring_config,
        bonus_flags={
            "hsts_preload": bool(hsts.preload and hsts.present and (hsts.max_age or 0) >= 31_536_000),
            "csp_nonce_or_hash": bool(csp.present and (csp.uses_nonce or csp.uses_hash)),
            "cross_origin_isolated": bool(cross_origin.cross_origin_isolated),
        },
    )
    result.recommendations = build_recommendations(result.findings)

    return ScanResult(
        target=target,
        url=url,
        final_url=resolved_final,
        status_code=status_code,
        reason=reason,
        http_version=http_version,
        elapsed_ms=elapsed_ms,
        headers=[(name, value) for name, value in headers],
        request_headers=dict(request_headers or {}),
        analysis=result,
        http_probe=http_probe,
        meta=dict(meta or {}),
    )


def build_recommendations(findings: Sequence[Finding], limit: int = MAX_RECOMMENDATIONS) -> list[str]:
    """Collapse findings into a short, de-duplicated action list."""
    seen: set[str] = set()
    actions: list[str] = []
    for finding in sorted(findings, key=lambda f: (f.severity.rank, f.id)):
        if finding.severity is Severity.PASS:
            continue
        action = finding.recommendation.strip().split(". ")[0].rstrip(".")
        key = action.lower()
        if key in seen or not action:
            continue
        seen.add(key)
        actions.append(action + ".")
        if len(actions) >= limit:
            break
    return actions


def analyze_raw_headers(
    raw_text: str,
    target: str = "raw-input",
    url: str | None = None,
    policy: HeaderPolicy | None = None,
    scoring: ScoringConfig | None = None,
) -> ScanResult:
    """Analyse a pasted/saved response head without touching the network."""
    from .utils import parse_raw_headers  # local import keeps utils dependency light

    meta, headers = parse_raw_headers(raw_text)
    resolved_url = url or "https://raw.input.local/"
    return analyze_response(
        target=target,
        url=resolved_url,
        final_url=resolved_url,
        status_code=meta.get("status_code"),  # type: ignore[arg-type]
        reason=str(meta.get("reason", "")),
        http_version=str(meta.get("http_version", "")),
        headers=headers,
        policy=policy,
        scoring=scoring,
        meta={"source": "raw-headers"},
    )
