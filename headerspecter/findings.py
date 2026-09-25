"""Findings engine: severities, the finding model and the check catalogue.

Every issue HeaderSpecter can report is registered in :data:`CHECKS` with a
stable identifier (``HS-###``), a default severity, the security impact and a
concrete remediation.  Analyzers never invent free-form findings: they call
:func:`make_finding` with a catalogue id plus the instance-specific details.
That keeps IDs stable for regression testing and baseline diffing.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

__all__ = [
    "Severity",
    "Finding",
    "CheckDefinition",
    "CHECKS",
    "make_finding",
    "sort_findings",
    "severity_counts",
    "server_config_examples",
]


class Severity(str, Enum):
    """Finding severity, ordered from most to least urgent."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    PASS = "PASS"

    @property
    def rank(self) -> int:
        """Sort key: 0 for CRITICAL … 5 for PASS."""
        return _SEVERITY_RANK[self]

    @property
    def color(self) -> str:
        """Rich style associated with this severity."""
        return _SEVERITY_COLOR[self]

    @property
    def icon(self) -> str:
        """Unicode icon key used by the UI layer."""
        return _SEVERITY_ICON[self]

    @classmethod
    def parse(cls, value: str | Severity, default: Severity | None = None) -> Severity:
        """Parse a (case-insensitive) severity name."""
        if isinstance(value, Severity):
            return value
        try:
            return cls(str(value).strip().upper())
        except ValueError:
            if default is not None:
                return default
            raise


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
    Severity.PASS: 5,
}

_SEVERITY_COLOR: dict[Severity, str] = {
    Severity.CRITICAL: "bold bright_red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "bold yellow",
    Severity.LOW: "bold cyan",
    Severity.INFO: "bold blue",
    Severity.PASS: "bold green",
}

_SEVERITY_ICON: dict[Severity, str] = {
    Severity.CRITICAL: "critical",
    Severity.HIGH: "high",
    Severity.MEDIUM: "warn",
    Severity.LOW: "low",
    Severity.INFO: "info",
    Severity.PASS: "pass",
}

#: Severity order used for iteration/summaries.
SEVERITY_ORDER: tuple[Severity, ...] = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
    Severity.PASS,
)


@dataclass(slots=True, frozen=True)
class CheckDefinition:
    """Static metadata for one security check."""

    id: str
    title: str
    category: str
    header: str | None
    severity: Severity
    impact: str
    recommendation: str
    remediation: str | None = None
    references: tuple[str, ...] = ()


@dataclass(slots=True)
class Finding:
    """One concrete observation about a scanned target."""

    id: str
    title: str
    severity: Severity
    category: str
    reason: str
    impact: str
    recommendation: str
    header: str | None = None
    value: str | None = None
    remediation: str | None = None
    references: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def is_issue(self) -> bool:
        """True for anything that is not a PASS."""
        return self.severity is not Severity.PASS

    def to_dict(self) -> dict[str, Any]:
        """JSON-serialisable representation."""
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.value,
            "category": self.category,
            "header": self.header,
            "value": self.value,
            "reason": self.reason,
            "impact": self.impact,
            "recommendation": self.recommendation,
            "remediation": self.remediation,
            "references": list(self.references),
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Finding:
        """Rebuild a finding from :meth:`to_dict` output (baseline loading)."""
        return cls(
            id=str(data.get("id", "HS-000")),
            title=str(data.get("title", "")),
            severity=Severity.parse(data.get("severity", "INFO"), Severity.INFO),
            category=str(data.get("category", "general")),
            reason=str(data.get("reason", "")),
            impact=str(data.get("impact", "")),
            recommendation=str(data.get("recommendation", "")),
            header=data.get("header"),
            value=data.get("value"),
            remediation=data.get("remediation"),
            references=list(data.get("references", []) or []),
            metadata=dict(data.get("metadata", {}) or {}),
        )


def _c(
    id: str,
    title: str,
    category: str,
    header: str | None,
    severity: Severity,
    impact: str,
    recommendation: str,
    remediation: str | None = None,
    references: tuple[str, ...] = (),
) -> CheckDefinition:
    return CheckDefinition(
        id=id,
        title=title,
        category=category,
        header=header,
        severity=severity,
        impact=impact,
        recommendation=recommendation,
        remediation=remediation,
        references=references,
    )


MDN = "https://developer.mozilla.org/docs/Web/HTTP/Headers"
OWASP = "https://owasp.org/www-project-secure-headers/"

# --------------------------------------------------------------------------- #
# Check catalogue
# --------------------------------------------------------------------------- #
_CHECK_LIST: tuple[CheckDefinition, ...] = (
    # ---------------------------------------------------------------- HS-0xx
    # Transport security: HSTS + TLS posture
    _c(
        "HS-001",
        "Missing Strict-Transport-Security",
        "transport",
        "strict-transport-security",
        Severity.HIGH,
        "Without HSTS a browser will happily issue the first request over plaintext HTTP, "
        "leaving users exposed to SSL-stripping and on-path downgrade attacks on hostile "
        "networks, and allowing cookies to leak before any redirect happens.",
        "Send Strict-Transport-Security on every HTTPS response with a max-age of at least "
        "one year once you are confident every subdomain supports TLS.",
        "Strict-Transport-Security: max-age=31536000; includeSubDomains",
        (f"{MDN}/Strict-Transport-Security",),
    ),
    _c(
        "HS-002",
        "HSTS max-age is too short",
        "transport",
        "strict-transport-security",
        Severity.MEDIUM,
        "A short max-age shrinks the window in which the browser enforces HTTPS. Once it "
        "expires the next navigation can be downgraded to HTTP again.",
        "Use max-age=31536000 (one year). Ramp up gradually (300 → 86400 → 31536000) if the "
        "estate is still being migrated.",
        "Strict-Transport-Security: max-age=31536000; includeSubDomains",
        (f"{MDN}/Strict-Transport-Security",),
    ),
    _c(
        "HS-003",
        "HSTS does not cover subdomains",
        "transport",
        "strict-transport-security",
        Severity.LOW,
        "Without includeSubDomains an attacker can target a forgotten subdomain over HTTP "
        "and set or read domain-scoped cookies from there.",
        "Add includeSubDomains after verifying that every subdomain (including internal "
        "ones) is reachable over HTTPS.",
        "Strict-Transport-Security: max-age=31536000; includeSubDomains",
        (f"{MDN}/Strict-Transport-Security",),
    ),
    _c(
        "HS-004",
        "HSTS preload not requested",
        "transport",
        "strict-transport-security",
        Severity.INFO,
        "Without preloading, the very first visit from a fresh browser profile can still be "
        "made over HTTP (trust-on-first-use gap).",
        "Once max-age >= 31536000 and includeSubDomains is set, add the preload token and "
        "submit the domain at hstspreload.org. Preloading is hard to undo — plan first.",
        "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        ("https://hstspreload.org/",),
    ),
    _c(
        "HS-005",
        "Malformed Strict-Transport-Security value",
        "transport",
        "strict-transport-security",
        Severity.MEDIUM,
        "Browsers ignore an HSTS header they cannot parse, so the protection silently does "
        "not exist even though the header is present.",
        "Emit a single, syntactically valid header: max-age=<seconds> with optional "
        "includeSubDomains and preload tokens separated by semicolons.",
        "Strict-Transport-Security: max-age=31536000; includeSubDomains",
        ("https://www.rfc-editor.org/rfc/rfc6797",),
    ),
    _c(
        "HS-006",
        "HSTS sent over plaintext HTTP",
        "transport",
        "strict-transport-security",
        Severity.INFO,
        "HSTS headers received over HTTP are ignored by browsers, so the policy is not "
        "actually applied.",
        "Redirect HTTP to HTTPS first and send the HSTS header on the HTTPS response.",
        None,
        ("https://www.rfc-editor.org/rfc/rfc6797#section-8.1",),
    ),
    _c(
        "HS-007",
        "Target served over plaintext HTTP",
        "transport",
        None,
        Severity.HIGH,
        "All traffic — including cookies, tokens and form data — is transmitted in the "
        "clear and can be read or modified by anyone on the network path.",
        "Terminate TLS for this host and permanently redirect HTTP to HTTPS.",
        "Strict-Transport-Security: max-age=31536000; includeSubDomains",
        (OWASP,),
    ),
    _c(
        "HS-008",
        "HSTS disabled with max-age=0",
        "transport",
        "strict-transport-security",
        Severity.MEDIUM,
        "max-age=0 instructs the browser to forget the HSTS policy for this host, which "
        "re-enables plaintext downgrade attacks.",
        "Restore a positive max-age (31536000) unless you are intentionally rolling HSTS "
        "back.",
        "Strict-Transport-Security: max-age=31536000; includeSubDomains",
        (f"{MDN}/Strict-Transport-Security",),
    ),
    _c(
        "HS-009",
        "HTTPS not enforced for HTTP requests",
        "transport",
        None,
        Severity.HIGH,
        "The plaintext endpoint answered without redirecting to HTTPS, so clients that type "
        "the bare domain stay on an unencrypted channel.",
        "Return 301 to the https:// equivalent for every HTTP request, then serve HSTS.",
        None,
        (OWASP,),
    ),
    _c(
        "HS-010",
        "TLS certificate expired",
        "tls",
        None,
        Severity.CRITICAL,
        "An expired certificate breaks trust for every visitor: browsers show a full-page "
        "interstitial and users are trained to click through it.",
        "Renew the certificate immediately and automate renewal (ACME/certbot) with expiry "
        "monitoring.",
        None,
        ("https://letsencrypt.org/docs/",),
    ),
    _c(
        "HS-011",
        "TLS certificate expires soon",
        "tls",
        None,
        Severity.MEDIUM,
        "A certificate close to expiry risks an outage and browser trust errors if renewal "
        "fails.",
        "Renew now and verify that automated renewal plus alerting are in place.",
        None,
        ("https://letsencrypt.org/docs/",),
    ),
    _c(
        "HS-012",
        "TLS certificate hostname mismatch",
        "tls",
        None,
        Severity.HIGH,
        "The certificate is not valid for the requested hostname, so clients cannot "
        "distinguish this from an on-path interception attempt.",
        "Issue a certificate whose subjectAltName covers the hostname actually served.",
        None,
        ("https://www.rfc-editor.org/rfc/rfc6125",),
    ),
    _c(
        "HS-013",
        "Obsolete TLS protocol negotiated",
        "tls",
        None,
        Severity.HIGH,
        "TLS 1.0/1.1 are deprecated, lack modern cipher suites and are rejected by current "
        "compliance regimes (PCI DSS, browsers).",
        "Disable TLS 1.0/1.1 and serve TLS 1.2 (with strong AEAD suites) and TLS 1.3.",
        None,
        ("https://www.rfc-editor.org/rfc/rfc8996",),
    ),
    _c(
        "HS-014",
        "TLS certificate chain could not be validated",
        "tls",
        None,
        Severity.HIGH,
        "A self-signed or incomplete chain means clients cannot prove they are talking to "
        "the legitimate server, and users get certificate warnings.",
        "Install the full intermediate chain from a publicly trusted CA (or the expected "
        "internal CA for private environments).",
        None,
        ("https://www.ssllabs.com/ssl-pulse/",),
    ),
    _c(
        "HS-015",
        "TLS 1.3 not negotiated",
        "tls",
        None,
        Severity.INFO,
        "TLS 1.3 removes legacy key-exchange and cipher options and offers a faster, safer "
        "handshake.",
        "Enable TLS 1.3 on the terminating server/CDN while keeping TLS 1.2 for older "
        "clients.",
        None,
        ("https://www.rfc-editor.org/rfc/rfc8446",),
    ),
    _c(
        "HS-016",
        "TLS inspection could not be completed",
        "tls",
        None,
        Severity.INFO,
        "HeaderSpecter could not complete the TLS handshake inspection, so certificate and "
        "protocol posture are unknown for this target.",
        "Re-run with a longer --timeout, check firewall/proxy interference, or inspect the "
        "endpoint manually with openssl s_client.",
        None,
        (),
    ),
    # ---------------------------------------------------------------- HS-1xx
    # Content-Security-Policy
    _c(
        "HS-100",
        "Missing Content-Security-Policy",
        "csp",
        "content-security-policy",
        Severity.HIGH,
        "No CSP was detected, so the browser has no policy-level defence against injected "
        "scripts, unexpected resource loads or data exfiltration to attacker domains.",
        "Deploy a restrictive CSP tailored to the application's real resource needs. Start "
        "in Report-Only mode, collect violations, then enforce.",
        "Content-Security-Policy: default-src 'self'; object-src 'none'; base-uri 'self'; "
        "frame-ancestors 'none'; form-action 'self'",
        (f"{MDN}/Content-Security-Policy", "https://csp.withgoogle.com/docs/strict-csp.html"),
    ),
    _c(
        "HS-101",
        "CSP allows 'unsafe-inline' scripts",
        "csp",
        "content-security-policy",
        Severity.HIGH,
        "'unsafe-inline' in a script directive permits inline <script> blocks and event "
        "handlers, which is exactly the capability an XSS payload needs — the policy stops "
        "being a meaningful mitigation.",
        "Move inline scripts to external files, or adopt a nonce/hash based strict CSP with "
        "'strict-dynamic' for third-party loaders.",
        "Content-Security-Policy: script-src 'nonce-{RANDOM}' 'strict-dynamic' https:; "
        "object-src 'none'; base-uri 'self'",
        ("https://csp.withgoogle.com/docs/strict-csp.html",),
    ),
    _c(
        "HS-102",
        "CSP allows 'unsafe-eval'",
        "csp",
        "content-security-policy",
        Severity.MEDIUM,
        "'unsafe-eval' re-enables eval(), new Function() and string timers, giving injected "
        "content a direct route from data to executable code.",
        "Remove 'unsafe-eval' and migrate templating/JSON parsing away from eval-based "
        "helpers (use JSON.parse and pre-compiled templates).",
        "Content-Security-Policy: script-src 'self' 'nonce-{RANDOM}'",
        (f"{MDN}/Content-Security-Policy/script-src",),
    ),
    _c(
        "HS-103",
        "CSP directive uses a wildcard source",
        "csp",
        "content-security-policy",
        Severity.MEDIUM,
        "A wildcard source lets the page load that resource type from any origin, so an "
        "attacker-controlled host is an acceptable source as far as the browser is "
        "concerned.",
        "Replace '*' with the explicit origins the application actually needs.",
        "Content-Security-Policy: default-src 'self'; img-src 'self' https://cdn.example.com",
        (f"{MDN}/Content-Security-Policy",),
    ),
    _c(
        "HS-104",
        "CSP does not restrict object-src",
        "csp",
        "content-security-policy",
        Severity.MEDIUM,
        "Plugin content (<object>, <embed>, <applet>) can execute scripts in the page's "
        "context and has historically been used to bypass CSP entirely.",
        "Add object-src 'none' — virtually no modern application needs plugin content.",
        "Content-Security-Policy: object-src 'none'",
        ("https://csp.withgoogle.com/docs/strict-csp.html",),
    ),
    _c(
        "HS-105",
        "CSP does not restrict base-uri",
        "csp",
        "content-security-policy",
        Severity.MEDIUM,
        "Without base-uri an injected <base> tag can re-point every relative URL on the "
        "page (scripts, forms, links) at an attacker-controlled host.",
        "Add base-uri 'self' (or 'none' for pages with no relative-base requirements).",
        "Content-Security-Policy: base-uri 'self'",
        (f"{MDN}/Content-Security-Policy/base-uri",),
    ),
    _c(
        "HS-106",
        "CSP does not set frame-ancestors",
        "csp",
        "content-security-policy",
        Severity.MEDIUM,
        "frame-ancestors is the modern clickjacking control. Without it the page may be "
        "embedded by third-party sites in browsers that ignore X-Frame-Options.",
        "Add frame-ancestors 'none' (or an explicit allow-list of embedding origins).",
        "Content-Security-Policy: frame-ancestors 'none'",
        (f"{MDN}/Content-Security-Policy/frame-ancestors",),
    ),
    _c(
        "HS-107",
        "CSP has no default-src fallback",
        "csp",
        "content-security-policy",
        Severity.MEDIUM,
        "Directives that are not listed fall back to default-src. Without it, every "
        "unlisted resource type is unrestricted.",
        "Add default-src 'self' (or 'none' plus explicit allow-lists) as a safety net.",
        "Content-Security-Policy: default-src 'self'",
        (f"{MDN}/Content-Security-Policy/default-src",),
    ),
    _c(
        "HS-108",
        "CSP permits insecure http: sources",
        "csp",
        "content-security-policy",
        Severity.MEDIUM,
        "Allowing plaintext http: sources reintroduces mixed content and lets an on-path "
        "attacker substitute the resource.",
        "Use https: origins only and add upgrade-insecure-requests during migration.",
        "Content-Security-Policy: default-src 'self' https:; upgrade-insecure-requests",
        (f"{MDN}/Content-Security-Policy",),
    ),
    _c(
        "HS-109",
        "CSP allows a dangerous scheme source",
        "csp",
        "content-security-policy",
        Severity.HIGH,
        "data:, blob: or filesystem: in a script/object directive lets an attacker encode a "
        "payload directly into a URI and execute it, bypassing origin restrictions.",
        "Remove data:/blob: from script-src and object-src; keep them only for img-src or "
        "media where genuinely required.",
        "Content-Security-Policy: script-src 'self' 'nonce-{RANDOM}'; object-src 'none'",
        (f"{MDN}/Content-Security-Policy/script-src",),
    ),
    _c(
        "HS-110",
        "CSP present in Report-Only mode only",
        "csp",
        "content-security-policy-report-only",
        Severity.MEDIUM,
        "A Report-Only policy collects violations but blocks nothing, so it provides "
        "telemetry rather than protection.",
        "Once the report stream is clean, promote the policy to the enforcing "
        "Content-Security-Policy header.",
        "Content-Security-Policy: default-src 'self'; object-src 'none'; base-uri 'self'",
        (f"{MDN}/Content-Security-Policy-Report-Only",),
    ),
    _c(
        "HS-111",
        "CSP allow-list is very large",
        "csp",
        "content-security-policy",
        Severity.LOW,
        "Large host allow-lists are difficult to audit and frequently contain origins that "
        "host JSONP endpoints or user content, which can be abused to bypass the policy.",
        "Trim unused origins and consider a nonce + 'strict-dynamic' policy, which does not "
        "depend on host allow-lists at all.",
        "Content-Security-Policy: script-src 'nonce-{RANDOM}' 'strict-dynamic'",
        ("https://csp.withgoogle.com/docs/strict-csp.html",),
    ),
    _c(
        "HS-112",
        "CSP has no violation reporting endpoint",
        "csp",
        "content-security-policy",
        Severity.INFO,
        "Without reporting you have no visibility into blocked resources or attempted "
        "injections in production.",
        "Add a report-to group (and report-uri for older browsers) pointing at a collector "
        "you control.",
        "Content-Security-Policy: ...; report-to csp-endpoint\n"
        'Reporting-Endpoints: csp-endpoint="https://example.com/csp-reports"',
        (f"{MDN}/Content-Security-Policy/report-to",),
    ),
    _c(
        "HS-113",
        "CSP style-src allows 'unsafe-inline'",
        "csp",
        "content-security-policy",
        Severity.LOW,
        "Inline styles enable CSS-based data exfiltration and UI redressing tricks, though "
        "the impact is lower than for scripts.",
        "Move inline styles into stylesheets or apply nonces/hashes to style blocks.",
        "Content-Security-Policy: style-src 'self' 'nonce-{RANDOM}'",
        (f"{MDN}/Content-Security-Policy/style-src",),
    ),
    _c(
        "HS-114",
        "CSP does not restrict form-action",
        "csp",
        "content-security-policy",
        Severity.LOW,
        "Without form-action an injected or modified form can post user credentials to an "
        "attacker-controlled endpoint.",
        "Add form-action 'self' (plus any legitimate payment/SSO endpoints).",
        "Content-Security-Policy: form-action 'self'",
        (f"{MDN}/Content-Security-Policy/form-action",),
    ),
    _c(
        "HS-115",
        "CSP contains an unknown or unsupported directive",
        "csp",
        "content-security-policy",
        Severity.LOW,
        "Unknown directives are ignored by browsers. A typo can silently disable an "
        "intended protection.",
        "Remove or correct the directive; validate the policy in browser devtools after "
        "each change.",
        None,
        ("https://www.w3.org/TR/CSP3/",),
    ),
    _c(
        "HS-116",
        "Multiple Content-Security-Policy headers returned",
        "csp",
        "content-security-policy",
        Severity.LOW,
        "Browsers enforce the intersection of all policies. Multiple headers are usually "
        "accidental (app + proxy) and make the effective policy hard to reason about; they "
        "can also break legitimate functionality.",
        "Emit exactly one Content-Security-Policy header from a single place in the stack.",
        None,
        ("https://www.w3.org/TR/CSP3/#multiple-policies",),
    ),
    _c(
        "HS-117",
        "CSP frame-ancestors allows any origin",
        "csp",
        "content-security-policy",
        Severity.HIGH,
        "frame-ancestors * lets any site frame the page, which enables clickjacking and UI "
        "redress attacks against authenticated users.",
        "Set frame-ancestors 'none' or list the specific origins allowed to embed the page.",
        "Content-Security-Policy: frame-ancestors 'none'",
        (f"{MDN}/Content-Security-Policy/frame-ancestors",),
    ),
    _c(
        "HS-118",
        "CSP sandbox allows scripts and same-origin together",
        "csp",
        "content-security-policy",
        Severity.LOW,
        "allow-scripts together with allow-same-origin lets sandboxed content remove its "
        "own sandbox attribute, defeating the isolation.",
        "Drop one of the two tokens, or serve untrusted content from a separate origin.",
        "Content-Security-Policy: sandbox allow-scripts allow-forms",
        (f"{MDN}/Content-Security-Policy/sandbox",),
    ),
    _c(
        "HS-119",
        "CSP uses 'unsafe-hashes'",
        "csp",
        "content-security-policy",
        Severity.LOW,
        "'unsafe-hashes' re-enables inline event handlers (onclick=...) whose hashes match, "
        "widening the inline-script surface.",
        "Replace inline handlers with addEventListener bound from an external script.",
        None,
        (f"{MDN}/Content-Security-Policy/script-src",),
    ),
    _c(
        "HS-120",
        "CSP uses deprecated report-uri only",
        "csp",
        "content-security-policy",
        Severity.INFO,
        "report-uri is deprecated in favour of the Reporting API; newer browsers prefer "
        "report-to and may drop report-uri support.",
        "Keep report-uri for legacy clients but add report-to with a Reporting-Endpoints "
        "header.",
        'Reporting-Endpoints: csp-endpoint="https://example.com/csp-reports"',
        (f"{MDN}/Content-Security-Policy/report-to",),
    ),
    _c(
        "HS-121",
        "CSP is missing upgrade-insecure-requests",
        "csp",
        "content-security-policy",
        Severity.INFO,
        "Legacy absolute http:// URLs inside the page will be blocked or downgraded instead "
        "of being transparently upgraded.",
        "Add upgrade-insecure-requests while migrating mixed content, then fix the URLs.",
        "Content-Security-Policy: upgrade-insecure-requests",
        (f"{MDN}/Content-Security-Policy/upgrade-insecure-requests",),
    ),
    _c(
        "HS-122",
        "CSP nonce looks weak or static",
        "csp",
        "content-security-policy",
        Severity.MEDIUM,
        "A predictable or reused nonce can be guessed and embedded by an attacker, which "
        "makes a nonce-based policy ineffective.",
        "Generate at least 128 bits of cryptographically random data per response and "
        "base64-encode it.",
        "Content-Security-Policy: script-src 'nonce-{RANDOM_128_BIT_BASE64}' 'strict-dynamic'",
        ("https://www.w3.org/TR/CSP3/#security-nonces",),
    ),
    # ---------------------------------------------------------------- HS-2xx
    # Framing, MIME sniffing, referrer, permissions
    _c(
        "HS-200",
        "No clickjacking protection",
        "framing",
        "x-frame-options",
        Severity.MEDIUM,
        "Neither X-Frame-Options nor CSP frame-ancestors was returned, so the page can be "
        "embedded in a hidden iframe and used for clickjacking against logged-in users.",
        "Send CSP frame-ancestors 'none' (modern) and X-Frame-Options: DENY (legacy "
        "clients) for pages that must never be framed.",
        "Content-Security-Policy: frame-ancestors 'none'\nX-Frame-Options: DENY",
        (f"{MDN}/X-Frame-Options",),
    ),
    _c(
        "HS-201",
        "Invalid X-Frame-Options value",
        "framing",
        "x-frame-options",
        Severity.MEDIUM,
        "Browsers ignore unrecognised X-Frame-Options values, so the page is effectively "
        "unprotected despite the header being present.",
        "Use exactly DENY or SAMEORIGIN.",
        "X-Frame-Options: DENY",
        (f"{MDN}/X-Frame-Options",),
    ),
    _c(
        "HS-202",
        "X-Frame-Options uses obsolete ALLOW-FROM",
        "framing",
        "x-frame-options",
        Severity.MEDIUM,
        "ALLOW-FROM was never implemented by Chrome/Safari and was removed from Firefox, so "
        "the directive provides no protection in current browsers.",
        "Replace it with CSP frame-ancestors listing the permitted embedding origins.",
        "Content-Security-Policy: frame-ancestors https://partner.example.com",
        (f"{MDN}/X-Frame-Options",),
    ),
    _c(
        "HS-203",
        "Clickjacking protection relies on the legacy header only",
        "framing",
        "x-frame-options",
        Severity.LOW,
        "X-Frame-Options is obsoleted by CSP frame-ancestors. Relying on it alone leaves "
        "gaps in browsers that have deprecated it.",
        "Add CSP frame-ancestors alongside the legacy header during the transition.",
        "Content-Security-Policy: frame-ancestors 'none'",
        (f"{MDN}/Content-Security-Policy/frame-ancestors",),
    ),
    _c(
        "HS-204",
        "X-Frame-Options and CSP frame-ancestors disagree",
        "framing",
        "x-frame-options",
        Severity.LOW,
        "When both are present, browsers that support CSP ignore X-Frame-Options. "
        "Conflicting values lead to inconsistent behaviour across clients.",
        "Align both headers, or drop X-Frame-Options once legacy clients are irrelevant.",
        None,
        (f"{MDN}/X-Frame-Options",),
    ),
    _c(
        "HS-210",
        "Missing X-Content-Type-Options",
        "content",
        "x-content-type-options",
        Severity.MEDIUM,
        "Without nosniff, browsers may MIME-sniff responses and execute a user-uploaded or "
        "text response as script or stylesheet.",
        "Send X-Content-Type-Options: nosniff on every response and make sure Content-Type "
        "values are correct.",
        "X-Content-Type-Options: nosniff",
        (f"{MDN}/X-Content-Type-Options",),
    ),
    _c(
        "HS-211",
        "Invalid X-Content-Type-Options value",
        "content",
        "x-content-type-options",
        Severity.LOW,
        "Only the literal token 'nosniff' is recognised; anything else is ignored and MIME "
        "sniffing stays enabled.",
        "Use exactly: X-Content-Type-Options: nosniff",
        "X-Content-Type-Options: nosniff",
        (f"{MDN}/X-Content-Type-Options",),
    ),
    _c(
        "HS-220",
        "Missing Referrer-Policy",
        "referrer",
        "referrer-policy",
        Severity.LOW,
        "Browser defaults vary. Full URLs — including path, query string, tokens and "
        "internal identifiers — can leak to third-party sites through the Referer header.",
        "Send Referrer-Policy: strict-origin-when-cross-origin (or no-referrer for the most "
        "privacy-sensitive applications).",
        "Referrer-Policy: strict-origin-when-cross-origin",
        (f"{MDN}/Referrer-Policy",),
    ),
    _c(
        "HS-221",
        "Weak Referrer-Policy value",
        "referrer",
        "referrer-policy",
        Severity.MEDIUM,
        "This policy sends full URLs (potentially including session identifiers, reset "
        "tokens or internal paths) to third parties, and some variants leak over plaintext "
        "downgrades.",
        "Switch to strict-origin-when-cross-origin, same-origin or no-referrer.",
        "Referrer-Policy: strict-origin-when-cross-origin",
        (f"{MDN}/Referrer-Policy",),
    ),
    _c(
        "HS-222",
        "Unknown Referrer-Policy token",
        "referrer",
        "referrer-policy",
        Severity.LOW,
        "Unrecognised tokens are ignored; if no valid token remains the browser falls back "
        "to its default policy.",
        "Use one of the eight standard tokens; a comma-separated list is allowed for "
        "progressive enhancement.",
        "Referrer-Policy: no-referrer, strict-origin-when-cross-origin",
        (f"{MDN}/Referrer-Policy",),
    ),
    _c(
        "HS-230",
        "Missing Permissions-Policy",
        "permissions",
        "permissions-policy",
        Severity.LOW,
        "Powerful browser features (camera, microphone, geolocation, payment) are left at "
        "their default availability for the page and for any embedded third-party frames.",
        "Send a deny-by-default Permissions-Policy and only enable what the app needs.",
        "Permissions-Policy: accelerometer=(), camera=(), geolocation=(), gyroscope=(), "
        "magnetometer=(), microphone=(), payment=(), usb=()",
        (f"{MDN}/Permissions-Policy",),
    ),
    _c(
        "HS-231",
        "Permissions-Policy grants a feature to all origins",
        "permissions",
        "permissions-policy",
        Severity.MEDIUM,
        "A wildcard allow-list lets any embedded third-party iframe use the feature, which "
        "is a privacy and phishing risk for sensitive capabilities.",
        "Replace * with () to deny, 'self' for first-party use, or an explicit origin list.",
        "Permissions-Policy: camera=(), microphone=(), geolocation=(self)",
        (f"{MDN}/Permissions-Policy",),
    ),
    _c(
        "HS-232",
        "Malformed Permissions-Policy value",
        "permissions",
        "permissions-policy",
        Severity.LOW,
        "Structured-header parse errors cause browsers to drop the whole directive (or the "
        "entire header), silently removing the restriction.",
        "Use the structured syntax: feature=(), feature=(self), feature=(self "
        '"https://trusted.example").',
        "Permissions-Policy: geolocation=(self), camera=()",
        ("https://www.w3.org/TR/permissions-policy-1/",),
    ),
    _c(
        "HS-233",
        "Sensitive browser features are not restricted",
        "permissions",
        "permissions-policy",
        Severity.LOW,
        "Camera, microphone, geolocation, payment and USB access are not explicitly denied, "
        "so availability depends on browser defaults and embedding context.",
        "Explicitly deny every feature the application does not use.",
        "Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()",
        (f"{MDN}/Permissions-Policy",),
    ),
    _c(
        "HS-234",
        "Deprecated Feature-Policy header in use",
        "deprecated",
        "feature-policy",
        Severity.INFO,
        "Feature-Policy has been renamed to Permissions-Policy; modern browsers ignore the "
        "old header and its syntax differs.",
        "Emit Permissions-Policy (structured syntax). Keep Feature-Policy only if you must "
        "support very old browsers.",
        "Permissions-Policy: camera=(), microphone=()",
        (f"{MDN}/Permissions-Policy",),
    ),
    # ---------------------------------------------------------------- HS-3xx
    # Cross-origin isolation + CORS
    _c(
        "HS-300",
        "Missing Cross-Origin-Opener-Policy",
        "cross-origin",
        "cross-origin-opener-policy",
        Severity.LOW,
        "Without COOP, a window opened by (or opening) this page keeps a cross-origin "
        "reference to it, enabling XS-Leaks and tab-nabbing style attacks.",
        "Send Cross-Origin-Opener-Policy: same-origin (use same-origin-allow-popups when "
        "OAuth popups are required).",
        "Cross-Origin-Opener-Policy: same-origin",
        (f"{MDN}/Cross-Origin-Opener-Policy",),
    ),
    _c(
        "HS-301",
        "COOP explicitly set to unsafe-none",
        "cross-origin",
        "cross-origin-opener-policy",
        Severity.LOW,
        "unsafe-none is the permissive default: the browsing context can be shared with "
        "cross-origin documents.",
        "Use same-origin unless a cross-origin popup integration genuinely requires "
        "window references.",
        "Cross-Origin-Opener-Policy: same-origin",
        (f"{MDN}/Cross-Origin-Opener-Policy",),
    ),
    _c(
        "HS-302",
        "Missing Cross-Origin-Resource-Policy",
        "cross-origin",
        "cross-origin-resource-policy",
        Severity.LOW,
        "CORP tells the browser who may embed this resource. Without it, responses can be "
        "pulled into cross-origin documents and abused for side-channel (Spectre-class) "
        "leaks.",
        "Send Cross-Origin-Resource-Policy: same-origin for private resources, same-site "
        "for shared internal assets, cross-origin only for public CDN content.",
        "Cross-Origin-Resource-Policy: same-origin",
        (f"{MDN}/Cross-Origin-Resource-Policy",),
    ),
    _c(
        "HS-303",
        "CORP set to cross-origin",
        "cross-origin",
        "cross-origin-resource-policy",
        Severity.INFO,
        "Any site may embed this resource. That is intended for public CDN assets but "
        "should not be used for authenticated or sensitive responses.",
        "Confirm this endpoint only serves public content; otherwise use same-origin or "
        "same-site.",
        "Cross-Origin-Resource-Policy: same-origin",
        (f"{MDN}/Cross-Origin-Resource-Policy",),
    ),
    _c(
        "HS-304",
        "Missing Cross-Origin-Embedder-Policy",
        "cross-origin",
        "cross-origin-embedder-policy",
        Severity.INFO,
        "Without COEP the document cannot become cross-origin isolated, so powerful APIs "
        "(SharedArrayBuffer, high-resolution timers) stay disabled and Spectre-class "
        "mitigations are weaker.",
        "Send Cross-Origin-Embedder-Policy: require-corp (or credentialless) together with "
        "COOP: same-origin when you need cross-origin isolation.",
        "Cross-Origin-Embedder-Policy: require-corp",
        (f"{MDN}/Cross-Origin-Embedder-Policy",),
    ),
    _c(
        "HS-305",
        "Cross-origin isolation is incomplete",
        "cross-origin",
        "cross-origin-embedder-policy",
        Severity.INFO,
        "COEP and COOP must both be set (require-corp/credentialless + same-origin) for "
        "crossOriginIsolated to become true; the current combination does not achieve it.",
        "Pair Cross-Origin-Embedder-Policy: require-corp with Cross-Origin-Opener-Policy: "
        "same-origin, and make sure sub-resources send CORP or CORS headers.",
        "Cross-Origin-Opener-Policy: same-origin\nCross-Origin-Embedder-Policy: require-corp",
        ("https://web.dev/articles/coop-coep",),
    ),
    _c(
        "HS-306",
        "Invalid cross-origin policy value",
        "cross-origin",
        None,
        Severity.LOW,
        "An unrecognised token makes the browser fall back to the permissive default, so "
        "the intended isolation is not applied.",
        "Use only the specified tokens for each header (see the recommendation column).",
        None,
        ("https://html.spec.whatwg.org/multipage/browsers.html",),
    ),
    _c(
        "HS-310",
        "CORS allows any origin",
        "cors",
        "access-control-allow-origin",
        Severity.MEDIUM,
        "Access-Control-Allow-Origin: * lets any website read this response. For public, "
        "non-sensitive APIs that is fine; for anything user-specific it is a data exposure.",
        "Return the specific allowed origin after validating it against an allow-list, and "
        "add Vary: Origin.",
        "Access-Control-Allow-Origin: https://app.example.com\nVary: Origin",
        (f"{MDN}/Access-Control-Allow-Origin",),
    ),
    _c(
        "HS-311",
        "CORS wildcard combined with credentials",
        "cors",
        "access-control-allow-origin",
        Severity.HIGH,
        "A wildcard origin together with Access-Control-Allow-Credentials: true is rejected "
        "by browsers but signals a misconfigured CORS layer; if the wildcard is ever "
        "replaced by origin reflection, any site could read authenticated responses.",
        "Never combine credentials with a wildcard. Echo one validated origin and keep the "
        "allow-list short.",
        "Access-Control-Allow-Origin: https://app.example.com\n"
        "Access-Control-Allow-Credentials: true\nVary: Origin",
        (f"{MDN}/Access-Control-Allow-Credentials",),
    ),
    _c(
        "HS-312",
        "CORS reflects an arbitrary origin with credentials",
        "cors",
        "access-control-allow-origin",
        Severity.HIGH,
        "The server echoed the probe origin back and allows credentials, so any attacker "
        "site can make authenticated cross-origin requests and read the responses — a "
        "direct account-data disclosure path.",
        "Validate Origin against a strict allow-list before echoing it, and only enable "
        "credentials for origins you control.",
        "Access-Control-Allow-Origin: https://app.example.com\n"
        "Access-Control-Allow-Credentials: true\nVary: Origin",
        ("https://portswigger.net/web-security/cors",),
    ),
    _c(
        "HS-313",
        "CORS reflects arbitrary origins",
        "cors",
        "access-control-allow-origin",
        Severity.MEDIUM,
        "The response echoed an unrelated probe origin. Without credentials the impact is "
        "limited, but it indicates missing origin validation and may expose data that is "
        "protected by network position (intranet, VPN).",
        "Compare Origin against an explicit allow-list and return a fixed value otherwise.",
        "Access-Control-Allow-Origin: https://app.example.com\nVary: Origin",
        ("https://portswigger.net/web-security/cors",),
    ),
    _c(
        "HS-314",
        "CORS allows the null origin",
        "cors",
        "access-control-allow-origin",
        Severity.HIGH,
        "'null' is sent by sandboxed iframes and local files, which an attacker can create "
        "at will — it is effectively a wildcard that also works with credentials.",
        "Never allow the null origin; require an explicit https origin.",
        "Access-Control-Allow-Origin: https://app.example.com",
        ("https://portswigger.net/web-security/cors",),
    ),
    _c(
        "HS-315",
        "Malformed Access-Control-Allow-Origin",
        "cors",
        "access-control-allow-origin",
        Severity.LOW,
        "The header must contain exactly one origin, or '*'. Multiple values make browsers "
        "reject the response, breaking legitimate clients and hinting at duplicated CORS "
        "logic.",
        "Emit a single origin value from one place in the stack.",
        "Access-Control-Allow-Origin: https://app.example.com",
        (f"{MDN}/Access-Control-Allow-Origin",),
    ),
    _c(
        "HS-316",
        "CORS allows unsafe methods broadly",
        "cors",
        "access-control-allow-methods",
        Severity.LOW,
        "Allowing every method (including wildcards or state-changing verbs) from other "
        "origins widens the CSRF/abuse surface of the API.",
        "List only the methods the endpoint actually implements.",
        "Access-Control-Allow-Methods: GET, POST, OPTIONS",
        (f"{MDN}/Access-Control-Allow-Methods",),
    ),
    _c(
        "HS-317",
        "CORS allows arbitrary request headers",
        "cors",
        "access-control-allow-headers",
        Severity.LOW,
        "A wildcard header allow-list lets cross-origin callers send custom headers such as "
        "Authorization or X-Requested-With, which some backends treat as trusted.",
        "Enumerate the accepted headers explicitly.",
        "Access-Control-Allow-Headers: Content-Type, Authorization",
        (f"{MDN}/Access-Control-Allow-Headers",),
    ),
    _c(
        "HS-318",
        "Dynamic CORS response is missing Vary: Origin",
        "cors",
        "vary",
        Severity.LOW,
        "When the allowed origin depends on the request but Vary: Origin is absent, shared "
        "caches and CDNs can serve one origin's CORS headers to another origin.",
        "Add Vary: Origin to every response whose CORS headers depend on the request origin.",
        "Vary: Origin",
        (f"{MDN}/Vary",),
    ),
    _c(
        "HS-319",
        "CORS exposes additional response headers",
        "cors",
        "access-control-expose-headers",
        Severity.INFO,
        "Exposed headers become readable by cross-origin scripts; wildcards may reveal "
        "internal or sensitive metadata.",
        "Expose only the headers clients genuinely need.",
        "Access-Control-Expose-Headers: Content-Length, X-Request-Id",
        (f"{MDN}/Access-Control-Expose-Headers",),
    ),
    # ---------------------------------------------------------------- HS-4xx
    # Cookies
    _c(
        "HS-400",
        "Cookie without Secure attribute",
        "cookies",
        "set-cookie",
        Severity.HIGH,
        "The cookie can be transmitted over plaintext HTTP, so an on-path attacker or a "
        "single mixed-content request can capture it.",
        "Add the Secure attribute to every cookie and serve the site exclusively over HTTPS.",
        "Set-Cookie: session=...; Secure; HttpOnly; SameSite=Lax; Path=/",
        (f"{MDN}/Set-Cookie",),
    ),
    _c(
        "HS-401",
        "Cookie without HttpOnly attribute",
        "cookies",
        "set-cookie",
        Severity.MEDIUM,
        "JavaScript can read this cookie, so a single XSS flaw turns into full session "
        "theft.",
        "Add HttpOnly to all cookies that do not need to be read by client-side scripts.",
        "Set-Cookie: session=...; Secure; HttpOnly; SameSite=Lax; Path=/",
        (f"{MDN}/Set-Cookie",),
    ),
    _c(
        "HS-402",
        "Cookie without SameSite attribute",
        "cookies",
        "set-cookie",
        Severity.LOW,
        "Cross-site requests may carry this cookie depending on the browser's default, "
        "which keeps classic CSRF viable on older clients.",
        "Set SameSite=Lax (or Strict for sensitive session cookies) explicitly.",
        "Set-Cookie: session=...; Secure; HttpOnly; SameSite=Lax",
        (f"{MDN}/Set-Cookie/SameSite",),
    ),
    _c(
        "HS-403",
        "SameSite=None cookie without Secure",
        "cookies",
        "set-cookie",
        Severity.HIGH,
        "SameSite=None requires Secure. Browsers reject the cookie, and if it is accepted "
        "anywhere it is sent cross-site over plaintext connections.",
        "Always pair SameSite=None with Secure, and question whether cross-site delivery is "
        "really needed.",
        "Set-Cookie: session=...; Secure; HttpOnly; SameSite=None",
        (f"{MDN}/Set-Cookie/SameSite",),
    ),
    _c(
        "HS-404",
        "Cookie scoped to a broad parent domain",
        "cookies",
        "set-cookie",
        Severity.LOW,
        "A cookie scoped to the registrable domain is sent to every subdomain, so a "
        "compromised or attacker-controlled subdomain can read or overwrite it.",
        "Drop the Domain attribute to make the cookie host-only, or use the __Host- prefix.",
        "Set-Cookie: __Host-session=...; Secure; HttpOnly; SameSite=Lax; Path=/",
        ("https://www.rfc-editor.org/rfc/rfc6265",),
    ),
    _c(
        "HS-405",
        "Cookie prefix requirements not met",
        "cookies",
        "set-cookie",
        Severity.MEDIUM,
        "__Secure-/__Host- prefixed cookies that do not satisfy their attribute rules are "
        "rejected by browsers, so the session may silently fail or fall back to a weaker "
        "cookie.",
        "__Secure- requires Secure; __Host- requires Secure, Path=/ and no Domain.",
        "Set-Cookie: __Host-session=...; Secure; HttpOnly; SameSite=Lax; Path=/",
        ("https://www.rfc-editor.org/rfc/rfc6265bis",),
    ),
    _c(
        "HS-406",
        "Long-lived persistent cookie",
        "cookies",
        "set-cookie",
        Severity.INFO,
        "Very long lifetimes extend the window in which a stolen cookie remains valid.",
        "Prefer short-lived session cookies with server-side revocation for authentication "
        "state.",
        None,
        (f"{MDN}/Set-Cookie",),
    ),
    _c(
        "HS-407",
        "Cookie set over plaintext HTTP",
        "cookies",
        "set-cookie",
        Severity.HIGH,
        "The cookie was delivered over an unencrypted channel and can be read by anyone on "
        "the path, regardless of its attributes.",
        "Serve the application over HTTPS only and set cookies from HTTPS responses.",
        "Set-Cookie: session=...; Secure; HttpOnly; SameSite=Lax",
        (f"{MDN}/Set-Cookie",),
    ),
    # ---------------------------------------------------------------- HS-5xx
    # Information disclosure + deprecated headers
    _c(
        "HS-500",
        "Server software version disclosed",
        "disclosure",
        "server",
        Severity.LOW,
        "Exact software versions let an attacker map the target to known CVEs without "
        "touching the application, speeding up reconnaissance.",
        "Suppress or genericise the Server banner (nginx: server_tokens off; Apache: "
        "ServerTokens Prod).",
        "Server: nginx",
        (OWASP,),
    ),
    _c(
        "HS-501",
        "Technology disclosed via X-Powered-By",
        "disclosure",
        "x-powered-by",
        Severity.LOW,
        "The header advertises the application stack and often its exact version, which is "
        "pure reconnaissance value for an attacker.",
        "Remove the header (PHP: expose_php=Off; Express: app.disable('x-powered-by')).",
        None,
        (OWASP,),
    ),
    _c(
        "HS-502",
        "Framework version headers exposed",
        "disclosure",
        None,
        Severity.LOW,
        "ASP.NET/MVC version headers identify the exact framework build in use.",
        "Remove them via <httpRuntime enableVersionHeader=\"false\" /> and "
        "MvcHandler.DisableMvcResponseHeader = true.",
        None,
        (OWASP,),
    ),
    _c(
        "HS-503",
        "Infrastructure details disclosed",
        "disclosure",
        None,
        Severity.INFO,
        "Headers such as Via, X-Backend-Server or X-Served-By reveal internal hostnames and "
        "proxy topology that help an attacker map the environment.",
        "Strip internal routing headers at the edge before responses leave the perimeter.",
        None,
        (OWASP,),
    ),
    _c(
        "HS-504",
        "Generator / CMS disclosed",
        "disclosure",
        "x-generator",
        Severity.INFO,
        "Identifying the CMS and version narrows down which plugin vulnerabilities to try.",
        "Disable generator headers/meta tags in the CMS configuration.",
        None,
        (OWASP,),
    ),
    _c(
        "HS-510",
        "Deprecated X-XSS-Protection header present",
        "deprecated",
        "x-xss-protection",
        Severity.INFO,
        "The XSS Auditor has been removed from all modern browsers; the header does nothing "
        "today and can give a false sense of protection.",
        "Remove the header (or keep the explicit 0 value) and rely on CSP plus contextual "
        "output encoding.",
        "X-XSS-Protection: 0",
        (f"{MDN}/X-XSS-Protection",),
    ),
    _c(
        "HS-511",
        "X-XSS-Protection filtering enabled",
        "deprecated",
        "x-xss-protection",
        Severity.LOW,
        "Value '1' without mode=block enables legacy filtering that was itself exploitable "
        "for XS-leaks and content injection in older browsers.",
        "Set X-XSS-Protection: 0 and deploy a CSP instead.",
        "X-XSS-Protection: 0",
        (f"{MDN}/X-XSS-Protection",),
    ),
    _c(
        "HS-512",
        "Deprecated Expect-CT header present",
        "deprecated",
        "expect-ct",
        Severity.INFO,
        "Certificate Transparency is now enforced by browsers automatically; Expect-CT is "
        "obsolete and ignored.",
        "Remove the header.",
        None,
        (f"{MDN}/Expect-CT",),
    ),
    _c(
        "HS-513",
        "Obsolete Public-Key-Pins header present",
        "deprecated",
        "public-key-pins",
        Severity.MEDIUM,
        "HPKP is removed from all browsers and is a well known foot-gun: a wrong pin can "
        "make the site unreachable for the pin's lifetime (ransom/bricking risk).",
        "Remove Public-Key-Pins entirely; use Certificate Transparency monitoring and CAA "
        "records instead.",
        None,
        (f"{MDN}/Public-Key-Pins",),
    ),
    _c(
        "HS-514",
        "Legacy Pragma header present",
        "deprecated",
        "pragma",
        Severity.INFO,
        "Pragma: no-cache is an HTTP/1.0 relic. It is harmless but indicates cache policy "
        "may not have been reviewed for modern clients.",
        "Rely on Cache-Control; keep Pragma only if HTTP/1.0 intermediaries still matter.",
        "Cache-Control: no-store",
        (f"{MDN}/Pragma",),
    ),
    _c(
        "HS-515",
        "Permissive X-Permitted-Cross-Domain-Policies",
        "disclosure",
        "x-permitted-cross-domain-policies",
        Severity.LOW,
        "Allowing cross-domain policy files lets legacy Adobe clients (Flash/Acrobat) read "
        "data from this origin.",
        "Set X-Permitted-Cross-Domain-Policies: none unless a legacy client requires "
        "otherwise.",
        "X-Permitted-Cross-Domain-Policies: none",
        (OWASP,),
    ),
    _c(
        "HS-516",
        "Missing X-Permitted-Cross-Domain-Policies",
        "disclosure",
        "x-permitted-cross-domain-policies",
        Severity.INFO,
        "Legacy Adobe clients fall back to looking for a /crossdomain.xml policy file.",
        "Send X-Permitted-Cross-Domain-Policies: none (defence in depth, zero cost).",
        "X-Permitted-Cross-Domain-Policies: none",
        (OWASP,),
    ),
    # ---------------------------------------------------------------- HS-6xx
    # Caching
    _c(
        "HS-600",
        "No Cache-Control header",
        "caching",
        "cache-control",
        Severity.INFO,
        "Without an explicit policy, heuristic caching by browsers and shared proxies "
        "decides how long the response is stored.",
        "Set an explicit policy: no-store for authenticated pages, immutable long max-age "
        "for fingerprinted static assets.",
        "Cache-Control: no-store",
        (f"{MDN}/Cache-Control",),
    ),
    _c(
        "HS-601",
        "Potentially sensitive response is cacheable",
        "caching",
        "cache-control",
        Severity.LOW,
        "The response sets cookies or looks user-specific, yet allows shared/public "
        "caching, which can leak one user's content to another via a proxy or CDN.",
        "Send Cache-Control: no-store (plus private where appropriate) for user-specific "
        "responses.",
        "Cache-Control: no-store, private",
        (f"{MDN}/Cache-Control",),
    ),
    _c(
        "HS-602",
        "Clear-Site-Data in use",
        "caching",
        "clear-site-data",
        Severity.INFO,
        "Clear-Site-Data wipes browser state. It is a good logout control, but on a normal "
        "page it can destroy data unexpectedly.",
        "Scope Clear-Site-Data to logout/account-deletion responses only.",
        'Clear-Site-Data: "cache", "cookies", "storage"',
        (f"{MDN}/Clear-Site-Data",),
    ),
    # ---------------------------------------------------------------- HS-7xx
    # Redirects / response
    _c(
        "HS-700",
        "Redirect downgrades HTTPS to HTTP",
        "redirects",
        None,
        Severity.HIGH,
        "A hop in the redirect chain moves from HTTPS to plaintext HTTP, exposing the "
        "request (and any cookies attached to it) on the wire.",
        "Keep every hop on HTTPS; fix absolute http:// URLs in redirect targets.",
        None,
        (OWASP,),
    ),
    _c(
        "HS-701",
        "Long redirect chain",
        "redirects",
        None,
        Severity.LOW,
        "Long chains slow down clients, complicate security review and often hide a "
        "downgrade or a cross-host hop in the middle.",
        "Collapse the chain to at most one or two hops.",
        None,
        (),
    ),
    _c(
        "HS-702",
        "Redirect crosses to a different host",
        "redirects",
        None,
        Severity.INFO,
        "The target redirects to another host. That is normal for www/apex or CDN setups, "
        "but worth confirming that the destination is expected.",
        "Verify the destination is owned by you and uses HTTPS.",
        None,
        (),
    ),
    _c(
        "HS-703",
        "Non-success final status code",
        "response",
        None,
        Severity.INFO,
        "The scan finished on a non-2xx response, so the analysed headers may belong to an "
        "error page rather than the real application.",
        "Re-scan an authenticated or valid application path for representative results.",
        None,
        (),
    ),
    _c(
        "HS-704",
        "Server error response",
        "response",
        None,
        Severity.LOW,
        "The endpoint returned a 5xx error. Error pages often leak stack traces and rarely "
        "carry the application's normal security headers.",
        "Investigate the failure and ensure error responses keep the same security headers.",
        None,
        (),
    ),
    # ---------------------------------------------------------------- HS-9xx
    # Custom policy violations
    _c(
        "HS-900",
        "Policy: required header missing",
        "policy",
        None,
        Severity.HIGH,
        "A header mandated by the organisation's header policy was not present on the "
        "response, so the target does not meet the internal baseline.",
        "Add the header at the application or edge layer so the target satisfies the "
        "policy.",
        None,
        (),
    ),
    _c(
        "HS-901",
        "Policy: forbidden header present",
        "policy",
        None,
        Severity.MEDIUM,
        "A header explicitly banned by the organisation's policy was returned.",
        "Strip the header at the application or reverse-proxy layer.",
        None,
        (),
    ),
    _c(
        "HS-902",
        "Policy: header value does not match",
        "policy",
        None,
        Severity.MEDIUM,
        "The header value differs from the value(s) the policy allows, so the deployed "
        "configuration drifted from the approved baseline.",
        "Align the header value with the approved policy value.",
        None,
        (),
    ),
)

#: Registry of all checks keyed by finding id.
CHECKS: dict[str, CheckDefinition] = {check.id: check for check in _CHECK_LIST}


def make_finding(
    check_id: str,
    *,
    reason: str,
    value: str | None = None,
    severity: Severity | str | None = None,
    header: str | None = None,
    title: str | None = None,
    impact: str | None = None,
    recommendation: str | None = None,
    remediation: str | None = None,
    metadata: Mapping[str, Any] | None = None,
) -> Finding:
    """Instantiate a :class:`Finding` from the catalogue.

    ``reason`` is the instance-specific explanation ("max-age is 600 seconds");
    everything else defaults to the catalogue entry but can be overridden (for
    example to raise severity when the target is served over HTTPS).
    """
    check = CHECKS.get(check_id)
    if check is None:  # pragma: no cover - guards against typos in analyzers
        raise KeyError(f"Unknown check id: {check_id}")
    resolved_severity = (
        Severity.parse(severity, check.severity) if severity is not None else check.severity
    )
    return Finding(
        id=check.id,
        title=title or check.title,
        severity=resolved_severity,
        category=check.category,
        reason=reason,
        impact=impact or check.impact,
        recommendation=recommendation or check.recommendation,
        header=header if header is not None else check.header,
        value=value,
        remediation=remediation if remediation is not None else check.remediation,
        references=list(check.references),
        metadata=dict(metadata or {}),
    )


def sort_findings(findings: Iterable[Finding]) -> list[Finding]:
    """Sort findings by severity, then by check id, then by header."""
    return sorted(findings, key=lambda f: (f.severity.rank, f.id, (f.header or ""), f.value or ""))


def severity_counts(findings: Iterable[Finding]) -> dict[str, int]:
    """Count findings per severity (always includes every level)."""
    counts = {severity.value: 0 for severity in SEVERITY_ORDER}
    for finding in findings:
        counts[finding.severity.value] = counts.get(finding.severity.value, 0) + 1
    return counts


# --------------------------------------------------------------------------- #
# Remediation snippets for common deployment stacks
# --------------------------------------------------------------------------- #
def server_config_examples(header: str, value: str) -> dict[str, str]:
    """Return copy-paste remediation templates for the major stacks.

    The snippets are intentionally generic: always review them against the
    application's own resource requirements before deploying.
    """
    escaped = value.replace('"', '\\"')
    return {
        "Nginx": f'add_header {header} "{escaped}" always;',
        "Apache": f'Header always set {header} "{escaped}"',
        "Cloudflare / Reverse proxy": (
            "Transform Rules → Modify Response Header → Set static:\n"
            f"  {header}: {value}"
        ),
        "Express / Node.js": f'app.use((req, res, next) => {{ res.setHeader("{header}", "{escaped}"); next(); }});',
        "Generic HTTP response": f"{header}: {value}",
    }
