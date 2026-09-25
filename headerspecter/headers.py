"""Header registry, container and per-header analyzers.

Covers HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy,
Permissions-Policy, cross-origin isolation, caching, information disclosure and
deprecated headers.

Each analyzer is a pure function over already-captured data, which makes the
whole analysis layer testable without network access.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from .findings import Finding, Severity, make_finding

__all__ = [
    "HeaderSpec",
    "SECURITY_HEADERS",
    "DISCLOSURE_HEADERS",
    "HeaderBag",
    "HeaderCheck",
    "AnalysisContext",
    "normalize_header_name",
    "analyze_hsts",
    "analyze_frame_options",
    "analyze_content_type_options",
    "analyze_referrer_policy",
    "analyze_permissions_policy",
    "analyze_cross_origin",
    "analyze_disclosure",
    "analyze_caching",
    "analyze_deprecated",
    "HSTSAnalysis",
    "PermissionsPolicyAnalysis",
    "CrossOriginAnalysis",
    "DisclosureItem",
]


# --------------------------------------------------------------------------- #
# Registry
# --------------------------------------------------------------------------- #
@dataclass(slots=True, frozen=True)
class HeaderSpec:
    """Metadata about one HTTP header HeaderSpecter knows about."""

    name: str
    category: str
    summary: str
    recommended: str | None = None
    deprecated: bool = False
    legacy: bool = False
    core: bool = False
    docs: str = ""

    @property
    def key(self) -> str:
        """Lowercase lookup key."""
        return self.name.lower()

    @property
    def status_note(self) -> str:
        """``DEPRECATED`` / ``LEGACY`` marker used by the reporters."""
        if self.deprecated:
            return "DEPRECATED"
        if self.legacy:
            return "LEGACY"
        return ""


_MDN = "https://developer.mozilla.org/docs/Web/HTTP/Headers"

_HEADER_SPECS: tuple[HeaderSpec, ...] = (
    # ---- core security headers -------------------------------------------
    HeaderSpec(
        "Content-Security-Policy",
        "csp",
        "Controls which resources the browser may load and execute.",
        "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
        core=True,
        docs=f"{_MDN}/Content-Security-Policy",
    ),
    HeaderSpec(
        "Strict-Transport-Security",
        "transport",
        "Forces the browser to use HTTPS for future requests.",
        "max-age=31536000; includeSubDomains",
        core=True,
        docs=f"{_MDN}/Strict-Transport-Security",
    ),
    HeaderSpec(
        "X-Content-Type-Options",
        "content",
        "Disables MIME type sniffing.",
        "nosniff",
        core=True,
        docs=f"{_MDN}/X-Content-Type-Options",
    ),
    HeaderSpec(
        "X-Frame-Options",
        "framing",
        "Legacy clickjacking control, superseded by CSP frame-ancestors.",
        "DENY",
        legacy=True,
        core=True,
        docs=f"{_MDN}/X-Frame-Options",
    ),
    HeaderSpec(
        "Referrer-Policy",
        "referrer",
        "Controls how much referrer information is sent with requests.",
        "strict-origin-when-cross-origin",
        core=True,
        docs=f"{_MDN}/Referrer-Policy",
    ),
    HeaderSpec(
        "Permissions-Policy",
        "permissions",
        "Enables or denies powerful browser features per origin.",
        "camera=(), microphone=(), geolocation=(), payment=()",
        core=True,
        docs=f"{_MDN}/Permissions-Policy",
    ),
    HeaderSpec(
        "Cross-Origin-Opener-Policy",
        "cross-origin",
        "Isolates the browsing context from cross-origin windows.",
        "same-origin",
        core=True,
        docs=f"{_MDN}/Cross-Origin-Opener-Policy",
    ),
    HeaderSpec(
        "Cross-Origin-Resource-Policy",
        "cross-origin",
        "Declares who may embed this resource.",
        "same-origin",
        core=True,
        docs=f"{_MDN}/Cross-Origin-Resource-Policy",
    ),
    HeaderSpec(
        "Cross-Origin-Embedder-Policy",
        "cross-origin",
        "Required for cross-origin isolation of the document.",
        "require-corp",
        core=True,
        docs=f"{_MDN}/Cross-Origin-Embedder-Policy",
    ),
    # ---- additional / legacy ---------------------------------------------
    HeaderSpec(
        "Content-Security-Policy-Report-Only",
        "csp",
        "Reports CSP violations without enforcing the policy.",
        None,
        docs=f"{_MDN}/Content-Security-Policy-Report-Only",
    ),
    HeaderSpec(
        "X-XSS-Protection",
        "deprecated",
        "Legacy browser XSS auditor; removed from modern browsers.",
        "0",
        deprecated=True,
        docs=f"{_MDN}/X-XSS-Protection",
    ),
    HeaderSpec(
        "X-Permitted-Cross-Domain-Policies",
        "disclosure",
        "Restricts legacy Adobe cross-domain policy files.",
        "none",
        legacy=True,
        docs="https://owasp.org/www-project-secure-headers/",
    ),
    HeaderSpec(
        "Clear-Site-Data",
        "caching",
        "Clears browsing data associated with the origin.",
        '"cache", "cookies", "storage"',
        docs=f"{_MDN}/Clear-Site-Data",
    ),
    HeaderSpec(
        "Cache-Control",
        "caching",
        "Directives for browser and shared caches.",
        "no-store",
        docs=f"{_MDN}/Cache-Control",
    ),
    HeaderSpec(
        "Pragma",
        "deprecated",
        "HTTP/1.0 cache directive kept for backwards compatibility.",
        None,
        legacy=True,
        docs=f"{_MDN}/Pragma",
    ),
    HeaderSpec(
        "Expect-CT",
        "deprecated",
        "Certificate Transparency enforcement; obsolete.",
        None,
        deprecated=True,
        docs=f"{_MDN}/Expect-CT",
    ),
    HeaderSpec(
        "Public-Key-Pins",
        "deprecated",
        "HTTP Public Key Pinning; removed from browsers, high foot-gun risk.",
        None,
        deprecated=True,
        docs=f"{_MDN}/Public-Key-Pins",
    ),
    HeaderSpec(
        "Feature-Policy",
        "deprecated",
        "Predecessor of Permissions-Policy.",
        None,
        deprecated=True,
        docs=f"{_MDN}/Feature-Policy",
    ),
    HeaderSpec(
        "Access-Control-Allow-Origin",
        "cors",
        "Which origins may read the response cross-origin.",
        None,
        docs=f"{_MDN}/Access-Control-Allow-Origin",
    ),
    HeaderSpec(
        "Access-Control-Allow-Credentials",
        "cors",
        "Whether cross-origin requests may carry credentials.",
        None,
        docs=f"{_MDN}/Access-Control-Allow-Credentials",
    ),
    HeaderSpec(
        "Access-Control-Allow-Methods",
        "cors",
        "Methods allowed for cross-origin requests.",
        None,
        docs=f"{_MDN}/Access-Control-Allow-Methods",
    ),
    HeaderSpec(
        "Access-Control-Allow-Headers",
        "cors",
        "Request headers allowed for cross-origin requests.",
        None,
        docs=f"{_MDN}/Access-Control-Allow-Headers",
    ),
    HeaderSpec(
        "Access-Control-Expose-Headers",
        "cors",
        "Response headers exposed to cross-origin scripts.",
        None,
        docs=f"{_MDN}/Access-Control-Expose-Headers",
    ),
    HeaderSpec(
        "Set-Cookie",
        "cookies",
        "Cookies set by the response.",
        None,
        docs=f"{_MDN}/Set-Cookie",
    ),
)

#: All known headers keyed by lowercase name.
SECURITY_HEADERS: dict[str, HeaderSpec] = {spec.key: spec for spec in _HEADER_SPECS}

#: Headers that are analysed as part of the "HEADER SECURITY" summary table.
CORE_HEADER_ORDER: tuple[str, ...] = (
    "content-security-policy",
    "strict-transport-security",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-opener-policy",
    "cross-origin-resource-policy",
    "cross-origin-embedder-policy",
)

#: Headers that disclose technology/infrastructure details.
DISCLOSURE_HEADERS: dict[str, str] = {
    "server": "Web server software",
    "x-powered-by": "Application stack",
    "x-aspnet-version": "ASP.NET runtime version",
    "x-aspnetmvc-version": "ASP.NET MVC version",
    "via": "Proxy / CDN chain",
    "x-generator": "Site generator / CMS",
    "x-backend-server": "Internal backend hostname",
    "x-served-by": "Cache/edge node identity",
    "x-drupal-cache": "Drupal cache layer",
    "x-varnish": "Varnish cache identity",
    "x-runtime": "Application runtime timing",
    "x-application-context": "Spring Boot application context",
}

#: Canonical spellings for headers whose title-casing is unusual.
_CANONICAL_OVERRIDES: dict[str, str] = {
    "x-xss-protection": "X-XSS-Protection",
    "content-md5": "Content-MD5",
    "dnt": "DNT",
    "etag": "ETag",
    "te": "TE",
    "www-authenticate": "WWW-Authenticate",
    "x-ua-compatible": "X-UA-Compatible",
    "nel": "NEL",
    "x-dns-prefetch-control": "X-DNS-Prefetch-Control",
    "alt-svc": "Alt-Svc",
    "x-aspnet-version": "X-AspNet-Version",
    "x-aspnetmvc-version": "X-AspNetMvc-Version",
}


def normalize_header_name(name: str) -> str:
    """Return the canonical spelling of ``name``.

    >>> normalize_header_name("strict-transport-security")
    'Strict-Transport-Security'
    >>> normalize_header_name("X-XSS-PROTECTION")
    'X-XSS-Protection'
    """
    key = name.strip().lower()
    if key in SECURITY_HEADERS:
        return SECURITY_HEADERS[key].name
    if key in _CANONICAL_OVERRIDES:
        return _CANONICAL_OVERRIDES[key]
    return "-".join(part.capitalize() if part else part for part in key.split("-"))


# --------------------------------------------------------------------------- #
# Header container
# --------------------------------------------------------------------------- #
class HeaderBag:
    """Case-insensitive, order preserving, multi-value header container."""

    __slots__ = ("_pairs", "_index")

    def __init__(self, pairs: Iterable[tuple[str, str]] | Mapping[str, str] | None = None) -> None:
        """Build a bag from header pairs or a mapping."""
        if pairs is None:
            items: list[tuple[str, str]] = []
        elif isinstance(pairs, Mapping):
            items = [(str(k), str(v)) for k, v in pairs.items()]
        else:
            items = [(str(k), str(v)) for k, v in pairs]
        self._pairs: list[tuple[str, str]] = items
        self._index: dict[str, list[str]] = {}
        for name, value in items:
            self._index.setdefault(name.strip().lower(), []).append(value.strip())

    # -- construction ------------------------------------------------------
    @classmethod
    def from_httpx(cls, headers: Any) -> HeaderBag:
        """Build a bag from an ``httpx.Headers`` instance (multi-value safe)."""
        return cls([(name, value) for name, value in headers.multi_items()])

    # -- access ------------------------------------------------------------
    def get(self, name: str, default: str | None = None) -> str | None:
        """Return the (first) value for ``name``."""
        values = self._index.get(name.strip().lower())
        if not values:
            return default
        return values[0]

    def get_all(self, name: str) -> list[str]:
        """Return every value sent for ``name``."""
        return list(self._index.get(name.strip().lower(), []))

    def joined(self, name: str, separator: str = ", ") -> str | None:
        """Return all values for ``name`` joined into one string."""
        values = self.get_all(name)
        if not values:
            return None
        return separator.join(values)

    def has(self, name: str) -> bool:
        """True when the header was returned at least once."""
        return bool(self._index.get(name.strip().lower()))

    def count(self, name: str) -> int:
        """How many times the header appeared."""
        return len(self._index.get(name.strip().lower(), []))

    def names(self) -> list[str]:
        """Canonical names of all received headers, in order."""
        seen: set[str] = set()
        result: list[str] = []
        for name, _ in self._pairs:
            key = name.lower()
            if key not in seen:
                seen.add(key)
                result.append(normalize_header_name(name))
        return result

    def items(self) -> list[tuple[str, str]]:
        """All header pairs as received (original casing)."""
        return list(self._pairs)

    def normalized_items(self) -> list[tuple[str, str]]:
        """All header pairs with canonical names."""
        return [(normalize_header_name(name), value) for name, value in self._pairs]

    def as_dict(self) -> dict[str, str]:
        """Lowercase name -> comma joined value mapping."""
        return {key: ", ".join(values) for key, values in self._index.items()}

    def raw_text(self) -> str:
        """Re-render the headers exactly as name/value lines."""
        return "\n".join(f"{name}: {value}" for name, value in self._pairs)

    def __contains__(self, name: object) -> bool:
        """Support ``"content-type" in bag``."""
        return isinstance(name, str) and self.has(name)

    def __len__(self) -> int:
        """Number of header lines received."""
        return len(self._pairs)

    def __iter__(self):
        """Iterate over ``(name, value)`` pairs in wire order."""
        return iter(self._pairs)

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        """Short debug representation."""
        return f"HeaderBag({len(self._pairs)} headers)"


# --------------------------------------------------------------------------- #
# Shared analysis types
# --------------------------------------------------------------------------- #
@dataclass(slots=True)
class HeaderCheck:
    """One row of the "HEADER SECURITY" summary table."""

    header: str
    status: Severity
    state: str
    value: str | None = None
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        """JSON-serialisable representation."""
        return {
            "header": self.header,
            "status": self.status.value,
            "state": self.state,
            "value": self.value,
            "note": self.note,
        }


@dataclass(slots=True)
class AnalysisContext:
    """Facts about the scanned response that analyzers need for decisions."""

    url: str
    final_url: str
    host: str
    is_https: bool
    status_code: int | None = None
    scheme_upgraded: bool = False
    probe_origin: str = ""
    content_type: str = ""

    @property
    def scheme(self) -> str:
        """``HTTPS`` or ``HTTP``."""
        return "HTTPS" if self.is_https else "HTTP"


@dataclass(slots=True)
class HSTSAnalysis:
    """Result of the Strict-Transport-Security analysis."""

    present: bool = False
    raw: str | None = None
    max_age: int | None = None
    include_subdomains: bool = False
    preload: bool = False
    valid: bool = True
    rows: list[tuple[str, Severity, str]] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    check: HeaderCheck | None = None

    def to_dict(self) -> dict[str, Any]:
        """JSON-serialisable representation."""
        return {
            "present": self.present,
            "raw": self.raw,
            "max_age": self.max_age,
            "include_subdomains": self.include_subdomains,
            "preload": self.preload,
            "valid": self.valid,
            "rows": [{"label": label, "status": status.value, "detail": detail} for label, status, detail in self.rows],
        }


@dataclass(slots=True)
class PermissionsPolicyAnalysis:
    """Result of the Permissions-Policy analysis."""

    present: bool = False
    raw: str | None = None
    directives: dict[str, list[str]] = field(default_factory=dict)
    unrestricted: list[str] = field(default_factory=list)
    restricted: list[str] = field(default_factory=list)
    malformed: list[str] = field(default_factory=list)
    rows: list[tuple[str, Severity, str]] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    check: HeaderCheck | None = None

    def to_dict(self) -> dict[str, Any]:
        """JSON-serialisable representation."""
        return {
            "present": self.present,
            "raw": self.raw,
            "directives": {k: list(v) for k, v in self.directives.items()},
            "unrestricted": list(self.unrestricted),
            "restricted": list(self.restricted),
            "malformed": list(self.malformed),
        }


@dataclass(slots=True)
class CrossOriginAnalysis:
    """COOP / CORP / COEP posture."""

    coop: str | None = None
    corp: str | None = None
    coep: str | None = None
    cross_origin_isolated: bool = False
    rows: list[tuple[str, Severity, str]] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    checks: list[HeaderCheck] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """JSON-serialisable representation."""
        return {
            "coop": self.coop,
            "corp": self.corp,
            "coep": self.coep,
            "cross_origin_isolated": self.cross_origin_isolated,
        }


@dataclass(slots=True)
class DisclosureItem:
    """One information-disclosure observation."""

    header: str
    value: str
    severity: Severity
    note: str

    def to_dict(self) -> dict[str, Any]:
        """JSON-serialisable representation."""
        return {
            "header": self.header,
            "value": self.value,
            "severity": self.severity.value,
            "note": self.note,
        }


# --------------------------------------------------------------------------- #
# Strict-Transport-Security
# --------------------------------------------------------------------------- #
_ONE_YEAR = 31_536_000
_SIX_MONTHS = 15_552_000
_MAX_AGE_RE = re.compile(r"^max-age\s*=\s*\"?(\d+)\"?$", re.IGNORECASE)


def analyze_hsts(bag: HeaderBag, ctx: AnalysisContext) -> HSTSAnalysis:
    """Analyse Strict-Transport-Security (max-age, includeSubDomains, preload)."""
    analysis = HSTSAnalysis()
    raw = bag.get("strict-transport-security")
    analysis.raw = raw

    if raw is None:
        analysis.present = False
        analysis.rows.append(("Header present", Severity.HIGH if ctx.is_https else Severity.INFO, "not returned"))
        if ctx.is_https:
            analysis.findings.append(
                make_finding(
                    "HS-001",
                    reason="No Strict-Transport-Security header was returned on an HTTPS response.",
                )
            )
        # For plaintext targets the missing policy is implied by HS-007, which
        # the orchestrator raises once per target.
        analysis.check = HeaderCheck(
            "Strict-Transport-Security",
            Severity.HIGH if ctx.is_https else Severity.INFO,
            "MISSING",
            None,
            "No HTTPS enforcement policy" if ctx.is_https else "Not applicable over plaintext HTTP",
        )
        return analysis

    analysis.present = True
    tokens = [token.strip() for token in raw.split(";") if token.strip()]
    unknown: list[str] = []
    for token in tokens:
        match = _MAX_AGE_RE.match(token)
        if match:
            try:
                analysis.max_age = int(match.group(1))
            except ValueError:  # pragma: no cover - regex guarantees digits
                analysis.valid = False
            continue
        lowered = token.lower()
        if lowered == "includesubdomains":
            analysis.include_subdomains = True
        elif lowered == "preload":
            analysis.preload = True
        else:
            unknown.append(token)

    if analysis.max_age is None or unknown:
        analysis.valid = False

    analysis.rows.append(("Header present", Severity.PASS, raw))

    if not ctx.is_https:
        analysis.rows.append(("Applied by browsers", Severity.INFO, "ignored over plaintext HTTP"))
        analysis.findings.append(
            make_finding(
                "HS-006",
                reason="The HSTS header was returned over HTTP, where browsers ignore it.",
                value=raw,
            )
        )

    if analysis.max_age is None:
        analysis.rows.append(("max-age", Severity.MEDIUM, "missing or unparsable"))
        analysis.findings.append(
            make_finding(
                "HS-005",
                reason="The header does not contain a parsable max-age directive.",
                value=raw,
            )
        )
    elif analysis.max_age == 0:
        analysis.rows.append(("max-age", Severity.MEDIUM, "0 (policy disabled)"))
        analysis.findings.append(
            make_finding("HS-008", reason="max-age=0 tells browsers to forget the HSTS policy.", value=raw)
        )
    elif analysis.max_age < _SIX_MONTHS:
        analysis.rows.append(("max-age", Severity.MEDIUM, f"{analysis.max_age} s (short)"))
        analysis.findings.append(
            make_finding(
                "HS-002",
                reason=f"max-age is {analysis.max_age} seconds (~{analysis.max_age // 86400} days); "
                "at least 31536000 (1 year) is recommended.",
                value=raw,
            )
        )
    elif analysis.max_age < _ONE_YEAR:
        analysis.rows.append(("max-age", Severity.LOW, f"{analysis.max_age} s (below 1 year)"))
        analysis.findings.append(
            make_finding(
                "HS-002",
                severity=Severity.LOW,
                reason=f"max-age is {analysis.max_age} seconds, below the recommended 31536000 (1 year).",
                value=raw,
            )
        )
    else:
        analysis.rows.append(("max-age", Severity.PASS, f"{analysis.max_age} s"))

    if analysis.include_subdomains:
        analysis.rows.append(("includeSubDomains", Severity.PASS, "present"))
    else:
        analysis.rows.append(("includeSubDomains", Severity.LOW, "not present"))
        analysis.findings.append(
            make_finding("HS-003", reason="The policy does not include subdomains.", value=raw)
        )

    if analysis.preload:
        analysis.rows.append(("preload", Severity.PASS, "requested"))
    else:
        analysis.rows.append(("preload", Severity.INFO, "not requested"))
        analysis.findings.append(
            make_finding("HS-004", reason="The policy does not request HSTS preloading.", value=raw)
        )

    if unknown:
        analysis.rows.append(("Syntax", Severity.MEDIUM, f"unknown token(s): {', '.join(unknown)}"))
        analysis.findings.append(
            make_finding(
                "HS-005",
                reason=f"Unrecognised HSTS token(s): {', '.join(unknown)}.",
                value=raw,
            )
        )
    if bag.count("strict-transport-security") > 1:
        analysis.rows.append(("Duplicates", Severity.LOW, f"{bag.count('strict-transport-security')} headers returned"))

    worst = _worst([status for _, status, _ in analysis.rows])
    analysis.check = HeaderCheck(
        "Strict-Transport-Security",
        worst,
        _state_for(worst),
        raw,
        "Valid policy" if analysis.valid and worst is Severity.PASS else "Policy can be strengthened",
    )
    return analysis


# --------------------------------------------------------------------------- #
# X-Frame-Options
# --------------------------------------------------------------------------- #
def analyze_frame_options(
    bag: HeaderBag,
    ctx: AnalysisContext,
    frame_ancestors: Sequence[str] | None,
) -> tuple[HeaderCheck, list[Finding], list[tuple[str, Severity, str]]]:
    """Analyse X-Frame-Options and reconcile it with CSP frame-ancestors."""
    findings: list[Finding] = []
    rows: list[tuple[str, Severity, str]] = []
    raw = bag.get("x-frame-options")
    value = (raw or "").strip()
    upper = value.upper()
    has_fa = frame_ancestors is not None

    if raw is None:
        if has_fa:
            rows.append(("X-Frame-Options", Severity.PASS, "absent (CSP frame-ancestors in use)"))
            check = HeaderCheck(
                "X-Frame-Options",
                Severity.PASS,
                "PASS",
                None,
                "Superseded by CSP frame-ancestors",
            )
        else:
            rows.append(("X-Frame-Options", Severity.MEDIUM, "missing"))
            findings.append(
                make_finding(
                    "HS-200",
                    reason="Neither X-Frame-Options nor CSP frame-ancestors was returned.",
                )
            )
            check = HeaderCheck(
                "X-Frame-Options",
                Severity.MEDIUM,
                "MISSING",
                None,
                "No framing protection",
            )
        return check, findings, rows

    if upper in {"DENY", "SAMEORIGIN"}:
        rows.append(("X-Frame-Options", Severity.PASS, f"{upper} (LEGACY header, still honoured)"))
        status = Severity.PASS
        note = f"{upper} — legacy control"
        if not has_fa:
            findings.append(
                make_finding(
                    "HS-203",
                    reason="Framing protection relies on the legacy X-Frame-Options header; "
                    "CSP frame-ancestors is absent.",
                    value=value,
                )
            )
            rows.append(("CSP frame-ancestors", Severity.LOW, "not set"))
            status = Severity.LOW
            note = f"{upper} — add CSP frame-ancestors"
    elif upper.startswith("ALLOW-FROM"):
        rows.append(("X-Frame-Options", Severity.MEDIUM, "ALLOW-FROM is obsolete"))
        findings.append(
            make_finding(
                "HS-202",
                reason="ALLOW-FROM is not supported by modern browsers, so the page is effectively unprotected.",
                value=value,
            )
        )
        status = Severity.MEDIUM
        note = "Obsolete ALLOW-FROM syntax"
    else:
        rows.append(("X-Frame-Options", Severity.MEDIUM, f"invalid value: {value!r}"))
        findings.append(
            make_finding(
                "HS-201",
                reason=f"{value!r} is not a valid X-Frame-Options value; browsers ignore it.",
                value=value,
            )
        )
        status = Severity.MEDIUM
        note = "Invalid value"

    if has_fa and upper in {"DENY", "SAMEORIGIN"}:
        fa_tokens = {token.lower() for token in (frame_ancestors or [])}
        denies = fa_tokens <= {"'none'"}
        same_origin_only = fa_tokens <= {"'self'"}
        conflict = (upper == "DENY" and not denies) or (upper == "SAMEORIGIN" and not (same_origin_only or denies))
        if conflict:
            findings.append(
                make_finding(
                    "HS-204",
                    reason=f"X-Frame-Options is {upper} while CSP frame-ancestors allows "
                    f"{' '.join(frame_ancestors or []) or 'nothing'}; browsers that support CSP use the CSP value.",
                    value=value,
                )
            )
            rows.append(("XFO vs frame-ancestors", Severity.LOW, "values disagree"))
        else:
            rows.append(("XFO vs frame-ancestors", Severity.PASS, "consistent"))

    return HeaderCheck("X-Frame-Options", status, _state_for(status), value, note), findings, rows


# --------------------------------------------------------------------------- #
# X-Content-Type-Options
# --------------------------------------------------------------------------- #
def analyze_content_type_options(bag: HeaderBag, ctx: AnalysisContext) -> tuple[HeaderCheck, list[Finding]]:
    """Analyse X-Content-Type-Options."""
    findings: list[Finding] = []
    raw = bag.get("x-content-type-options")
    if raw is None:
        findings.append(make_finding("HS-210", reason="X-Content-Type-Options was not returned."))
        return (
            HeaderCheck("X-Content-Type-Options", Severity.MEDIUM, "MISSING", None, "MIME sniffing not disabled"),
            findings,
        )
    value = raw.strip()
    if value.lower() == "nosniff":
        return HeaderCheck("X-Content-Type-Options", Severity.PASS, "PASS", value, "MIME sniffing disabled"), findings
    findings.append(
        make_finding(
            "HS-211",
            reason=f"{value!r} is not the expected 'nosniff' token.",
            value=value,
        )
    )
    return HeaderCheck("X-Content-Type-Options", Severity.LOW, "FAIL", value, "Invalid token"), findings


# --------------------------------------------------------------------------- #
# Referrer-Policy
# --------------------------------------------------------------------------- #
VALID_REFERRER_POLICIES: tuple[str, ...] = (
    "no-referrer",
    "no-referrer-when-downgrade",
    "origin",
    "origin-when-cross-origin",
    "same-origin",
    "strict-origin",
    "strict-origin-when-cross-origin",
    "unsafe-url",
    "",
)

#: Policy -> (severity, explanation) for values that weaken privacy/security.
WEAK_REFERRER_POLICIES: dict[str, tuple[Severity, str]] = {
    "unsafe-url": (
        Severity.MEDIUM,
        "Sends the full URL (path and query) to every destination, including plaintext HTTP origins.",
    ),
    "no-referrer-when-downgrade": (
        Severity.LOW,
        "Sends the full URL to all HTTPS destinations, so paths and query strings leak to third parties.",
    ),
    "origin-when-cross-origin": (
        Severity.LOW,
        "Sends the origin cross-origin but still leaks it to plaintext HTTP destinations.",
    ),
    "origin": (
        Severity.LOW,
        "Always sends the origin, including to insecure destinations.",
    ),
}

STRONG_REFERRER_POLICIES: frozenset[str] = frozenset(
    {"no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin"}
)


def analyze_referrer_policy(bag: HeaderBag, ctx: AnalysisContext) -> tuple[HeaderCheck, list[Finding]]:
    """Analyse Referrer-Policy, including comma separated fallback lists."""
    findings: list[Finding] = []
    raw = bag.joined("referrer-policy")
    if raw is None:
        findings.append(make_finding("HS-220", reason="No Referrer-Policy header was returned."))
        return HeaderCheck("Referrer-Policy", Severity.LOW, "MISSING", None, "Browser default applies"), findings

    tokens = [token.strip().lower() for token in raw.split(",")]
    known = [token for token in tokens if token in VALID_REFERRER_POLICIES and token]
    unknown = [token for token in tokens if token and token not in VALID_REFERRER_POLICIES]

    if unknown:
        findings.append(
            make_finding(
                "HS-222",
                reason=f"Unknown Referrer-Policy token(s): {', '.join(unknown)}.",
                value=raw,
            )
        )
    if not known:
        return (
            HeaderCheck("Referrer-Policy", Severity.LOW, "FAIL", raw, "No valid token — browser default applies"),
            findings,
        )

    # Browsers honour the last token they understand.
    effective = known[-1]
    if effective in WEAK_REFERRER_POLICIES:
        severity, explanation = WEAK_REFERRER_POLICIES[effective]
        findings.append(
            make_finding(
                "HS-221",
                severity=severity,
                reason=f"Effective policy '{effective}': {explanation}",
                value=raw,
            )
        )
        return (
            HeaderCheck("Referrer-Policy", severity, _state_for(severity), raw, f"Weak policy: {effective}"),
            findings,
        )

    status = Severity.LOW if unknown else Severity.PASS
    return (
        HeaderCheck("Referrer-Policy", status, _state_for(status), raw, f"Effective policy: {effective}"),
        findings,
    )


# --------------------------------------------------------------------------- #
# Permissions-Policy
# --------------------------------------------------------------------------- #
#: Features that should normally be denied unless explicitly required.
SENSITIVE_FEATURES: tuple[str, ...] = (
    "camera",
    "microphone",
    "geolocation",
    "payment",
    "usb",
    "serial",
    "bluetooth",
    "hid",
    "midi",
    "display-capture",
    "idle-detection",
    "screen-wake-lock",
)

#: The subset that matters most: privacy sensitive and commonly abused in
#: embedded third-party frames.  HS-233 is raised when several of these are
#: left unrestricted.
CORE_SENSITIVE_FEATURES: tuple[str, ...] = (
    "camera",
    "microphone",
    "geolocation",
    "payment",
    "usb",
    "display-capture",
)

#: Additional features commonly restricted for privacy/UX reasons.
COMMON_FEATURES: tuple[str, ...] = (
    "accelerometer",
    "gyroscope",
    "magnetometer",
    "autoplay",
    "fullscreen",
    "clipboard-read",
    "clipboard-write",
    "encrypted-media",
    "picture-in-picture",
    "xr-spatial-tracking",
    "interest-cohort",
    "browsing-topics",
)

_PP_DIRECTIVE_RE = re.compile(r"^(?P<name>[A-Za-z0-9*_-]+)\s*=\s*(?P<value>.+)$", re.DOTALL)


def parse_permissions_policy(raw: str) -> tuple[dict[str, list[str]], list[str]]:
    """Parse a Permissions-Policy header into ``{feature: [allowlist]}``.

    Returns the directives plus a list of malformed fragments.

    >>> parse_permissions_policy('camera=(), geolocation=(self "https://a.example")')[0]
    {'camera': [], 'geolocation': ['self', 'https://a.example']}
    """
    directives: dict[str, list[str]] = {}
    malformed: list[str] = []

    for fragment in _split_top_level(raw, ","):
        item = fragment.strip()
        if not item:
            continue
        match = _PP_DIRECTIVE_RE.match(item)
        if not match:
            malformed.append(item)
            continue
        name = match.group("name").strip().lower()
        value = match.group("value").strip()
        if value == "*":
            directives[name] = ["*"]
            continue
        if value.startswith("(") and value.endswith(")"):
            inner = value[1:-1].strip()
            if not inner:
                directives[name] = []
                continue
            origins = [token.strip().strip('"') for token in inner.split() if token.strip()]
            directives[name] = origins
            continue
        # Legacy Feature-Policy style: `camera 'none'`
        malformed.append(item)
    return directives, malformed


def _split_top_level(value: str, separator: str) -> list[str]:
    """Split on ``separator`` ignoring separators inside quotes or parentheses."""
    parts: list[str] = []
    depth = 0
    quoted = False
    current: list[str] = []
    for char in value:
        if char == '"':
            quoted = not quoted
        elif char == "(" and not quoted:
            depth += 1
        elif char == ")" and not quoted:
            depth = max(0, depth - 1)
        if char == separator and depth == 0 and not quoted:
            parts.append("".join(current))
            current = []
            continue
        current.append(char)
    parts.append("".join(current))
    return parts


def analyze_permissions_policy(bag: HeaderBag, ctx: AnalysisContext) -> PermissionsPolicyAnalysis:
    """Analyse Permissions-Policy (and flag the deprecated Feature-Policy)."""
    analysis = PermissionsPolicyAnalysis()
    raw = bag.joined("permissions-policy")
    analysis.raw = raw

    if bag.has("feature-policy"):
        analysis.findings.append(
            make_finding(
                "HS-234",
                reason="The deprecated Feature-Policy header is still being sent.",
                value=bag.get("feature-policy"),
            )
        )

    if raw is None:
        analysis.present = False
        analysis.findings.append(make_finding("HS-230", reason="No Permissions-Policy header was returned."))
        analysis.rows.append(("Header present", Severity.LOW, "not returned"))
        analysis.check = HeaderCheck(
            "Permissions-Policy",
            Severity.LOW,
            "MISSING",
            None,
            "Browser feature defaults apply",
        )
        return analysis

    analysis.present = True
    directives, malformed = parse_permissions_policy(raw)
    analysis.directives = directives
    analysis.malformed = malformed

    for feature, allowlist in directives.items():
        if "*" in allowlist:
            analysis.unrestricted.append(feature)
            severity = Severity.MEDIUM if feature in SENSITIVE_FEATURES else Severity.LOW
            analysis.rows.append((f"{feature}=*", severity, "allowed for every origin"))
            analysis.findings.append(
                make_finding(
                    "HS-231",
                    severity=severity,
                    reason=f"Feature '{feature}' is allowed for all origins (*).",
                    value=f"{feature}=*",
                )
            )
        elif not allowlist:
            analysis.restricted.append(feature)
            analysis.rows.append((f"{feature}=()", Severity.PASS, "denied everywhere"))
        else:
            analysis.restricted.append(feature)
            analysis.rows.append((f"{feature}=({' '.join(allowlist)})", Severity.PASS, "restricted allow-list"))

    if malformed:
        analysis.findings.append(
            make_finding(
                "HS-232",
                reason=f"Could not parse directive(s): {', '.join(malformed)}.",
                value=raw,
            )
        )
        analysis.rows.append(("Syntax", Severity.LOW, f"{len(malformed)} malformed directive(s)"))

    missing_sensitive = [f for f in CORE_SENSITIVE_FEATURES if f not in directives]
    if len(missing_sensitive) >= 3:
        analysis.findings.append(
            make_finding(
                "HS-233",
                reason="Sensitive features are not explicitly restricted: " + ", ".join(missing_sensitive[:8]) + ".",
                value=raw,
                metadata={"missing": missing_sensitive},
            )
        )
        analysis.rows.append(
            ("Sensitive features", Severity.LOW, f"{len(missing_sensitive)} not explicitly denied")
        )

    worst = _worst([status for _, status, _ in analysis.rows])
    analysis.check = HeaderCheck(
        "Permissions-Policy",
        worst,
        _state_for(worst),
        raw,
        f"{len(directives)} directive(s), {len(analysis.unrestricted)} unrestricted",
    )
    return analysis


# --------------------------------------------------------------------------- #
# Cross-origin isolation (COOP / CORP / COEP)
# --------------------------------------------------------------------------- #
COOP_VALUES = {"unsafe-none", "same-origin-allow-popups", "same-origin", "noopener-allow-popups"}
CORP_VALUES = {"same-site", "same-origin", "cross-origin"}
COEP_VALUES = {"unsafe-none", "require-corp", "credentialless"}

#: Plain-language explanation of each value, per header.
CROSS_ORIGIN_EXPLANATIONS: dict[str, dict[str, str]] = {
    "coop": {
        "unsafe-none": "permissive default — the document shares its browsing context group with cross-origin documents",
        "same-origin": "only same-origin documents may share the browsing context group",
        "same-origin-allow-popups": "isolates the document but keeps references to popups it opens (OAuth friendly)",
        "noopener-allow-popups": "severs the opener relationship while still allowing popups to be opened",
    },
    "corp": {
        "same-origin": "only same-origin documents may embed this resource",
        "same-site": "only documents from the same site may embed this resource",
        "cross-origin": "any origin may embed this resource — intended for public assets",
    },
    "coep": {
        "unsafe-none": "permissive default — cross-origin sub-resources load without opting in",
        "require-corp": "sub-resources must opt in via CORP or CORS; required for cross-origin isolation",
        "credentialless": "cross-origin sub-resources load without credentials instead of requiring CORP",
    },
}


def _explain(header_key: str, value: str) -> str:
    """Return the human explanation for a cross-origin policy value."""
    return CROSS_ORIGIN_EXPLANATIONS.get(header_key, {}).get(value, "")


def analyze_cross_origin(bag: HeaderBag, ctx: AnalysisContext) -> CrossOriginAnalysis:
    """Analyse COOP, CORP and COEP, including isolation compatibility."""
    analysis = CrossOriginAnalysis()
    findings: list[Finding] = []

    coop = (bag.get("cross-origin-opener-policy") or "").split(";")[0].strip().lower() or None
    corp = (bag.get("cross-origin-resource-policy") or "").strip().lower() or None
    coep = (bag.get("cross-origin-embedder-policy") or "").split(";")[0].strip().lower() or None
    analysis.coop, analysis.corp, analysis.coep = coop, corp, coep

    # ---- COOP -------------------------------------------------------------
    if coop is None:
        findings.append(make_finding("HS-300", reason="No Cross-Origin-Opener-Policy header was returned."))
        analysis.rows.append(("COOP", Severity.LOW, "missing"))
        analysis.checks.append(
            HeaderCheck("Cross-Origin-Opener-Policy", Severity.LOW, "MISSING", None, "Browsing context not isolated")
        )
    elif coop not in COOP_VALUES:
        findings.append(
            make_finding(
                "HS-306",
                reason=f"{coop!r} is not a valid Cross-Origin-Opener-Policy value.",
                header="cross-origin-opener-policy",
                value=coop,
                recommendation="Use same-origin, same-origin-allow-popups or unsafe-none.",
            )
        )
        analysis.rows.append(("COOP", Severity.LOW, f"invalid value: {coop}"))
        analysis.checks.append(
            HeaderCheck("Cross-Origin-Opener-Policy", Severity.LOW, "FAIL", coop, "Invalid value")
        )
    elif coop == "unsafe-none":
        findings.append(
            make_finding("HS-301", reason="COOP is explicitly set to unsafe-none.", value=coop)
        )
        analysis.rows.append(("COOP", Severity.LOW, f"unsafe-none — {_explain('coop', coop)}"))
        analysis.checks.append(
            HeaderCheck("Cross-Origin-Opener-Policy", Severity.LOW, "WEAK", coop, "Permissive value")
        )
    else:
        analysis.rows.append(("COOP", Severity.PASS, f"{coop} — {_explain('coop', coop)}"))
        analysis.checks.append(
            HeaderCheck("Cross-Origin-Opener-Policy", Severity.PASS, "PASS", coop, "Browsing context isolated")
        )

    # ---- CORP -------------------------------------------------------------
    if corp is None:
        findings.append(make_finding("HS-302", reason="No Cross-Origin-Resource-Policy header was returned."))
        analysis.rows.append(("CORP", Severity.LOW, "missing"))
        analysis.checks.append(
            HeaderCheck("Cross-Origin-Resource-Policy", Severity.LOW, "MISSING", None, "Embedding not restricted")
        )
    elif corp not in CORP_VALUES:
        findings.append(
            make_finding(
                "HS-306",
                reason=f"{corp!r} is not a valid Cross-Origin-Resource-Policy value.",
                header="cross-origin-resource-policy",
                value=corp,
                recommendation="Use same-origin, same-site or cross-origin.",
            )
        )
        analysis.rows.append(("CORP", Severity.LOW, f"invalid value: {corp}"))
        analysis.checks.append(
            HeaderCheck("Cross-Origin-Resource-Policy", Severity.LOW, "FAIL", corp, "Invalid value")
        )
    elif corp == "cross-origin":
        findings.append(
            make_finding("HS-303", reason="CORP is set to cross-origin, so any site may embed this resource.", value=corp)
        )
        analysis.rows.append(("CORP", Severity.INFO, f"cross-origin — {_explain('corp', corp)}"))
        analysis.checks.append(
            HeaderCheck("Cross-Origin-Resource-Policy", Severity.INFO, "INFO", corp, "Public resource policy")
        )
    else:
        analysis.rows.append(("CORP", Severity.PASS, f"{corp} — {_explain('corp', corp)}"))
        analysis.checks.append(
            HeaderCheck("Cross-Origin-Resource-Policy", Severity.PASS, "PASS", corp, "Embedding restricted")
        )

    # ---- COEP -------------------------------------------------------------
    if coep is None:
        findings.append(make_finding("HS-304", reason="No Cross-Origin-Embedder-Policy header was returned."))
        analysis.rows.append(("COEP", Severity.INFO, "missing"))
        analysis.checks.append(
            HeaderCheck("Cross-Origin-Embedder-Policy", Severity.INFO, "MISSING", None, "Not cross-origin isolated")
        )
    elif coep not in COEP_VALUES:
        findings.append(
            make_finding(
                "HS-306",
                reason=f"{coep!r} is not a valid Cross-Origin-Embedder-Policy value.",
                header="cross-origin-embedder-policy",
                value=coep,
                recommendation="Use require-corp, credentialless or unsafe-none.",
            )
        )
        analysis.rows.append(("COEP", Severity.LOW, f"invalid value: {coep}"))
        analysis.checks.append(
            HeaderCheck("Cross-Origin-Embedder-Policy", Severity.LOW, "FAIL", coep, "Invalid value")
        )
    else:
        severity = Severity.PASS if coep in {"require-corp", "credentialless"} else Severity.INFO
        analysis.rows.append(("COEP", severity, f"{coep} — {_explain('coep', coep)}"))
        analysis.checks.append(
            HeaderCheck(
                "Cross-Origin-Embedder-Policy",
                severity,
                _state_for(severity),
                coep,
                "Isolation capable" if severity is Severity.PASS else "Permissive value",
            )
        )

    # ---- combination ------------------------------------------------------
    analysis.cross_origin_isolated = coop == "same-origin" and coep in {"require-corp", "credentialless"}
    if analysis.cross_origin_isolated:
        analysis.rows.append(("Cross-origin isolated", Severity.PASS, "COOP same-origin + COEP enforced"))
    elif coep in {"require-corp", "credentialless"} and coop != "same-origin":
        findings.append(
            make_finding(
                "HS-305",
                reason=f"COEP is {coep} but COOP is {coop or 'absent'}; crossOriginIsolated stays false and "
                "sub-resources may break without the isolation benefit.",
                value=f"COOP={coop or 'absent'}, COEP={coep}",
            )
        )
        analysis.rows.append(("Cross-origin isolated", Severity.INFO, "no — COOP must be same-origin"))
    else:
        analysis.rows.append(("Cross-origin isolated", Severity.INFO, "no"))

    analysis.findings = findings
    return analysis


# --------------------------------------------------------------------------- #
# Information disclosure
# --------------------------------------------------------------------------- #
_VERSION_RE = re.compile(r"\d+(\.\d+)+|\d{2,}")


def analyze_disclosure(bag: HeaderBag, ctx: AnalysisContext) -> tuple[list[DisclosureItem], list[Finding]]:
    """Report headers that disclose technology or infrastructure details.

    These are *observations*, not vulnerabilities: they reduce the cost of
    reconnaissance but do not by themselves allow an attack.
    """
    items: list[DisclosureItem] = []
    findings: list[Finding] = []

    for key, description in DISCLOSURE_HEADERS.items():
        value = bag.joined(key)
        if value is None:
            continue
        has_version = bool(_VERSION_RE.search(value))
        canonical = normalize_header_name(key)

        if key == "server":
            severity = Severity.LOW if has_version else Severity.INFO
            note = "Version disclosed" if has_version else "Software name disclosed"
            if has_version:
                findings.append(
                    make_finding(
                        "HS-500",
                        reason=f"The Server header exposes a specific version: {value}.",
                        value=value,
                        header="server",
                    )
                )
            else:
                findings.append(
                    make_finding(
                        "HS-500",
                        severity=Severity.INFO,
                        reason=f"The Server header discloses the software in use: {value}.",
                        value=value,
                        header="server",
                        title="Server software disclosed",
                    )
                )
        elif key == "x-powered-by":
            severity = Severity.LOW
            note = "Application stack disclosed"
            findings.append(
                make_finding("HS-501", reason=f"X-Powered-By discloses: {value}.", value=value)
            )
        elif key in {"x-aspnet-version", "x-aspnetmvc-version"}:
            severity = Severity.LOW
            note = "Framework version disclosed"
            findings.append(
                make_finding(
                    "HS-502",
                    reason=f"{canonical} discloses the framework version: {value}.",
                    value=value,
                    header=key,
                )
            )
        elif key == "x-generator":
            severity = Severity.INFO
            note = "Generator/CMS disclosed"
            findings.append(
                make_finding("HS-504", reason=f"X-Generator discloses: {value}.", value=value)
            )
        else:
            severity = Severity.INFO
            note = description
            findings.append(
                make_finding(
                    "HS-503",
                    reason=f"{canonical} exposes infrastructure detail: {value}.",
                    value=value,
                    header=key,
                    title=f"Infrastructure detail disclosed via {canonical}",
                )
            )
        items.append(DisclosureItem(canonical, value, severity, note))

    return items, findings


# --------------------------------------------------------------------------- #
# Caching
# --------------------------------------------------------------------------- #
def analyze_caching(bag: HeaderBag, ctx: AnalysisContext) -> tuple[list[tuple[str, Severity, str]], list[Finding]]:
    """Analyse Cache-Control / Pragma / Clear-Site-Data posture."""
    rows: list[tuple[str, Severity, str]] = []
    findings: list[Finding] = []

    cache_control = bag.joined("cache-control")
    if cache_control is None:
        rows.append(("Cache-Control", Severity.INFO, "not set — heuristic caching applies"))
        findings.append(make_finding("HS-600", reason="No Cache-Control header was returned."))
    else:
        directives = {token.strip().lower() for token in cache_control.split(",") if token.strip()}
        no_store = "no-store" in directives
        private = "private" in directives
        public = "public" in directives
        rows.append(("Cache-Control", Severity.PASS if no_store or private else Severity.INFO, cache_control))
        sets_cookies = bag.has("set-cookie")
        if sets_cookies and not no_store and (public or not private):
            findings.append(
                make_finding(
                    "HS-601",
                    reason="The response sets cookies but does not use Cache-Control: no-store, "
                    "so a shared cache may store user-specific content.",
                    value=cache_control,
                )
            )
            rows.append(("Sensitive caching", Severity.LOW, "cookies set on a cacheable response"))

    if bag.has("pragma"):
        rows.append(("Pragma", Severity.INFO, f"{bag.get('pragma')} (LEGACY)"))
        findings.append(
            make_finding("HS-514", reason="The HTTP/1.0 Pragma header is still present.", value=bag.get("pragma"))
        )

    if bag.has("clear-site-data"):
        value = bag.joined("clear-site-data") or ""
        rows.append(("Clear-Site-Data", Severity.INFO, value))
        findings.append(
            make_finding("HS-602", reason=f"Clear-Site-Data is being sent on this response: {value}.", value=value)
        )

    return rows, findings


# --------------------------------------------------------------------------- #
# Deprecated / legacy headers
# --------------------------------------------------------------------------- #
def analyze_deprecated(bag: HeaderBag, ctx: AnalysisContext) -> tuple[list[HeaderCheck], list[Finding]]:
    """Flag deprecated and legacy headers, and the missing legacy hardening ones."""
    checks: list[HeaderCheck] = []
    findings: list[Finding] = []

    xss = bag.get("x-xss-protection")
    if xss is not None:
        value = xss.strip()
        first = value.split(";")[0].strip()
        if first == "0":
            checks.append(
                HeaderCheck("X-XSS-Protection", Severity.INFO, "DEPRECATED", value, "Filter disabled (recommended)")
            )
            findings.append(
                make_finding(
                    "HS-510",
                    reason="X-XSS-Protection: 0 is present. The header is deprecated; keeping the explicit 0 "
                    "is acceptable but no longer necessary.",
                    value=value,
                )
            )
        else:
            checks.append(
                HeaderCheck("X-XSS-Protection", Severity.LOW, "DEPRECATED", value, "Legacy filter enabled")
            )
            findings.append(
                make_finding(
                    "HS-511",
                    reason=f"X-XSS-Protection is set to {value!r}; the legacy auditor is removed from modern "
                    "browsers and was itself a source of vulnerabilities.",
                    value=value,
                )
            )

    if bag.has("expect-ct"):
        value = bag.joined("expect-ct") or ""
        checks.append(HeaderCheck("Expect-CT", Severity.INFO, "DEPRECATED", value, "Obsolete header"))
        findings.append(make_finding("HS-512", reason="The obsolete Expect-CT header is still sent.", value=value))

    for pin_header in ("public-key-pins", "public-key-pins-report-only"):
        if bag.has(pin_header):
            value = bag.joined(pin_header) or ""
            checks.append(
                HeaderCheck(normalize_header_name(pin_header), Severity.MEDIUM, "DEPRECATED", value, "HPKP removed from browsers")
            )
            findings.append(
                make_finding(
                    "HS-513",
                    reason=f"{normalize_header_name(pin_header)} is present; HPKP is removed from all browsers "
                    "and risks bricking the site.",
                    value=value,
                    header=pin_header,
                )
            )

    xpcdp = bag.get("x-permitted-cross-domain-policies")
    if xpcdp is None:
        checks.append(
            HeaderCheck(
                "X-Permitted-Cross-Domain-Policies",
                Severity.INFO,
                "MISSING",
                None,
                "Legacy Adobe clients fall back to crossdomain.xml",
            )
        )
        findings.append(make_finding("HS-516", reason="X-Permitted-Cross-Domain-Policies was not returned."))
    else:
        value = xpcdp.strip().lower()
        if value == "none":
            checks.append(
                HeaderCheck("X-Permitted-Cross-Domain-Policies", Severity.PASS, "PASS", xpcdp, "Policy files denied")
            )
        else:
            checks.append(
                HeaderCheck("X-Permitted-Cross-Domain-Policies", Severity.LOW, "WEAK", xpcdp, "Permissive value")
            )
            findings.append(
                make_finding(
                    "HS-515",
                    reason=f"X-Permitted-Cross-Domain-Policies is {xpcdp!r} instead of 'none'.",
                    value=xpcdp,
                )
            )

    return checks, findings


# --------------------------------------------------------------------------- #
# Internal helpers
# --------------------------------------------------------------------------- #
def _worst(statuses: Iterable[Severity]) -> Severity:
    """Return the most severe status in ``statuses`` (PASS when empty)."""
    worst = Severity.PASS
    for status in statuses:
        if status.rank < worst.rank:
            worst = status
    return worst


def _state_for(severity: Severity) -> str:
    """Map a severity to the short state label used in tables."""
    return {
        Severity.CRITICAL: "CRITICAL",
        Severity.HIGH: "FAIL",
        Severity.MEDIUM: "WARNING",
        Severity.LOW: "WEAK",
        Severity.INFO: "INFO",
        Severity.PASS: "PASS",
    }[severity]
