"""Advanced Content-Security-Policy parser and analyzer.

The parser is deliberately tolerant (real-world policies are messy) while the
analyzer is strict: it evaluates the *effective* value of each directive,
taking ``default-src`` fallback into account, and reports risky patterns such
as ``'unsafe-inline'``, ``'unsafe-eval'``, wildcards, plaintext sources,
dangerous schemes and missing hardening directives.

When multiple CSP headers are returned, browsers enforce the intersection of
all policies.  HeaderSpecter analyses the union of directives (a directive is
considered "present" when any policy defines it) and raises ``HS-116`` so the
operator knows the effective policy is harder to reason about.
"""

from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from .findings import Finding, Severity, make_finding
from .headers import AnalysisContext, HeaderBag, HeaderCheck

__all__ = [
    "CSPPolicy",
    "CSPAnalysis",
    "CSPDirectiveRow",
    "parse_csp",
    "analyze_csp",
    "FETCH_DIRECTIVES",
    "KNOWN_DIRECTIVES",
]

#: Directives that fall back to ``default-src`` when absent.
FETCH_DIRECTIVES: frozenset[str] = frozenset(
    {
        "child-src",
        "connect-src",
        "default-src",
        "font-src",
        "frame-src",
        "img-src",
        "manifest-src",
        "media-src",
        "object-src",
        "prefetch-src",
        "script-src",
        "script-src-attr",
        "script-src-elem",
        "style-src",
        "style-src-attr",
        "style-src-elem",
        "worker-src",
    }
)

#: Document / navigation / reporting / other directives.
OTHER_DIRECTIVES: frozenset[str] = frozenset(
    {
        "base-uri",
        "block-all-mixed-content",
        "form-action",
        "frame-ancestors",
        "navigate-to",
        "plugin-types",
        "referrer",
        "report-to",
        "report-uri",
        "require-trusted-types-for",
        "sandbox",
        "trusted-types",
        "upgrade-insecure-requests",
    }
)

KNOWN_DIRECTIVES: frozenset[str] = FETCH_DIRECTIVES | OTHER_DIRECTIVES

#: Directives whose analysis is displayed in the CSP panel, in this order.
DISPLAY_ORDER: tuple[str, ...] = (
    "default-src",
    "script-src",
    "style-src",
    "img-src",
    "font-src",
    "connect-src",
    "frame-src",
    "object-src",
    "media-src",
    "manifest-src",
    "worker-src",
    "child-src",
    "base-uri",
    "form-action",
    "frame-ancestors",
    "sandbox",
    "upgrade-insecure-requests",
    "block-all-mixed-content",
    "report-uri",
    "report-to",
)

CSP_KEYWORDS: frozenset[str] = frozenset(
    {
        "'self'",
        "'none'",
        "'unsafe-inline'",
        "'unsafe-eval'",
        "'wasm-unsafe-eval'",
        "'strict-dynamic'",
        "'unsafe-hashes'",
        "'report-sample'",
        "'inline-speculation-rules'",
        "'unsafe-allow-redirects'",
    }
)

_SCHEME_SOURCE_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*:$")
_NONCE_RE = re.compile(r"^'nonce-(?P<nonce>[A-Za-z0-9+/=_\-]+)'$", re.IGNORECASE)
_HASH_RE = re.compile(r"^'(sha256|sha384|sha512)-[A-Za-z0-9+/=_\-]+'$", re.IGNORECASE)
_PLACEHOLDER_NONCE_RE = re.compile(r"^(nonce|random|placeholder|test|abc123|changeme|value)$", re.IGNORECASE)

#: Schemes that must never appear in a script/object context.
DANGEROUS_SCHEMES: tuple[str, ...] = ("data:", "blob:", "filesystem:", "javascript:")

#: Directives for which a wildcard is particularly dangerous.
CRITICAL_WILDCARD_DIRECTIVES: frozenset[str] = frozenset(
    {"default-src", "script-src", "script-src-elem", "object-src", "frame-ancestors"}
)

#: Above this number of distinct host sources the policy becomes hard to audit.
LARGE_ALLOWLIST_THRESHOLD = 15


@dataclass(slots=True)
class CSPPolicy:
    """One parsed Content-Security-Policy header."""

    raw: str
    directives: dict[str, list[str]] = field(default_factory=dict)
    report_only: bool = False
    duplicate_directives: list[str] = field(default_factory=list)
    empty_directives: list[str] = field(default_factory=list)

    def get(self, directive: str) -> list[str] | None:
        """Return the raw source list for ``directive`` (``None`` when absent)."""
        return self.directives.get(directive.lower())

    def effective(self, directive: str) -> tuple[list[str] | None, str | None]:
        """Return ``(sources, source_directive)`` honouring default-src fallback."""
        name = directive.lower()
        if name in self.directives:
            return self.directives[name], name
        if name in FETCH_DIRECTIVES and "default-src" in self.directives:
            return self.directives["default-src"], "default-src"
        # script-src-elem/attr also fall back to script-src, style the same way
        if name in {"script-src-elem", "script-src-attr"} and "script-src" in self.directives:
            return self.directives["script-src"], "script-src"
        if name in {"style-src-elem", "style-src-attr"} and "style-src" in self.directives:
            return self.directives["style-src"], "style-src"
        return None, None

    def to_dict(self) -> dict[str, Any]:
        """JSON-serialisable representation."""
        return {
            "raw": self.raw,
            "report_only": self.report_only,
            "directives": {name: list(values) for name, values in self.directives.items()},
        }


@dataclass(slots=True)
class CSPDirectiveRow:
    """One row of the detailed CSP directive table."""

    directive: str
    value: str
    status: Severity
    note: str

    def to_dict(self) -> dict[str, Any]:
        """JSON-serialisable representation."""
        return {
            "directive": self.directive,
            "value": self.value,
            "status": self.status.value,
            "note": self.note,
        }


@dataclass(slots=True)
class CSPAnalysis:
    """Aggregated CSP posture for a scanned response."""

    present: bool = False
    enforced: bool = False
    report_only_present: bool = False
    policies: list[CSPPolicy] = field(default_factory=list)
    merged: dict[str, list[str]] = field(default_factory=dict)
    rows: list[tuple[str, Severity, str]] = field(default_factory=list)
    directive_rows: list[CSPDirectiveRow] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    check: HeaderCheck | None = None
    frame_ancestors: list[str] | None = None
    uses_nonce: bool = False
    uses_hash: bool = False
    strict_dynamic: bool = False
    host_sources: list[str] = field(default_factory=list)
    raw: str | None = None

    @property
    def strict(self) -> bool:
        """True when the policy follows the nonce/hash + strict-dynamic pattern."""
        return (self.uses_nonce or self.uses_hash) and self.strict_dynamic

    def to_dict(self) -> dict[str, Any]:
        """JSON-serialisable representation."""
        return {
            "present": self.present,
            "enforced": self.enforced,
            "report_only_present": self.report_only_present,
            "raw": self.raw,
            "directives": {name: list(values) for name, values in self.merged.items()},
            "uses_nonce": self.uses_nonce,
            "uses_hash": self.uses_hash,
            "strict_dynamic": self.strict_dynamic,
            "strict": self.strict,
            "host_sources": list(self.host_sources),
            "frame_ancestors": list(self.frame_ancestors) if self.frame_ancestors is not None else None,
            "checks": [
                {"label": label, "status": status.value, "detail": detail} for label, status, detail in self.rows
            ],
            "directive_rows": [row.to_dict() for row in self.directive_rows],
        }


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #
def parse_csp(raw: str, report_only: bool = False) -> CSPPolicy:
    """Parse a CSP header value into a :class:`CSPPolicy`.

    >>> policy = parse_csp("default-src 'self'; script-src 'self' https://cdn.example.com")
    >>> policy.directives["script-src"]
    ["'self'", 'https://cdn.example.com']
    """
    policy = CSPPolicy(raw=raw.strip(), report_only=report_only)
    for segment in raw.split(";"):
        chunk = segment.strip()
        if not chunk:
            continue
        parts = chunk.split()
        name = parts[0].lower()
        values = parts[1:]
        if name in policy.directives:
            policy.duplicate_directives.append(name)
            # Browsers ignore the repeated occurrence; keep the first one.
            continue
        if not values and name in FETCH_DIRECTIVES:
            policy.empty_directives.append(name)
        policy.directives[name] = values
    return policy


def _is_host_source(token: str) -> bool:
    """True when the token is a host/URL source (not a keyword/scheme/nonce)."""
    lowered = token.lower()
    if lowered in CSP_KEYWORDS or _NONCE_RE.match(token) or _HASH_RE.match(token):
        return False
    if _SCHEME_SOURCE_RE.match(lowered):
        return False
    return lowered not in {"*", "'none'"}


def _nonce_of(token: str) -> str | None:
    match = _NONCE_RE.match(token)
    return match.group("nonce") if match else None


def _nonce_is_weak(nonce: str) -> bool:
    """Heuristic check for short/predictable nonces (< 128 bits of entropy)."""
    if _PLACEHOLDER_NONCE_RE.match(nonce):
        return True
    if len(set(nonce)) <= 2:
        return True
    try:
        padded = nonce + "=" * (-len(nonce) % 4)
        decoded = base64.b64decode(padded.replace("-", "+").replace("_", "/"), validate=False)
        return len(decoded) < 16
    except (binascii.Error, ValueError):
        return len(nonce) < 16


# --------------------------------------------------------------------------- #
# Analysis
# --------------------------------------------------------------------------- #
def analyze_csp(bag: HeaderBag, ctx: AnalysisContext) -> CSPAnalysis:
    """Run the full CSP analysis over the response headers."""
    analysis = CSPAnalysis()
    enforced_raw = bag.get_all("content-security-policy")
    report_raw = bag.get_all("content-security-policy-report-only")

    analysis.policies = [parse_csp(value) for value in enforced_raw] + [
        parse_csp(value, report_only=True) for value in report_raw
    ]
    analysis.enforced = bool(enforced_raw)
    analysis.report_only_present = bool(report_raw)
    analysis.present = bool(analysis.policies)
    analysis.raw = enforced_raw[0] if enforced_raw else (report_raw[0] if report_raw else None)

    if not analysis.present:
        analysis.findings.append(
            make_finding("HS-100", reason="No Content-Security-Policy header was returned.")
        )
        analysis.rows.append(("Content-Security-Policy", Severity.HIGH, "not returned"))
        analysis.check = HeaderCheck(
            "Content-Security-Policy", Severity.HIGH, "MISSING", None, "No browser-side content policy"
        )
        return analysis

    if not analysis.enforced and analysis.report_only_present:
        analysis.findings.append(
            make_finding(
                "HS-110",
                reason="Only Content-Security-Policy-Report-Only was returned; violations are reported but "
                "nothing is blocked.",
                value=analysis.raw,
            )
        )
        analysis.rows.append(("Enforcement", Severity.MEDIUM, "Report-Only (nothing is blocked)"))
    else:
        analysis.rows.append(("Enforcement", Severity.PASS, "Enforcing policy present"))

    if len(enforced_raw) > 1:
        analysis.findings.append(
            make_finding(
                "HS-116",
                reason=f"{len(enforced_raw)} Content-Security-Policy headers were returned; browsers enforce the "
                "intersection of all of them.",
                value=" || ".join(enforced_raw),
            )
        )
        analysis.rows.append(("Policy count", Severity.LOW, f"{len(enforced_raw)} enforcing policies"))

    # Union view used for the remaining checks.
    enforcing_policies = [p for p in analysis.policies if not p.report_only] or analysis.policies
    merged: dict[str, list[str]] = {}
    for policy in enforcing_policies:
        for name, values in policy.directives.items():
            merged.setdefault(name, [])
            for value in values:
                if value not in merged[name]:
                    merged[name].append(value)
    analysis.merged = merged

    primary = enforcing_policies[0]
    analysis.frame_ancestors = merged.get("frame-ancestors")

    all_tokens = [token for values in merged.values() for token in values]
    analysis.uses_nonce = any(_NONCE_RE.match(token) for token in all_tokens)
    analysis.uses_hash = any(_HASH_RE.match(token) for token in all_tokens)
    analysis.strict_dynamic = any(token.lower() == "'strict-dynamic'" for token in all_tokens)
    analysis.host_sources = sorted({token for token in all_tokens if _is_host_source(token)})

    _check_unknown_directives(analysis, merged)
    _check_script_sources(analysis, merged, primary)
    _check_style_sources(analysis, merged)
    _check_wildcards(analysis, merged)
    _check_schemes(analysis, merged, ctx)
    _check_missing_directives(analysis, merged)
    _check_sandbox(analysis, merged)
    _check_reporting(analysis, merged)
    _check_allowlist_size(analysis)
    _build_directive_rows(analysis, merged)

    worst = Severity.PASS
    for _, status, _ in analysis.rows:
        if status.rank < worst.rank:
            worst = status
    note = "Strict nonce-based policy" if analysis.strict else f"{len(merged)} directive(s)"
    analysis.check = HeaderCheck(
        "Content-Security-Policy",
        worst,
        {
            Severity.CRITICAL: "CRITICAL",
            Severity.HIGH: "FAIL",
            Severity.MEDIUM: "WARNING",
            Severity.LOW: "WEAK",
            Severity.INFO: "INFO",
            Severity.PASS: "PASS",
        }[worst],
        analysis.raw,
        note,
    )
    return analysis


def _effective(merged: dict[str, list[str]], directive: str) -> tuple[list[str] | None, str | None]:
    """default-src aware lookup against the merged directive map."""
    if directive in merged:
        return merged[directive], directive
    if directive in {"script-src-elem", "script-src-attr"} and "script-src" in merged:
        return merged["script-src"], "script-src"
    if directive in {"style-src-elem", "style-src-attr"} and "style-src" in merged:
        return merged["style-src"], "style-src"
    if directive in FETCH_DIRECTIVES and "default-src" in merged:
        return merged["default-src"], "default-src"
    return None, None


def _check_unknown_directives(analysis: CSPAnalysis, merged: dict[str, list[str]]) -> None:
    unknown = [name for name in merged if name not in KNOWN_DIRECTIVES]
    if unknown:
        analysis.findings.append(
            make_finding(
                "HS-115",
                reason="Unknown or unsupported directive(s): " + ", ".join(sorted(unknown)) + ".",
                value=", ".join(sorted(unknown)),
            )
        )
        analysis.rows.append(("Unknown directives", Severity.LOW, ", ".join(sorted(unknown))))


def _check_script_sources(analysis: CSPAnalysis, merged: dict[str, list[str]], primary: CSPPolicy) -> None:
    sources, origin = _effective(merged, "script-src")
    if sources is None:
        return  # handled by the missing default-src / script-src checks

    lowered = [token.lower() for token in sources]
    has_nonce = any(_NONCE_RE.match(token) for token in sources)
    has_hash = any(_HASH_RE.match(token) for token in sources)

    if "'unsafe-inline'" in lowered:
        if has_nonce or has_hash:
            analysis.findings.append(
                make_finding(
                    "HS-101",
                    severity=Severity.INFO,
                    reason="'unsafe-inline' is present in "
                    f"{origin} but a nonce/hash is also specified, so CSP2+ browsers ignore it. "
                    "It only takes effect on legacy browsers.",
                    value=f"{origin}: {' '.join(sources)}",
                    title="CSP keeps 'unsafe-inline' as a legacy fallback",
                )
            )
            analysis.rows.append(("'unsafe-inline' (scripts)", Severity.INFO, "present but neutralised by nonce/hash"))
        else:
            analysis.findings.append(
                make_finding(
                    "HS-101",
                    reason=f"{origin} allows 'unsafe-inline', so inline scripts and event handlers execute.",
                    value=f"{origin}: {' '.join(sources)}",
                )
            )
            analysis.rows.append(("'unsafe-inline' (scripts)", Severity.HIGH, "detected"))
    else:
        analysis.rows.append(("'unsafe-inline' (scripts)", Severity.PASS, "not allowed"))

    if "'unsafe-eval'" in lowered:
        analysis.findings.append(
            make_finding(
                "HS-102",
                reason=f"{origin} allows 'unsafe-eval'.",
                value=f"{origin}: {' '.join(sources)}",
            )
        )
        analysis.rows.append(("'unsafe-eval'", Severity.MEDIUM, "detected"))
    else:
        analysis.rows.append(("'unsafe-eval'", Severity.PASS, "not allowed"))

    if "'unsafe-hashes'" in lowered:
        analysis.findings.append(
            make_finding(
                "HS-119",
                reason=f"{origin} allows 'unsafe-hashes', re-enabling hashed inline event handlers.",
                value=f"{origin}: {' '.join(sources)}",
            )
        )
        analysis.rows.append(("'unsafe-hashes'", Severity.LOW, "detected"))

    for token in sources:
        nonce = _nonce_of(token)
        if nonce and _nonce_is_weak(nonce):
            analysis.findings.append(
                make_finding(
                    "HS-122",
                    reason=f"Nonce {token} provides less than 128 bits of entropy or looks like a placeholder.",
                    value=token,
                )
            )
            analysis.rows.append(("Nonce entropy", Severity.MEDIUM, f"weak nonce: {token}"))
            break

    if has_nonce or has_hash:
        label = "nonce" if has_nonce else "hash"
        detail = f"{label}-based policy" + (" with 'strict-dynamic'" if analysis.strict_dynamic else "")
        analysis.rows.append(("Script policy style", Severity.PASS, detail))


def _check_style_sources(analysis: CSPAnalysis, merged: dict[str, list[str]]) -> None:
    sources, origin = _effective(merged, "style-src")
    if sources is None:
        return
    lowered = [token.lower() for token in sources]
    if "'unsafe-inline'" in lowered and not any(_NONCE_RE.match(t) or _HASH_RE.match(t) for t in sources):
        analysis.findings.append(
            make_finding(
                "HS-113",
                reason=f"{origin} allows 'unsafe-inline' for stylesheets.",
                value=f"{origin}: {' '.join(sources)}",
            )
        )
        analysis.rows.append(("'unsafe-inline' (styles)", Severity.LOW, "detected"))


def _check_wildcards(analysis: CSPAnalysis, merged: dict[str, list[str]]) -> None:
    flagged: list[str] = []
    for name, values in merged.items():
        if name not in FETCH_DIRECTIVES and name != "frame-ancestors":
            continue
        for token in values:
            lowered = token.lower()
            is_bare_wildcard = lowered == "*"
            is_broad_wildcard = lowered.startswith("*.") and lowered.count(".") <= 1
            if not (is_bare_wildcard or is_broad_wildcard):
                continue
            if name == "frame-ancestors" and is_bare_wildcard:
                analysis.findings.append(
                    make_finding(
                        "HS-117",
                        reason="frame-ancestors * allows any site to frame this page.",
                        value=f"{name}: {' '.join(values)}",
                    )
                )
                flagged.append(name)
                continue
            severity = Severity.HIGH if name in CRITICAL_WILDCARD_DIRECTIVES else Severity.MEDIUM
            analysis.findings.append(
                make_finding(
                    "HS-103",
                    severity=severity,
                    reason=f"{name} contains the wildcard source {token!r}, allowing resources from any "
                    "matching origin.",
                    value=f"{name}: {' '.join(values)}",
                )
            )
            flagged.append(name)
    if flagged:
        analysis.rows.append(("Wildcard sources", Severity.MEDIUM, ", ".join(sorted(set(flagged)))))
    else:
        analysis.rows.append(("Wildcard sources", Severity.PASS, "none detected"))


def _check_schemes(analysis: CSPAnalysis, merged: dict[str, list[str]], ctx: AnalysisContext) -> None:
    http_sources: list[str] = []
    dangerous: list[str] = []
    for name, values in merged.items():
        if name not in FETCH_DIRECTIVES and name not in {"frame-ancestors", "form-action", "base-uri"}:
            continue
        for token in values:
            lowered = token.lower()
            if lowered.startswith("http://") or lowered == "http:":
                http_sources.append(f"{name}: {token}")
            if name in {"script-src", "script-src-elem", "object-src", "default-src", "worker-src"}:
                for scheme in DANGEROUS_SCHEMES:
                    if lowered == scheme or lowered.startswith(scheme):
                        dangerous.append(f"{name}: {token}")

    if http_sources:
        analysis.findings.append(
            make_finding(
                "HS-108",
                reason="Plaintext http: sources are allowed: " + "; ".join(http_sources[:6]) + ".",
                value="; ".join(http_sources[:12]),
            )
        )
        analysis.rows.append(("Insecure http: sources", Severity.MEDIUM, f"{len(http_sources)} source(s)"))
        if "upgrade-insecure-requests" not in merged:
            analysis.findings.append(
                make_finding(
                    "HS-121",
                    reason="The policy allows http: sources but does not include upgrade-insecure-requests.",
                    value=analysis.raw,
                )
            )
    if dangerous:
        analysis.findings.append(
            make_finding(
                "HS-109",
                reason="Dangerous scheme source(s) in an executable context: " + "; ".join(sorted(set(dangerous))[:6]) + ".",
                value="; ".join(sorted(set(dangerous))[:12]),
            )
        )
        analysis.rows.append(("Dangerous schemes", Severity.HIGH, ", ".join(sorted(set(dangerous))[:3])))


def _check_missing_directives(analysis: CSPAnalysis, merged: dict[str, list[str]]) -> None:
    has_default = "default-src" in merged
    default_values = [token.lower() for token in merged.get("default-src", [])]
    default_locks_down = bool(default_values) and set(default_values) <= {"'none'", "'self'"}

    if not has_default:
        analysis.findings.append(
            make_finding("HS-107", reason="The policy has no default-src fallback directive.", value=analysis.raw)
        )
        analysis.rows.append(("default-src", Severity.MEDIUM, "missing"))
    else:
        rendered = " ".join(merged["default-src"]) or "(empty)"
        permissive = {"*", "'unsafe-inline'", "'unsafe-eval'"} & set(default_values)
        analysis.rows.append(
            (
                "default-src",
                Severity.MEDIUM if permissive else Severity.PASS,
                rendered + (" — permissive fallback" if permissive else ""),
            )
        )

    object_values, object_origin = _effective(merged, "object-src")
    object_locked = object_values is not None and [v.lower() for v in object_values] == ["'none'"]
    if object_locked:
        analysis.rows.append(("object-src", Severity.PASS, "'none' — plugin content blocked"))
    elif object_values is None or not default_locks_down:
        analysis.findings.append(
            make_finding(
                "HS-104",
                reason=(
                    "object-src is not set and default-src does not lock plugin content down."
                    if object_values is None
                    else f"object-src (via {object_origin}) is {' '.join(object_values)} instead of 'none'."
                ),
                value=analysis.raw,
            )
        )
        analysis.rows.append(("object-src", Severity.MEDIUM, "not restricted to 'none'"))
    else:
        analysis.rows.append(("object-src", Severity.PASS, f"inherited from {object_origin}"))

    if "base-uri" not in merged:
        analysis.findings.append(
            make_finding("HS-105", reason="base-uri is not set (it does not fall back to default-src).", value=analysis.raw)
        )
        analysis.rows.append(("base-uri", Severity.MEDIUM, "missing"))
    else:
        analysis.rows.append(("base-uri", Severity.PASS, " ".join(merged["base-uri"])))

    if "frame-ancestors" not in merged:
        analysis.findings.append(
            make_finding("HS-106", reason="frame-ancestors is not set, so CSP does not control framing.", value=analysis.raw)
        )
        analysis.rows.append(("frame-ancestors", Severity.MEDIUM, "missing"))
    else:
        analysis.rows.append(("frame-ancestors", Severity.PASS, " ".join(merged["frame-ancestors"])))

    if "form-action" not in merged:
        analysis.findings.append(
            make_finding("HS-114", reason="form-action is not set, so form submissions are unrestricted.", value=analysis.raw)
        )
        analysis.rows.append(("form-action", Severity.LOW, "missing"))
    else:
        analysis.rows.append(("form-action", Severity.PASS, " ".join(merged["form-action"])))


def _check_sandbox(analysis: CSPAnalysis, merged: dict[str, list[str]]) -> None:
    if "sandbox" not in merged:
        return
    tokens = {token.lower() for token in merged["sandbox"]}
    if {"allow-scripts", "allow-same-origin"} <= tokens:
        analysis.findings.append(
            make_finding(
                "HS-118",
                reason="sandbox allows both allow-scripts and allow-same-origin, which lets the content "
                "remove its own sandbox.",
                value="sandbox " + " ".join(sorted(tokens)),
            )
        )
        analysis.rows.append(("sandbox", Severity.LOW, "allow-scripts + allow-same-origin"))
    else:
        analysis.rows.append(("sandbox", Severity.PASS, " ".join(sorted(tokens)) or "(fully sandboxed)"))


def _check_reporting(analysis: CSPAnalysis, merged: dict[str, list[str]]) -> None:
    has_report_to = "report-to" in merged
    has_report_uri = "report-uri" in merged
    if not has_report_to and not has_report_uri:
        analysis.findings.append(
            make_finding("HS-112", reason="The policy defines no report-to or report-uri endpoint.", value=analysis.raw)
        )
        analysis.rows.append(("Violation reporting", Severity.INFO, "no endpoint configured"))
    elif has_report_uri and not has_report_to:
        analysis.findings.append(
            make_finding(
                "HS-120",
                reason="Only the deprecated report-uri directive is configured.",
                value=" ".join(merged.get("report-uri", [])),
            )
        )
        analysis.rows.append(("Violation reporting", Severity.INFO, "report-uri only (deprecated)"))
    else:
        analysis.rows.append(("Violation reporting", Severity.PASS, " ".join(merged.get("report-to", [])) or "configured"))


def _check_allowlist_size(analysis: CSPAnalysis) -> None:
    count = len(analysis.host_sources)
    if count > LARGE_ALLOWLIST_THRESHOLD:
        analysis.findings.append(
            make_finding(
                "HS-111",
                reason=f"The policy allow-lists {count} distinct host sources, which is difficult to audit and "
                "often contains bypassable origins.",
                value=", ".join(analysis.host_sources[:15]) + (" …" if count > 15 else ""),
                metadata={"host_count": count},
            )
        )
        analysis.rows.append(("Allow-list size", Severity.LOW, f"{count} host sources"))
    elif count:
        analysis.rows.append(("Allow-list size", Severity.PASS, f"{count} host source(s)"))


def _build_directive_rows(analysis: CSPAnalysis, merged: dict[str, list[str]]) -> None:
    """Build the per-directive table shown in the terminal and HTML report."""
    seen: set[str] = set()
    for directive in DISPLAY_ORDER:
        seen.add(directive)
        values = merged.get(directive)
        if values is None:
            inherited, origin = _effective(merged, directive)
            if inherited is not None and origin != directive:
                analysis.directive_rows.append(
                    CSPDirectiveRow(directive, " ".join(inherited), Severity.INFO, f"inherited from {origin}")
                )
            elif directive in {"base-uri", "frame-ancestors", "form-action", "object-src", "default-src"}:
                analysis.directive_rows.append(CSPDirectiveRow(directive, "—", Severity.MEDIUM, "not set"))
            continue
        rendered = " ".join(values) if values else "(empty)"
        lowered = {token.lower() for token in values}
        status = Severity.PASS
        note = "explicit policy"
        if lowered & {"'unsafe-inline'", "'unsafe-eval'"}:
            status = Severity.MEDIUM
            note = "permissive keyword"
        if "*" in lowered:
            status = Severity.HIGH if directive in CRITICAL_WILDCARD_DIRECTIVES else Severity.MEDIUM
            note = "wildcard source"
        if lowered == {"'none'"}:
            note = "blocked"
        if directive in {"upgrade-insecure-requests", "block-all-mixed-content"}:
            rendered = "enabled"
            note = "mixed-content mitigation"
        analysis.directive_rows.append(CSPDirectiveRow(directive, rendered, status, note))

    for directive, values in merged.items():
        if directive in seen:
            continue
        analysis.directive_rows.append(
            CSPDirectiveRow(
                directive,
                " ".join(values) or "(empty)",
                Severity.LOW if directive not in KNOWN_DIRECTIVES else Severity.INFO,
                "unknown directive" if directive not in KNOWN_DIRECTIVES else "additional directive",
            )
        )


def iter_policies(analysis: CSPAnalysis) -> Iterable[CSPPolicy]:
    """Yield every parsed policy (enforcing first)."""
    yield from sorted(analysis.policies, key=lambda policy: policy.report_only)
