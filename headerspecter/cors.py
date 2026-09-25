"""CORS (Cross-Origin Resource Sharing) analyzer.

HeaderSpecter evaluates the CORS headers returned by the target and — when the
passive probe is enabled — whether the server blindly reflects an arbitrary
``Origin`` request header.  The probe is a single, ordinary GET request with an
``Origin`` header; nothing is exploited, no credentials are supplied and no
authentication is bypassed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .findings import Finding, Severity, make_finding
from .headers import AnalysisContext, HeaderBag, HeaderCheck

__all__ = ["CORSAnalysis", "analyze_cors", "UNSAFE_METHODS"]

#: Methods that change state and therefore deserve a closer look when exposed.
UNSAFE_METHODS: frozenset[str] = frozenset({"PUT", "PATCH", "DELETE", "TRACE", "CONNECT"})


@dataclass(slots=True)
class CORSAnalysis:
    """Aggregated CORS posture for a scanned response."""

    present: bool = False
    allow_origin: str | None = None
    allow_credentials: bool = False
    allow_methods: list[str] = field(default_factory=list)
    allow_headers: list[str] = field(default_factory=list)
    expose_headers: list[str] = field(default_factory=list)
    max_age: int | None = None
    vary_origin: bool = False
    reflects_origin: bool = False
    probe_origin: str | None = None
    probe_performed: bool = False
    rows: list[tuple[str, Severity, str]] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    check: HeaderCheck | None = None

    def to_dict(self) -> dict[str, Any]:
        """JSON-serialisable representation."""
        return {
            "present": self.present,
            "allow_origin": self.allow_origin,
            "allow_credentials": self.allow_credentials,
            "allow_methods": list(self.allow_methods),
            "allow_headers": list(self.allow_headers),
            "expose_headers": list(self.expose_headers),
            "max_age": self.max_age,
            "vary_origin": self.vary_origin,
            "reflects_origin": self.reflects_origin,
            "probe_origin": self.probe_origin,
            "probe_performed": self.probe_performed,
            "checks": [
                {"label": label, "status": status.value, "detail": detail} for label, status, detail in self.rows
            ],
        }


def _split_list(value: str | None) -> list[str]:
    if not value:
        return []
    return [token.strip() for token in value.split(",") if token.strip()]


def analyze_cors(
    bag: HeaderBag,
    ctx: AnalysisContext,
    probe_headers: HeaderBag | None = None,
) -> CORSAnalysis:
    """Analyse CORS headers, optionally including the ``Origin`` probe response.

    ``probe_headers`` are the headers of a second request that carried an
    ``Origin`` header (see :mod:`headerspecter.scanner`).  When supplied, origin
    reflection can be detected reliably.
    """
    analysis = CORSAnalysis()
    source = probe_headers if probe_headers is not None and probe_headers.has("access-control-allow-origin") else bag
    analysis.probe_performed = probe_headers is not None
    analysis.probe_origin = ctx.probe_origin or None

    acao_values = source.get_all("access-control-allow-origin")
    analysis.allow_origin = acao_values[0] if acao_values else None
    analysis.allow_credentials = (source.get("access-control-allow-credentials") or "").strip().lower() == "true"
    analysis.allow_methods = _split_list(source.joined("access-control-allow-methods"))
    analysis.allow_headers = _split_list(source.joined("access-control-allow-headers"))
    analysis.expose_headers = _split_list(source.joined("access-control-expose-headers"))
    vary_tokens = {token.strip().lower() for token in _split_list(source.joined("vary"))}
    analysis.vary_origin = "origin" in vary_tokens
    try:
        analysis.max_age = int((source.get("access-control-max-age") or "").strip())
    except ValueError:
        analysis.max_age = None

    analysis.present = bool(
        acao_values
        or analysis.allow_methods
        or analysis.allow_headers
        or analysis.expose_headers
        or analysis.allow_credentials
    )

    if not analysis.present:
        analysis.rows.append(("CORS headers", Severity.PASS, "none returned — resource is same-origin only"))
        analysis.check = HeaderCheck(
            "Access-Control-Allow-Origin", Severity.PASS, "PASS", None, "No cross-origin sharing configured"
        )
        return analysis

    origin_value = (analysis.allow_origin or "").strip()
    lowered = origin_value.lower()
    probe = (ctx.probe_origin or "").strip().lower()
    analysis.reflects_origin = bool(probe) and lowered == probe

    if len(acao_values) > 1 or ("," in origin_value) or (" " in origin_value.strip() and origin_value.strip() != "*"):
        analysis.findings.append(
            make_finding(
                "HS-315",
                reason=f"Access-Control-Allow-Origin contains more than one value: {', '.join(acao_values)}.",
                value=", ".join(acao_values),
            )
        )
        analysis.rows.append(("Allow-Origin syntax", Severity.LOW, "multiple values returned"))

    if lowered == "*":
        if analysis.allow_credentials:
            analysis.findings.append(
                make_finding(
                    "HS-311",
                    reason="Access-Control-Allow-Origin is '*' while Access-Control-Allow-Credentials is true.",
                    value=f"{origin_value} + credentials",
                )
            )
            analysis.rows.append(("Allow-Origin", Severity.HIGH, "* with credentials — invalid and unsafe"))
        else:
            analysis.findings.append(
                make_finding(
                    "HS-310",
                    reason="Access-Control-Allow-Origin is '*', so any website can read this response.",
                    value=origin_value,
                )
            )
            analysis.rows.append(("Allow-Origin", Severity.MEDIUM, "* (any origin may read the response)"))
    elif lowered == "null":
        analysis.findings.append(
            make_finding(
                "HS-314",
                reason="Access-Control-Allow-Origin is 'null', which sandboxed frames and local files can forge.",
                value=origin_value,
            )
        )
        analysis.rows.append(("Allow-Origin", Severity.HIGH, "null origin allowed"))
    elif analysis.reflects_origin:
        if analysis.allow_credentials:
            analysis.findings.append(
                make_finding(
                    "HS-312",
                    reason=f"The server reflected the probe origin {ctx.probe_origin} and allows credentials, so any "
                    "site could read authenticated responses.",
                    value=f"{origin_value} + credentials",
                )
            )
            analysis.rows.append(("Allow-Origin", Severity.HIGH, "arbitrary origin reflected with credentials"))
        else:
            analysis.findings.append(
                make_finding(
                    "HS-313",
                    reason=f"The server reflected the arbitrary probe origin {ctx.probe_origin} without validation.",
                    value=origin_value,
                )
            )
            analysis.rows.append(("Allow-Origin", Severity.MEDIUM, "arbitrary origin reflected"))
    elif origin_value:
        analysis.rows.append(("Allow-Origin", Severity.PASS, f"{origin_value} (explicit origin)"))

    if analysis.allow_credentials:
        severity = Severity.PASS if origin_value and lowered not in {"*", "null"} and not analysis.reflects_origin else Severity.MEDIUM
        analysis.rows.append(
            (
                "Allow-Credentials",
                severity,
                "true — responses are readable by the allowed origin with cookies attached",
            )
        )

    if analysis.allow_methods:
        methods = {method.strip().upper() for method in analysis.allow_methods}
        if "*" in methods or (methods & UNSAFE_METHODS):
            analysis.findings.append(
                make_finding(
                    "HS-316",
                    reason="Cross-origin callers may use "
                    + (", ".join(sorted(methods & UNSAFE_METHODS)) if methods & UNSAFE_METHODS else "any method (*)")
                    + ".",
                    value=", ".join(analysis.allow_methods),
                )
            )
            analysis.rows.append(("Allow-Methods", Severity.LOW, ", ".join(sorted(methods))))
        else:
            analysis.rows.append(("Allow-Methods", Severity.PASS, ", ".join(sorted(methods))))

    if analysis.allow_headers:
        if any(header.strip() == "*" for header in analysis.allow_headers):
            analysis.findings.append(
                make_finding(
                    "HS-317",
                    reason="Access-Control-Allow-Headers is '*', allowing any custom request header cross-origin.",
                    value=", ".join(analysis.allow_headers),
                )
            )
            analysis.rows.append(("Allow-Headers", Severity.LOW, "* (any request header)"))
        else:
            analysis.rows.append(("Allow-Headers", Severity.PASS, ", ".join(analysis.allow_headers)))

    if analysis.expose_headers:
        severity = Severity.INFO
        analysis.findings.append(
            make_finding(
                "HS-319",
                reason="Response headers exposed to cross-origin scripts: " + ", ".join(analysis.expose_headers) + ".",
                value=", ".join(analysis.expose_headers),
            )
        )
        analysis.rows.append(("Expose-Headers", severity, ", ".join(analysis.expose_headers)))

    dynamic_origin = analysis.reflects_origin or (bool(origin_value) and lowered not in {"*", "null"})
    if dynamic_origin and not analysis.vary_origin:
        analysis.findings.append(
            make_finding(
                "HS-318",
                reason="The allowed origin depends on the request but the response does not include Vary: Origin, "
                "so caches may reuse it for other origins.",
                value=origin_value,
            )
        )
        analysis.rows.append(("Vary: Origin", Severity.LOW, "missing on a dynamic CORS response"))
    elif analysis.vary_origin:
        analysis.rows.append(("Vary: Origin", Severity.PASS, "present"))

    if analysis.max_age is not None:
        analysis.rows.append(("Max-Age", Severity.INFO, f"{analysis.max_age} s preflight cache"))

    worst = Severity.PASS
    for _, status, _ in analysis.rows:
        if status.rank < worst.rank:
            worst = status
    analysis.check = HeaderCheck(
        "Access-Control-Allow-Origin",
        worst,
        {
            Severity.CRITICAL: "CRITICAL",
            Severity.HIGH: "FAIL",
            Severity.MEDIUM: "WARNING",
            Severity.LOW: "WEAK",
            Severity.INFO: "INFO",
            Severity.PASS: "PASS",
        }[worst],
        analysis.allow_origin,
        "Cross-origin sharing enabled",
    )
    return analysis
