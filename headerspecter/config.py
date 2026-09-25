"""Central configuration objects and tunable defaults for HeaderSpecter.

Everything that influences scanning behaviour or scoring lives here as a typed
dataclass so it can be overridden from the CLI or from a user supplied policy
file.  No "magic numbers" are hidden inside the analyzers: every deduction the
scoring engine applies is derived from :class:`ScoringConfig`.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from typing import Any

from . import APP_NAME, AUTHOR, AUTHOR_URL, PROJECT_URL, TAGLINE, __version__

__all__ = [
    "APP_NAME",
    "AUTHOR",
    "AUTHOR_URL",
    "PROJECT_URL",
    "TAGLINE",
    "DEFAULT_USER_AGENT",
    "ScanConfig",
    "ScoringConfig",
    "OutputConfig",
    "GRADE_BANDS",
]

#: Default browser-like User-Agent.  Looking like a normal browser gives the
#: most representative set of response headers (some CDNs vary on UA).
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/125.0.0.0 Safari/537.36 HeaderSpecter/" + __version__
)

#: Origin value used for the (passive) CORS reflection probe.
DEFAULT_PROBE_ORIGIN = "https://headerspecter.invalid"

#: Sensible request headers sent with every scan.
DEFAULT_REQUEST_HEADERS: dict[str, str] = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Cache-Control": "no-cache",
    "Pragma": "no-cache",
}


@dataclass(slots=True)
class ScanConfig:
    """Runtime knobs for the network layer."""

    timeout: float = 15.0
    """Per-request timeout in seconds."""

    retries: int = 2
    """How many times a failed request is retried (transport errors only)."""

    retry_backoff: float = 0.6
    """Base seconds for exponential backoff between retries."""

    concurrency: int = 10
    """Maximum number of targets scanned in parallel during batch runs."""

    delay: float = 0.0
    """Polite delay (seconds) inserted before each request in batch mode."""

    proxy: str | None = None
    """Proxy URL, e.g. ``http://127.0.0.1:8080`` for Burp Suite / ZAP."""

    user_agent: str = DEFAULT_USER_AGENT

    method: str = "GET"
    """HTTP method used for the main request."""

    follow_redirects: bool = True

    max_redirects: int = 10

    verify_tls: bool = False
    """Whether httpx should reject invalid certificates.

    Default is ``False`` so that a broken certificate still yields a full
    header analysis; the dedicated TLS analyzer performs *strict* validation
    separately and reports the failure as a finding.
    """

    extra_probes: bool = True
    """Send the two optional passive probes (CORS ``Origin`` + HTTP upgrade)."""

    probe_origin: str = DEFAULT_PROBE_ORIGIN

    tls_probe: bool = True
    """Perform the TLS certificate / protocol inspection for HTTPS targets."""

    extra_headers: dict[str, str] = field(default_factory=dict)
    """Additional request headers supplied with ``-H/--header``."""

    http2: bool = True
    """Negotiate HTTP/2 when the optional ``h2`` package is installed."""

    cert_expiry_warning_days: int = 30
    """Certificate lifetime below which a warning finding is raised."""

    def with_overrides(self, **kwargs: Any) -> ScanConfig:
        """Return a copy of this config with ``kwargs`` applied."""
        return replace(self, **{k: v for k, v in kwargs.items() if v is not None})


@dataclass(slots=True)
class ScoringConfig:
    """Transparent, fully configurable scoring model.

    The score starts at :attr:`base_score` and every finding subtracts

        ``severity_weights[severity] * header_multipliers.get(header, 1.0)``

    points (capped by :attr:`max_deduction_per_finding`).  Deductions are
    additionally capped per category so that, e.g., twenty insecure cookies
    cannot alone push a site to zero.  The scoring breakdown is always
    rendered/exported, so a score can be audited line by line.
    """

    base_score: float = 100.0

    severity_weights: dict[str, float] = field(
        default_factory=lambda: {
            "CRITICAL": 28.0,
            "HIGH": 15.0,
            "MEDIUM": 7.0,
            "LOW": 3.0,
            "INFO": 0.5,
            "PASS": 0.0,
        }
    )

    header_multipliers: dict[str, float] = field(
        default_factory=lambda: {
            "content-security-policy": 1.25,
            "strict-transport-security": 1.20,
            "x-content-type-options": 1.00,
            "x-frame-options": 1.00,
            "referrer-policy": 0.90,
            "permissions-policy": 0.85,
            "set-cookie": 1.00,
            "access-control-allow-origin": 1.10,
            "cross-origin-opener-policy": 0.80,
            "cross-origin-resource-policy": 0.80,
            "cross-origin-embedder-policy": 0.70,
            "server": 0.60,
            "x-powered-by": 0.60,
        }
    )

    category_caps: dict[str, float] = field(
        default_factory=lambda: {
            "csp": 32.0,
            "cookies": 24.0,
            "cors": 28.0,
            "transport": 30.0,
            "tls": 30.0,
            "framing": 18.0,
            "content": 12.0,
            "referrer": 10.0,
            "permissions": 12.0,
            "cross-origin": 12.0,
            "disclosure": 8.0,
            "deprecated": 6.0,
            "caching": 6.0,
            "redirects": 18.0,
            "response": 6.0,
            "policy": 40.0,
        }
    )

    max_deduction_per_finding: float = 30.0

    bonus_points: dict[str, float] = field(
        default_factory=lambda: {
            # Small, explicit rewards for going beyond the baseline.
            "hsts_preload": 1.5,
            "csp_nonce_or_hash": 2.0,
            "cross_origin_isolated": 1.5,
        }
    )

    max_bonus: float = 4.0

    def weight_for(self, severity: str, header: str | None) -> float:
        """Return the raw point deduction for ``severity`` on ``header``."""
        base = self.severity_weights.get(severity.upper(), 0.0)
        multiplier = 1.0
        if header:
            multiplier = self.header_multipliers.get(header.strip().lower(), 1.0)
        return min(base * multiplier, self.max_deduction_per_finding)

    def merge(self, data: Mapping[str, Any]) -> ScoringConfig:
        """Return a new config with values from a policy file merged in."""
        merged = ScoringConfig(
            base_score=float(data.get("base_score", self.base_score)),
            severity_weights=dict(self.severity_weights),
            header_multipliers=dict(self.header_multipliers),
            category_caps=dict(self.category_caps),
            max_deduction_per_finding=float(
                data.get("max_deduction_per_finding", self.max_deduction_per_finding)
            ),
            bonus_points=dict(self.bonus_points),
            max_bonus=float(data.get("max_bonus", self.max_bonus)),
        )
        for key, target in (
            ("severity_weights", merged.severity_weights),
            ("header_multipliers", merged.header_multipliers),
            ("category_caps", merged.category_caps),
            ("bonus_points", merged.bonus_points),
        ):
            section = data.get(key)
            if isinstance(section, Mapping):
                for name, value in section.items():
                    try:
                        target[str(name).lower() if key != "severity_weights" else str(name).upper()] = float(value)
                    except (TypeError, ValueError):  # pragma: no cover - defensive
                        continue
        return merged


#: Letter grades.  ``(minimum score, grade, rich style)``.
GRADE_BANDS: tuple[tuple[float, str, str], ...] = (
    (95.0, "A+", "bold bright_green"),
    (90.0, "A", "bold green"),
    (80.0, "B", "bold green3"),
    (70.0, "C", "bold yellow"),
    (60.0, "D", "bold dark_orange"),
    (40.0, "E", "bold red"),
    (0.0, "F", "bold bright_red"),
)


@dataclass(slots=True)
class OutputConfig:
    """Which sections the terminal reporter should render."""

    show_response: bool = True
    show_score: bool = True
    show_headers: bool = True
    show_findings: bool = True
    show_csp: bool = True
    show_hsts: bool = True
    show_cookies: bool = True
    show_cors: bool = True
    show_tls: bool = True
    show_redirects: bool = True
    show_disclosure: bool = True
    show_recommendations: bool = True
    show_raw: bool = False
    verbose_findings: bool = False
    max_findings: int = 0  # 0 == unlimited

    @classmethod
    def only(cls, **sections: bool) -> OutputConfig:
        """Build a config with every section disabled except those given."""
        cfg = cls(
            show_response=False,
            show_score=False,
            show_headers=False,
            show_findings=False,
            show_csp=False,
            show_hsts=False,
            show_cookies=False,
            show_cors=False,
            show_tls=False,
            show_redirects=False,
            show_disclosure=False,
            show_recommendations=False,
        )
        for name, value in sections.items():
            setattr(cfg, name, value)
        return cfg
