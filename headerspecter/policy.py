"""Custom header policy support.

Organisations rarely agree on a single baseline, so HeaderSpecter lets users
describe their own in YAML (or JSON):

.. code-block:: yaml

    name: Corporate baseline
    required:
      - content-security-policy
      - strict-transport-security
    forbidden:
      - x-powered-by
    values:
      x-frame-options: [DENY, SAMEORIGIN]
      referrer-policy: "re:^(no-referrer|strict-origin.*)$"
    severity:
      HS-100: critical          # raise a specific finding
      permissions-policy: low   # or every finding about a header
    scoring:
      severity_weights:
        MEDIUM: 9
    min_score: 80

Everything is optional.  Unknown keys are ignored (with a warning) so policies
stay forward compatible.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .config import ScoringConfig
from .findings import Finding, Severity, make_finding
from .headers import HeaderBag, normalize_header_name
from .utils import HeaderSpecterError

LOGGER = logging.getLogger("headerspecter.policy")

__all__ = ["HeaderPolicy", "PolicyError", "load_policy"]

_KNOWN_KEYS = {
    "name",
    "description",
    "required",
    "forbidden",
    "optional",
    "values",
    "allowed_values",
    "severity",
    "severities",
    "scoring",
    "min_score",
}


class PolicyError(HeaderSpecterError):
    """Raised when a policy file cannot be loaded or is invalid."""


@dataclass(slots=True)
class HeaderPolicy:
    """A user supplied header baseline."""

    name: str = "default"
    description: str = ""
    required: list[str] = field(default_factory=list)
    forbidden: list[str] = field(default_factory=list)
    optional: list[str] = field(default_factory=list)
    allowed_values: dict[str, list[str]] = field(default_factory=dict)
    severity_overrides: dict[str, str] = field(default_factory=dict)
    scoring: dict[str, Any] = field(default_factory=dict)
    min_score: float | None = None
    source: Path | None = None

    # -- loading -----------------------------------------------------------
    @classmethod
    def from_mapping(cls, data: Mapping[str, Any], source: Path | None = None) -> HeaderPolicy:
        """Build a policy from an already parsed mapping."""
        if not isinstance(data, Mapping):  # pragma: no cover - defensive
            raise PolicyError("Policy file must contain a mapping at the top level")

        unknown = set(data) - _KNOWN_KEYS
        if unknown:
            LOGGER.warning("Ignoring unknown policy keys: %s", ", ".join(sorted(unknown)))

        values_section = data.get("values") or data.get("allowed_values") or {}
        allowed_values: dict[str, list[str]] = {}
        if isinstance(values_section, Mapping):
            for header, expected in values_section.items():
                key = str(header).strip().lower()
                if isinstance(expected, str):
                    allowed_values[key] = [expected]
                elif isinstance(expected, Iterable):
                    allowed_values[key] = [str(item) for item in expected]

        severity_section = data.get("severity") or data.get("severities") or {}
        severity_overrides: dict[str, str] = {}
        if isinstance(severity_section, Mapping):
            for key, value in severity_section.items():
                try:
                    severity_overrides[str(key).strip().lower()] = Severity.parse(str(value)).value
                except ValueError as exc:
                    raise PolicyError(f"Invalid severity {value!r} for {key!r} in policy") from exc

        min_score = data.get("min_score")
        return cls(
            name=str(data.get("name", source.stem if source else "custom")),
            description=str(data.get("description", "")),
            required=[str(item).strip().lower() for item in data.get("required", []) or []],
            forbidden=[str(item).strip().lower() for item in data.get("forbidden", []) or []],
            optional=[str(item).strip().lower() for item in data.get("optional", []) or []],
            allowed_values=allowed_values,
            severity_overrides=severity_overrides,
            scoring=dict(data.get("scoring", {}) or {}),
            min_score=float(min_score) if min_score is not None else None,
            source=source,
        )

    @classmethod
    def load(cls, path: str | Path) -> HeaderPolicy:
        """Load a policy from a YAML or JSON file."""
        file_path = Path(path).expanduser()
        if not file_path.exists():
            raise PolicyError(f"Policy file not found: {file_path}")
        text = file_path.read_text(encoding="utf-8")
        data: Any
        if file_path.suffix.lower() in {".json"}:
            try:
                data = json.loads(text)
            except json.JSONDecodeError as exc:
                raise PolicyError(f"Invalid JSON policy: {exc}") from exc
        else:
            try:
                import yaml
            except ImportError as exc:  # pragma: no cover - PyYAML is a dependency
                raise PolicyError(
                    "PyYAML is required to read YAML policies", hint="pip install pyyaml (or use a .json policy)"
                ) from exc
            try:
                data = yaml.safe_load(text)
            except Exception as exc:  # yaml.YAMLError and friends
                raise PolicyError(f"Invalid YAML policy: {exc}") from exc
        if data is None:
            data = {}
        return cls.from_mapping(data, source=file_path)

    # -- application -------------------------------------------------------
    def scoring_config(self, base: ScoringConfig | None = None) -> ScoringConfig:
        """Return the scoring configuration with the policy overrides merged."""
        config = base or ScoringConfig()
        if not self.scoring:
            return config
        return config.merge(self.scoring)

    def evaluate(self, bag: HeaderBag) -> list[Finding]:
        """Check the response headers against the policy."""
        findings: list[Finding] = []

        for header in self.required:
            if not bag.has(header):
                canonical = normalize_header_name(header)
                findings.append(
                    make_finding(
                        "HS-900",
                        header=header,
                        reason=f"Policy '{self.name}' requires {canonical}, which was not returned.",
                        title=f"Policy: required header missing ({canonical})",
                        severity=self.severity_overrides.get(header),
                        recommendation=f"Add the {canonical} header so the target satisfies the '{self.name}' policy.",
                    )
                )

        for header in self.forbidden:
            if bag.has(header):
                canonical = normalize_header_name(header)
                findings.append(
                    make_finding(
                        "HS-901",
                        header=header,
                        value=bag.joined(header),
                        reason=f"Policy '{self.name}' forbids {canonical}, but the response returned it.",
                        title=f"Policy: forbidden header present ({canonical})",
                        severity=self.severity_overrides.get(header),
                        recommendation=f"Strip the {canonical} header at the application or proxy layer.",
                    )
                )

        for header, expected in self.allowed_values.items():
            actual = bag.joined(header)
            if actual is None:
                continue  # covered by `required` when the policy cares
            if not _value_matches(actual, expected):
                canonical = normalize_header_name(header)
                findings.append(
                    make_finding(
                        "HS-902",
                        header=header,
                        value=actual,
                        reason=f"{canonical} is {actual!r} but policy '{self.name}' allows: "
                        + ", ".join(repr(item) for item in expected)
                        + ".",
                        title=f"Policy: unexpected value for {canonical}",
                        severity=self.severity_overrides.get(header),
                        recommendation=f"Set {canonical} to one of the approved values.",
                    )
                )

        return findings

    def apply_severity_overrides(self, findings: Iterable[Finding]) -> list[Finding]:
        """Re-map severities for findings matched by id or header name."""
        if not self.severity_overrides:
            return list(findings)
        result: list[Finding] = []
        for finding in findings:
            override = self.severity_overrides.get(finding.id.lower())
            if override is None and finding.header:
                override = self.severity_overrides.get(finding.header.lower())
            if override is not None and finding.severity is not Severity.PASS:
                finding.severity = Severity.parse(override, finding.severity)
            result.append(finding)
        return result

    def to_dict(self) -> dict[str, Any]:
        """JSON-serialisable representation."""
        return {
            "name": self.name,
            "description": self.description,
            "required": list(self.required),
            "forbidden": list(self.forbidden),
            "optional": list(self.optional),
            "values": {k: list(v) for k, v in self.allowed_values.items()},
            "severity": dict(self.severity_overrides),
            "min_score": self.min_score,
            "source": str(self.source) if self.source else None,
        }


def _value_matches(actual: str, expected: list[str]) -> bool:
    """Compare a header value against literal or ``re:`` pattern expectations."""
    normalized = " ".join(actual.split()).strip().lower()
    for item in expected:
        candidate = item.strip()
        if candidate.lower().startswith("re:"):
            pattern = candidate[3:].strip()
            try:
                if re.search(pattern, actual, re.IGNORECASE):
                    return True
            except re.error:  # pragma: no cover - invalid user pattern
                LOGGER.warning("Invalid regex in policy: %s", pattern)
            continue
        if normalized == " ".join(candidate.split()).strip().lower():
            return True
    return False


def load_policy(path: str | Path | None) -> HeaderPolicy | None:
    """Convenience wrapper: load a policy when a path is given."""
    if not path:
        return None
    return HeaderPolicy.load(path)
