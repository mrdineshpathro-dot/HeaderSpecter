"""Security scoring engine.

The model is deliberately simple and completely transparent:

1. Start from :attr:`ScoringConfig.base_score` (100 by default).
2. Every finding deducts ``severity_weight × header_multiplier`` points.
3. Deductions are capped per finding and per category so one noisy category
   cannot dominate the result.
4. A small, explicit bonus rewards hardening that goes beyond the baseline
   (HSTS preload, nonce/hash based CSP, cross-origin isolation).

Every individual deduction is preserved in :class:`ScoreResult.deductions`, so
the score can be explained line by line in any report.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from .config import GRADE_BANDS, ScoringConfig
from .findings import Finding, Severity, severity_counts

__all__ = ["ScoreDeduction", "ScoreBonus", "ScoreResult", "compute_score", "grade_for"]


@dataclass(slots=True)
class ScoreDeduction:
    """One line of the score breakdown."""

    finding_id: str
    title: str
    severity: str
    category: str
    header: str | None
    raw_points: float
    applied_points: float
    capped: bool = False

    def to_dict(self) -> dict[str, Any]:
        """JSON-serialisable representation."""
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "severity": self.severity,
            "category": self.category,
            "header": self.header,
            "raw_points": round(self.raw_points, 2),
            "applied_points": round(self.applied_points, 2),
            "capped": self.capped,
        }


@dataclass(slots=True)
class ScoreBonus:
    """One awarded bonus."""

    key: str
    reason: str
    points: float

    def to_dict(self) -> dict[str, Any]:
        """JSON-serialisable representation."""
        return {"key": self.key, "reason": self.reason, "points": round(self.points, 2)}


@dataclass(slots=True)
class ScoreResult:
    """Outcome of the scoring engine."""

    score: float
    base_score: float
    grade: str
    grade_style: str
    deductions: list[ScoreDeduction] = field(default_factory=list)
    bonuses: list[ScoreBonus] = field(default_factory=list)
    category_totals: dict[str, float] = field(default_factory=dict)
    counts: dict[str, int] = field(default_factory=dict)

    @property
    def total_deducted(self) -> float:
        """Sum of all applied deductions."""
        return round(sum(item.applied_points for item in self.deductions), 2)

    @property
    def total_bonus(self) -> float:
        """Sum of all awarded bonuses."""
        return round(sum(item.points for item in self.bonuses), 2)

    def bar(self, width: int = 24, filled: str = "█", empty: str = "░") -> str:
        """Render a plain-text score bar."""
        blocks = int(round((self.score / 100.0) * width))
        blocks = max(0, min(width, blocks))
        return filled * blocks + empty * (width - blocks)

    def to_dict(self) -> dict[str, Any]:
        """JSON-serialisable representation."""
        return {
            "score": round(self.score, 1),
            "base_score": self.base_score,
            "grade": self.grade,
            "total_deducted": self.total_deducted,
            "total_bonus": self.total_bonus,
            "counts": dict(self.counts),
            "category_totals": {k: round(v, 2) for k, v in self.category_totals.items()},
            "deductions": [item.to_dict() for item in self.deductions],
            "bonuses": [item.to_dict() for item in self.bonuses],
        }


def grade_for(score: float) -> tuple[str, str]:
    """Return ``(grade, rich_style)`` for a numeric score."""
    for minimum, grade, style in GRADE_BANDS:
        if score >= minimum:
            return grade, style
    return "F", "bold bright_red"  # pragma: no cover - GRADE_BANDS ends at 0


def compute_score(
    findings: Iterable[Finding],
    config: ScoringConfig | None = None,
    bonus_flags: Mapping[str, bool] | None = None,
) -> ScoreResult:
    """Score a set of findings.

    ``bonus_flags`` may contain ``hsts_preload``, ``csp_nonce_or_hash`` and
    ``cross_origin_isolated`` booleans; each awards the configured bonus.
    """
    cfg = config or ScoringConfig()
    findings = list(findings)
    deductions: list[ScoreDeduction] = []
    category_totals: dict[str, float] = {}

    # Worst findings first so that per-category caps keep the important ones.
    for finding in sorted(findings, key=lambda f: (f.severity.rank, f.id)):
        if finding.severity is Severity.PASS:
            continue
        raw = cfg.weight_for(finding.severity.value, finding.header)
        if raw <= 0:
            continue
        cap = cfg.category_caps.get(finding.category)
        used = category_totals.get(finding.category, 0.0)
        applied = raw
        capped = False
        if cap is not None:
            remaining = max(0.0, cap - used)
            if raw > remaining:
                applied = remaining
                capped = True
        category_totals[finding.category] = used + applied
        deductions.append(
            ScoreDeduction(
                finding_id=finding.id,
                title=finding.title,
                severity=finding.severity.value,
                category=finding.category,
                header=finding.header,
                raw_points=raw,
                applied_points=applied,
                capped=capped,
            )
        )

    bonuses: list[ScoreBonus] = []
    flags = dict(bonus_flags or {})
    bonus_reasons = {
        "hsts_preload": "HSTS policy requests preloading",
        "csp_nonce_or_hash": "CSP uses nonces or hashes instead of 'unsafe-inline'",
        "cross_origin_isolated": "Document is cross-origin isolated (COOP + COEP)",
    }
    for key, awarded in flags.items():
        if not awarded:
            continue
        points = cfg.bonus_points.get(key, 0.0)
        if points:
            bonuses.append(ScoreBonus(key, bonus_reasons.get(key, key), points))

    total_bonus = min(sum(item.points for item in bonuses), cfg.max_bonus)
    total_deducted = sum(item.applied_points for item in deductions)
    score = cfg.base_score - total_deducted + total_bonus
    score = max(0.0, min(cfg.base_score, score))
    grade, style = grade_for(score)

    return ScoreResult(
        score=round(score, 1),
        base_score=cfg.base_score,
        grade=grade,
        grade_style=style,
        deductions=deductions,
        bonuses=bonuses,
        category_totals=category_totals,
        counts=severity_counts(findings),
    )
