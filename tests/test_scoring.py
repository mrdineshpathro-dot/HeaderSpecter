"""Tests for the scoring engine and the policy overrides that feed it."""

from __future__ import annotations

from headerspecter.config import ScoringConfig
from headerspecter.findings import Severity, make_finding
from headerspecter.policy import HeaderPolicy
from headerspecter.scoring import compute_score, grade_for


def finding(check_id: str, severity: Severity | None = None, header: str | None = None):
    """Small helper to build a finding for the scoring tests."""
    return make_finding(check_id, reason="test", severity=severity, header=header)


def test_perfect_score_without_findings():
    result = compute_score([])
    assert result.score == 100.0
    assert result.grade == "A+"
    assert result.deductions == []


def test_deduction_uses_severity_weight_and_header_multiplier():
    config = ScoringConfig()
    result = compute_score([finding("HS-100")], config)  # HIGH, content-security-policy
    expected = config.severity_weights["HIGH"] * config.header_multipliers["content-security-policy"]
    assert result.deductions[0].applied_points == expected
    assert result.score == round(100 - expected, 1)


def test_pass_findings_do_not_deduct():
    result = compute_score([make_finding("HS-100", reason="ok", severity=Severity.PASS)])
    assert result.score == 100.0
    assert result.counts["PASS"] == 1


def test_category_cap_limits_noisy_categories():
    config = ScoringConfig()
    config.category_caps["cookies"] = 10.0
    findings = [finding("HS-400", header="set-cookie") for _ in range(10)]
    result = compute_score(findings, config)
    assert sum(item.applied_points for item in result.deductions) == 10.0
    assert any(item.capped for item in result.deductions)


def test_score_never_drops_below_zero():
    config = ScoringConfig(category_caps={})  # no per-category caps
    findings = [finding("HS-100") for _ in range(50)]
    result = compute_score(findings, config)
    assert result.score == 0.0
    assert result.grade == "F"


def test_category_caps_bound_the_total_deduction():
    # With the default caps, CSP issues alone cannot cost more than the cap.
    config = ScoringConfig()
    result = compute_score([finding("HS-100") for _ in range(50)], config)
    assert result.category_totals["csp"] == config.category_caps["csp"]


def test_bonus_points_are_awarded_and_capped():
    result = compute_score(
        [],
        ScoringConfig(),
        bonus_flags={"hsts_preload": True, "csp_nonce_or_hash": True, "cross_origin_isolated": True},
    )
    # No deductions, so the score is already at the maximum.
    assert result.score == 100.0
    assert result.total_bonus > 0

    with_issue = compute_score(
        [finding("HS-230")],
        ScoringConfig(),
        bonus_flags={"hsts_preload": True},
    )
    assert with_issue.total_bonus == ScoringConfig().bonus_points["hsts_preload"]


def test_severity_weights_are_configurable():
    weights = {"HIGH": 20.0, "MEDIUM": 0.0, "LOW": 0.0, "INFO": 0.0, "CRITICAL": 0.0, "PASS": 0.0}
    config = ScoringConfig(severity_weights=weights)
    result = compute_score([finding("HS-100")], config)
    assert result.deductions[0].raw_points == 20.0 * config.header_multipliers["content-security-policy"]


def test_single_finding_deduction_is_capped():
    config = ScoringConfig(
        severity_weights={"HIGH": 500.0, "MEDIUM": 0.0, "LOW": 0.0, "INFO": 0.0, "CRITICAL": 0.0, "PASS": 0.0},
        max_deduction_per_finding=30.0,
    )
    result = compute_score([finding("HS-100")], config)
    assert result.deductions[0].raw_points == 30.0


def test_worst_findings_are_scored_first():
    config = ScoringConfig()
    config.category_caps["csp"] = 16.0
    findings = [finding("HS-112"), finding("HS-100")]  # INFO then HIGH
    result = compute_score(findings, config)
    assert result.deductions[0].severity == "HIGH"


def test_grades_cover_the_bands():
    assert grade_for(100)[0] == "A+"
    assert grade_for(92)[0] == "A"
    assert grade_for(85)[0] == "B"
    assert grade_for(75)[0] == "C"
    assert grade_for(65)[0] == "D"
    assert grade_for(45)[0] == "E"
    assert grade_for(10)[0] == "F"


def test_score_bar_length():
    result = compute_score([])
    assert len(result.bar(20)) == 20
    assert result.bar(20).count("█") == 20
    zero = compute_score([finding("HS-100") for _ in range(20)], ScoringConfig(category_caps={}))
    assert zero.score == 0.0
    assert zero.bar(10).count("░") == 10


def test_score_dict_is_serialisable():
    import json

    result = compute_score([finding("HS-100"), finding("HS-230")])
    payload = json.loads(json.dumps(result.to_dict()))
    assert payload["grade"] == result.grade
    assert len(payload["deductions"]) == 2


def test_policy_scoring_overrides_are_merged():
    policy = HeaderPolicy.from_mapping(
        {"name": "test", "scoring": {"severity_weights": {"HIGH": 40}, "category_caps": {"csp": 5}}}
    )
    config = policy.scoring_config()
    assert config.severity_weights["HIGH"] == 40.0
    assert config.category_caps["csp"] == 5.0
    result = compute_score([finding("HS-100")], config)
    assert result.deductions[0].applied_points == 5.0  # capped by the category limit


def test_end_to_end_scores_reflect_posture(strong_result, weak_result, empty_result):
    assert strong_result.score is not None and strong_result.score >= 90
    assert strong_result.grade in {"A+", "A"}
    assert weak_result.score is not None and weak_result.score < 40
    assert empty_result.score is not None
    assert weak_result.score < empty_result.score or empty_result.score < 70
