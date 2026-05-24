"""Tests for verdict calculation."""

from nyuwaymcpsandbox.detection.engine import Finding
from nyuwaymcpsandbox.detection.verdict import (
    SEVERITY_FLOORS,
    VERDICT_MESSAGES,
    VERDICT_RANGES,
    calculate_verdict,
)


def _finding(severity: str, weight: int, rule_id: str = "r") -> Finding:
    return Finding(
        rule_id=rule_id,
        title=f"Test {rule_id}",
        severity=severity,
        weight=weight,
        category="test",
        description="",
        recommendation="",
    )


# ── Basic tiers ──────────────────────────────────────────────────────────


def test_empty_findings_returns_pass():
    v = calculate_verdict([])
    assert v.score == 0
    assert v.tier == "PASS"
    assert v.finding_count == 0
    assert v.severity_breakdown == {"critical": 0, "high": 0, "medium": 0, "low": 0}


def test_single_low_finding_within_low_tier():
    v = calculate_verdict([_finding("low", 20)])
    assert v.score == 20
    assert v.tier == "LOW"


def test_two_low_findings_sum_to_medium():
    v = calculate_verdict([_finding("low", 20), _finding("low", 20)])
    assert v.score == 40
    assert v.tier == "MEDIUM"


def test_one_medium_finding_in_medium_tier():
    v = calculate_verdict([_finding("medium", 45)])
    assert v.score == 45
    assert v.tier == "MEDIUM"


def test_one_high_finding_in_high_tier():
    v = calculate_verdict([_finding("high", 65)])
    assert v.score == 65
    assert v.tier == "HIGH"


# ── Critical severity floor ──────────────────────────────────────────────


def test_single_critical_finding_floored_to_high_minimum():
    """A critical finding with a small weight must still produce HIGH."""
    v = calculate_verdict([_finding("critical", 10)])
    assert v.score == 60  # floor
    assert v.tier == "HIGH"


def test_critical_floor_does_not_override_higher_weight_sum():
    """If the weight sum exceeds the floor, the sum wins."""
    v = calculate_verdict([_finding("critical", 75)])
    assert v.score == 75
    assert v.tier == "HIGH"


def test_multiple_criticals_can_push_into_critical_tier():
    v = calculate_verdict([_finding("critical", 35), _finding("critical", 35)])
    assert v.score == 70
    assert v.tier == "HIGH"
    v3 = calculate_verdict([_finding("critical", 35) for _ in range(3)])
    assert v3.score == 100  # capped
    assert v3.tier == "CRITICAL"


def test_floor_applies_only_when_critical_present():
    """Many lows summing to 30 must remain LOW, not get boosted."""
    v = calculate_verdict([_finding("low", 10), _finding("low", 10), _finding("low", 10)])
    assert v.score == 30
    assert v.tier == "LOW"


# ── Score cap ────────────────────────────────────────────────────────────


def test_score_capped_at_100():
    findings = [_finding("high", 35) for _ in range(5)]  # would be 175
    v = calculate_verdict(findings)
    assert v.score == 100
    assert v.tier == "CRITICAL"


def test_score_exactly_at_100_is_critical():
    v = calculate_verdict([_finding("high", 50), _finding("high", 50)])
    assert v.score == 100
    assert v.tier == "CRITICAL"


# ── Tier boundaries ──────────────────────────────────────────────────────


def test_score_at_pass_high_boundary_19_is_pass():
    v = calculate_verdict([_finding("low", 19)])
    assert v.tier == "PASS"


def test_score_at_low_low_boundary_20_is_low():
    v = calculate_verdict([_finding("low", 20)])
    assert v.tier == "LOW"


def test_score_at_high_low_boundary_60_is_high():
    v = calculate_verdict([_finding("high", 60)])
    assert v.tier == "HIGH"


def test_score_at_critical_low_boundary_80_is_critical():
    v = calculate_verdict([_finding("high", 35), _finding("high", 35), _finding("medium", 10)])
    assert v.score == 80
    assert v.tier == "CRITICAL"


# ── Severity breakdown ───────────────────────────────────────────────────


def test_severity_breakdown_counts_each_finding():
    findings = [
        _finding("critical", 30, "a"),
        _finding("high", 20, "b"),
        _finding("high", 15, "c"),
        _finding("medium", 10, "d"),
    ]
    v = calculate_verdict(findings)
    assert v.severity_breakdown == {"critical": 1, "high": 2, "medium": 1, "low": 0}
    assert v.finding_count == 4


def test_unknown_severity_does_not_contribute_floor_or_raise():
    """Defensive: a typo'd severity must not crash the calculator."""
    v = calculate_verdict([_finding("urgent", 10)])
    assert v.score == 10  # no floor applied
    assert v.tier == "PASS"
    # The unknown severity is still counted in the breakdown.
    assert v.severity_breakdown.get("urgent") == 1


# ── Serialization ────────────────────────────────────────────────────────


def test_to_dict_round_trips_fields():
    v = calculate_verdict([_finding("high", 65)])
    d = v.to_dict()
    assert d["score"] == 65
    assert d["tier"] == "HIGH"
    assert d["finding_count"] == 1
    assert "message" in d
    assert d["severity_breakdown"]["high"] == 1


def test_verdict_message_matches_tier():
    """Every tier resolves to its own canonical message."""
    cases = [
        ([], "PASS"),
        ([_finding("low", 25)], "LOW"),
        ([_finding("medium", 45)], "MEDIUM"),
        ([_finding("high", 65)], "HIGH"),
        ([_finding("critical", 35), _finding("critical", 35), _finding("medium", 15)], "CRITICAL"),
    ]
    for findings, expected_tier in cases:
        v = calculate_verdict(findings)
        assert v.tier == expected_tier
        assert v.message == VERDICT_MESSAGES[expected_tier]


# ── Constants sanity ─────────────────────────────────────────────────────


def test_verdict_ranges_cover_0_to_100_without_gaps():
    """Every score 0..100 must fall into exactly one tier."""
    covered = [False] * 101
    for _, lo, hi in VERDICT_RANGES:
        for s in range(lo, hi + 1):
            assert not covered[s], f"score {s} covered by multiple tiers"
            covered[s] = True
    assert all(covered), "tier ranges leave gaps"


def test_severity_floors_known_keys():
    """The floor table must list every severity the engine emits."""
    assert set(SEVERITY_FLOORS.keys()) >= {"critical", "high", "medium", "low"}
