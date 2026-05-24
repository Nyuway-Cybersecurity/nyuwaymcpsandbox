"""Verdict calculation - turns Findings into a final score + tier.

Scoring model (from the v1 product spec):

    score = min(100, max(sum_of_finding_weights, severity_floor))

Severity floor: a single CRITICAL finding raises the score to at least 60
(HIGH tier). Without this floor, a critical finding with a small weight
could fall into LOW or MEDIUM purely from arithmetic - which would
misrepresent the actual risk of an observed critical behaviour.

Tier ranges:

    PASS      0  – 19   Deploy.
    LOW      20 – 39   Deploy with monitoring.
    MEDIUM   40 – 59   Review before deployment.
    HIGH     60 – 79   Block deployment.
    CRITICAL 80 – 100  Do not deploy.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from nyuwaymcpsandbox.detection.engine import Finding

# Tier ranges, ordered low to high. Inclusive on both ends.
VERDICT_RANGES: tuple[tuple[str, int, int], ...] = (
    ("PASS", 0, 19),
    ("LOW", 20, 39),
    ("MEDIUM", 40, 59),
    ("HIGH", 60, 79),
    ("CRITICAL", 80, 100),
)

# Per-severity floor on the final score. A single finding at this severity
# guarantees the score is at least this value.
SEVERITY_FLOORS: dict[str, int] = {
    "critical": 60,  # any critical finding forces verdict >= HIGH
    "high": 0,
    "medium": 0,
    "low": 0,
}

VERDICT_MESSAGES: dict[str, str] = {
    "PASS": "Deploy. No suspicious behaviour observed during detonation.",
    "LOW": "Deploy with monitoring. Minor signals warrant a casual review.",
    "MEDIUM": "Review before deployment. Multiple signals require analyst attention.",
    "HIGH": "Block deployment. Behavioural evidence suggests intent or capability for malicious activity.",
    "CRITICAL": "DO NOT DEPLOY. Server demonstrated active malicious behaviour under controlled testing.",
}


@dataclass
class Verdict:
    """Final risk verdict over a set of findings."""

    score: int  # 0-100
    tier: str  # PASS | LOW | MEDIUM | HIGH | CRITICAL
    message: str
    finding_count: int
    severity_breakdown: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "tier": self.tier,
            "message": self.message,
            "finding_count": self.finding_count,
            "severity_breakdown": dict(self.severity_breakdown),
        }


def _tier_for_score(score: int) -> str:
    for name, lo, hi in VERDICT_RANGES:
        if lo <= score <= hi:
            return name
    # Score is bounded to [0, 100] before this is called, so this branch
    # is defensive only.
    return "CRITICAL" if score > 100 else "PASS"


def calculate_verdict(findings: list[Finding]) -> Verdict:
    """Compute the verdict for a list of findings.

    Empty findings list returns a PASS at score 0. Severities outside the
    standard four are counted in the breakdown but do not contribute to
    the floor (an unknown severity is treated as informational).
    """
    weight_sum = sum(f.weight for f in findings)
    floor = max((SEVERITY_FLOORS.get(f.severity, 0) for f in findings), default=0)
    score = min(100, max(weight_sum, floor))
    tier = _tier_for_score(score)

    breakdown: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        breakdown[f.severity] = breakdown.get(f.severity, 0) + 1

    return Verdict(
        score=score,
        tier=tier,
        message=VERDICT_MESSAGES[tier],
        finding_count=len(findings),
        severity_breakdown=breakdown,
    )
