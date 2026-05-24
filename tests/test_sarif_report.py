"""Tests for the SARIF 2.1.0 output renderer."""

import json

from nyuwaymcpsandbox.detection.engine import Finding
from nyuwaymcpsandbox.detection.verdict import calculate_verdict
from nyuwaymcpsandbox.output.report import Report
from nyuwaymcpsandbox.output.sarif_report import (
    SARIF_SCHEMA,
    SARIF_VERSION,
    render_sarif,
)
from nyuwaymcpsandbox.sandbox.events import EVT_PROCESS_SPAWN, SRC_PROCESS, BehavioralEvent
from nyuwaymcpsandbox.sandbox.timeline import BehavioralTimeline


def _build_report(findings):
    tl = BehavioralTimeline()
    e = BehavioralEvent(type=EVT_PROCESS_SPAWN, source=SRC_PROCESS, timestamp=1.0)
    tl.add(e)
    for f in findings:
        f.matched_event_ids = [e.event_id]
    verdict = calculate_verdict(findings)
    return Report(target="./demo", mode="fast", timeline=tl, findings=findings, verdict=verdict)


def _finding(rule_id="r1", severity="high", weight=25):
    return Finding(
        rule_id=rule_id,
        title="Test rule " + rule_id,
        severity=severity,
        weight=weight,
        category="test",
        description="desc",
        recommendation="rec",
    )


def test_sarif_top_level_shape():
    report = _build_report([_finding()])
    sarif = json.loads(render_sarif(report))
    assert sarif["version"] == SARIF_VERSION
    assert sarif["$schema"] == SARIF_SCHEMA
    assert "runs" in sarif
    assert len(sarif["runs"]) == 1


def test_sarif_driver_metadata():
    report = _build_report([_finding()])
    sarif = json.loads(render_sarif(report))
    driver = sarif["runs"][0]["tool"]["driver"]
    assert driver["name"] == "nyuwaymcpsandbox"
    assert "version" in driver
    assert driver["informationUri"].startswith("https://")


def test_sarif_rules_deduped():
    """A rule that fires twice must only appear once in tool.driver.rules."""
    report = _build_report([_finding("r1"), _finding("r1"), _finding("r2")])
    sarif = json.loads(render_sarif(report))
    rules = sarif["runs"][0]["tool"]["driver"]["rules"]
    rule_ids = [r["id"] for r in rules]
    assert sorted(rule_ids) == ["r1", "r2"]


def test_sarif_severity_mapped_to_level():
    findings = [
        _finding("a", severity="critical"),
        _finding("b", severity="high"),
        _finding("c", severity="medium"),
        _finding("d", severity="low"),
    ]
    report = _build_report(findings)
    sarif = json.loads(render_sarif(report))
    results = sarif["runs"][0]["results"]
    level_by_rule = {r["ruleId"]: r["level"] for r in results}
    assert level_by_rule["a"] == "error"
    assert level_by_rule["b"] == "error"
    assert level_by_rule["c"] == "warning"
    assert level_by_rule["d"] == "note"


def test_sarif_result_logical_location_carries_event_id():
    report = _build_report([_finding()])
    sarif = json.loads(render_sarif(report))
    result = sarif["runs"][0]["results"][0]
    locations = result["locations"]
    assert len(locations) == 1
    logical = locations[0]["logicalLocations"]
    assert len(logical) >= 1
    assert logical[0]["kind"] == "behavioralEvent"


def test_sarif_result_properties_carry_full_finding():
    report = _build_report([_finding(severity="medium", weight=15)])
    sarif = json.loads(render_sarif(report))
    props = sarif["runs"][0]["results"][0]["properties"]
    assert props["severity"] == "medium"
    assert props["weight"] == 15
    assert props["category"] == "test"
    assert "matched_event_ids" in props


def test_sarif_invocation_carries_verdict():
    report = _build_report([_finding(severity="critical", weight=35)])
    sarif = json.loads(render_sarif(report))
    invocation = sarif["runs"][0]["invocations"][0]
    assert invocation["properties"]["target"] == "./demo"
    assert invocation["properties"]["mode"] == "fast"
    assert invocation["properties"]["verdict"]["tier"] == "HIGH"  # critical floor


def test_sarif_clean_report_has_empty_results():
    tl = BehavioralTimeline()
    verdict = calculate_verdict([])
    report = Report(target="./x", mode="fast", timeline=tl, findings=[], verdict=verdict)
    sarif = json.loads(render_sarif(report))
    assert sarif["runs"][0]["results"] == []
    assert sarif["runs"][0]["tool"]["driver"]["rules"] == []
