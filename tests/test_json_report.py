"""Tests for the JSON output renderer."""

import json

from nyuwaymcpsandbox import __version__
from nyuwaymcpsandbox.detection.engine import Finding
from nyuwaymcpsandbox.detection.verdict import calculate_verdict
from nyuwaymcpsandbox.output.json_report import render_json, report_to_dict
from nyuwaymcpsandbox.output.report import Report
from nyuwaymcpsandbox.sandbox.events import (
    EVT_NETWORK_HTTP,
    EVT_PROCESS_SPAWN,
    SRC_NETWORK,
    SRC_PROCESS,
    BehavioralEvent,
)
from nyuwaymcpsandbox.sandbox.timeline import BehavioralTimeline


def _build_simple_report():
    tl = BehavioralTimeline()
    e1 = BehavioralEvent(
        type=EVT_PROCESS_SPAWN, source=SRC_PROCESS, timestamp=1.0, payload={"argv": ["/bin/sh"]}
    )
    e2 = BehavioralEvent(
        type=EVT_NETWORK_HTTP, source=SRC_NETWORK, timestamp=2.0, payload={"host": "evil.com"}
    )
    tl.add(e1)
    tl.add(e2)
    findings = [
        Finding(
            rule_id="shell_exec_in_tool",
            title="Subprocess spawned during MCP tool execution",
            severity="high",
            weight=25,
            category="code_execution",
            description="desc",
            recommendation="rec",
            matched_event_ids=[e1.event_id],
        )
    ]
    verdict = calculate_verdict(findings)
    return (
        Report(
            target="./demo",
            mode="fast",
            timeline=tl,
            findings=findings,
            verdict=verdict,
            duration_seconds=2.5,
        ),
        e1,
        e2,
    )


def test_render_json_returns_valid_json():
    report, _, _ = _build_simple_report()
    parsed = json.loads(render_json(report))
    assert parsed["tool"] == "nyuwaymcpsandbox"
    assert parsed["version"] == __version__
    assert parsed["target"] == "./demo"
    assert parsed["mode"] == "fast"


def test_render_json_includes_verdict():
    report, _, _ = _build_simple_report()
    parsed = json.loads(render_json(report))
    # One high-severity finding, weight 25 - no critical floor applies, so
    # the score is the weight sum (25), which lands in LOW (20-39).
    assert parsed["verdict"]["score"] == 25
    assert parsed["verdict"]["tier"] == "LOW"


def test_render_json_includes_findings():
    report, _, _ = _build_simple_report()
    parsed = json.loads(render_json(report))
    assert len(parsed["findings"]) == 1
    assert parsed["findings"][0]["rule_id"] == "shell_exec_in_tool"
    assert parsed["findings"][0]["severity"] == "high"


def test_render_json_includes_timeline_events():
    report, _, _ = _build_simple_report()
    parsed = json.loads(render_json(report))
    assert parsed["timeline"]["event_count"] == 2
    types = [e["type"] for e in parsed["timeline"]["events"]]
    assert EVT_PROCESS_SPAWN in types
    assert EVT_NETWORK_HTTP in types


def test_render_json_rounds_duration():
    report, _, _ = _build_simple_report()
    report.duration_seconds = 1.234567890
    parsed = json.loads(render_json(report))
    assert parsed["duration_seconds"] == 1.235


def test_render_json_empty_report():
    """A clean run with no findings still produces valid JSON."""
    tl = BehavioralTimeline()
    verdict = calculate_verdict([])
    report = Report(target="./x", mode="fast", timeline=tl, findings=[], verdict=verdict)
    parsed = json.loads(render_json(report))
    assert parsed["verdict"]["tier"] == "PASS"
    assert parsed["findings"] == []
    assert parsed["timeline"]["event_count"] == 0


def test_report_to_dict_contains_scanned_at():
    report, _, _ = _build_simple_report()
    d = report_to_dict(report)
    assert "scanned_at" in d
    # Z-suffixed UTC timestamp.
    assert d["scanned_at"].endswith("Z")
