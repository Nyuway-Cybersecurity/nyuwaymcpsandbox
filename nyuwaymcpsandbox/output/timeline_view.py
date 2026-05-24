"""Rich terminal timeline view - the default human-facing output.

The behavioural-first layout is the product's differentiation: the
behavioural timeline is what shows the user *what the server did*,
backed by detection findings. Layout follows the v1 product spec:

    Header: target, mode, verdict, duration
    Timeline: chronological event list with status icons + detection refs
    Detections: severity-grouped list of findings
    Recommendation: verdict-level message

Falls back to plain text when stdout is not a TTY.
"""

from __future__ import annotations

from io import StringIO

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from nyuwaymcpsandbox.output.describe import describe_event, format_relative_time
from nyuwaymcpsandbox.output.report import Report

# Status glyphs for the timeline. ASCII variants used in plain-text mode
# so logs and CI consoles without unicode support still render legibly.
_GLYPH_OK_UNICODE = "✓"
_GLYPH_WARN_UNICODE = "⚠"
_GLYPH_BAD_UNICODE = "✗"

_GLYPH_OK_ASCII = "."
_GLYPH_WARN_ASCII = "!"
_GLYPH_BAD_ASCII = "X"

# Severity ordering: critical first so the Detections section reads
# worst-to-mildest.
_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

# Severity to Rich style.
_SEVERITY_STYLE = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
}


def _select_glyphs(unicode: bool) -> tuple[str, str, str]:
    if unicode:
        return _GLYPH_OK_UNICODE, _GLYPH_WARN_UNICODE, _GLYPH_BAD_UNICODE
    return _GLYPH_OK_ASCII, _GLYPH_WARN_ASCII, _GLYPH_BAD_ASCII


def _verdict_style(tier: str) -> str:
    return _SEVERITY_STYLE.get(tier.lower(), "white")


def _build_header_panel(report: Report, unicode: bool) -> Panel:
    """Render the top-of-output header with target / mode / verdict / duration."""
    grid = Table.grid(padding=(0, 2))
    grid.add_column(justify="right", style="bold")
    grid.add_column()
    grid.add_row("Target:", report.target)
    grid.add_row("Mode:", report.mode)
    grid.add_row(
        "Verdict:",
        Text(
            f"{report.verdict.tier}  (score {report.verdict.score}/100)",
            style=_verdict_style(report.verdict.tier),
        ),
    )
    grid.add_row("Duration:", format_relative_time(report.duration_seconds))
    grid.add_row("Findings:", str(report.verdict.finding_count))
    return Panel(
        grid,
        title="nyuwaymcpsandbox - Behavioral Analysis",
        border_style="bright_blue",
        box=box.ROUNDED if unicode else box.ASCII,
    )


def _build_timeline_table(report: Report, unicode: bool) -> Table:
    glyph_ok, glyph_warn, glyph_bad = _select_glyphs(unicode)
    matched_ids = report.matched_event_ids()

    # Map event_id -> the rule_ids that referenced it, for the [DETECTION:] tag.
    detection_tags: dict[str, list[str]] = {}
    for finding in report.findings:
        for event_id in finding.matched_event_ids:
            detection_tags.setdefault(event_id, []).append(finding.rule_id)

    table = Table(
        title="Behavioral Timeline",
        show_lines=False,
        expand=False,
        box=box.SIMPLE if unicode else box.ASCII,
    )
    table.add_column("Time", justify="right", style="dim")
    table.add_column("", width=1)  # glyph
    table.add_column("Event")

    for event in report.timeline.events:
        glyph = glyph_bad if event.event_id in matched_ids else glyph_ok
        style = "red" if event.event_id in matched_ids else None
        description = describe_event(event)
        tag_rules = detection_tags.get(event.event_id)
        if tag_rules:
            description = f"{description}   [DETECTION: {', '.join(tag_rules)}]"
        table.add_row(
            format_relative_time(event.timestamp),
            Text(glyph, style=style or "green"),
            Text(description, style=style or "white"),
        )
        # Suppress unused warning while keeping the glyph available for
        # future intermediate severities (warn).
        _ = glyph_warn
    return table


def _build_detections_table(report: Report, unicode: bool) -> Table:
    glyph_ok, glyph_warn, glyph_bad = _select_glyphs(unicode)
    # Sort by severity (critical first), then by rule id for stability.
    sorted_findings = sorted(
        report.findings, key=lambda f: (_SEVERITY_ORDER.get(f.severity, 99), f.rule_id)
    )

    table = Table(
        title=f"Detections ({report.verdict.finding_count})",
        show_lines=False,
        expand=False,
        box=box.SIMPLE if unicode else box.ASCII,
    )
    table.add_column("", width=1)
    table.add_column("Severity", style="bold")
    table.add_column("Rule")
    table.add_column("Title")

    for f in sorted_findings:
        sev = f.severity
        style = _SEVERITY_STYLE.get(sev, "white")
        glyph = glyph_bad if sev in ("critical", "high") else glyph_warn
        table.add_row(
            Text(glyph, style=style),
            Text(sev.upper(), style=style),
            f.rule_id,
            f.title,
        )
        _ = glyph_ok
    return table


def render_timeline(report: Report, unicode: bool = True) -> str:
    """Render a Report as a Rich-formatted string ready for stdout.

    Returns the captured terminal output as a string. Callers can print
    it directly or pipe it elsewhere.
    """
    buf = StringIO()
    console = Console(file=buf, force_terminal=False, width=100, color_system=None)
    console.print(_build_header_panel(report, unicode))
    console.print(_build_timeline_table(report, unicode))
    if report.findings:
        console.print(_build_detections_table(report, unicode))
    # Recommendation / verdict message
    console.print(
        Panel(
            report.verdict.message,
            title="Recommendation",
            border_style="bright_blue",
            box=box.ROUNDED if unicode else box.ASCII,
        )
    )
    console.print()
    console.print("Powered by nyuwaymcpsandbox - nyuway.ai", style="dim")
    return buf.getvalue()
