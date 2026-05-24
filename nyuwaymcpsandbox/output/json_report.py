"""JSON output renderer.

Stable machine-readable schema that scripts, dashboards, and the v1.2
public registry consume. The schema is documented in the README; any
field change here is a breaking change.
"""

from __future__ import annotations

import json

from nyuwaymcpsandbox import __version__
from nyuwaymcpsandbox.output.report import Report


def report_to_dict(report: Report) -> dict:
    """Return a JSON-serializable dict for the report."""
    return {
        "tool": "nyuwaymcpsandbox",
        "version": __version__,
        "target": report.target,
        "mode": report.mode,
        "scanned_at": report.scanned_at,
        "duration_seconds": round(report.duration_seconds, 3),
        "verdict": report.verdict.to_dict(),
        "findings": [f.to_dict() for f in report.findings],
        "timeline": report.timeline.to_dict(),
    }


def render_json(report: Report, indent: int | None = 2) -> str:
    """Return the report as a JSON string."""
    return json.dumps(report_to_dict(report), indent=indent, sort_keys=False)
