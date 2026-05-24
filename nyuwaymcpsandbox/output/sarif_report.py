"""SARIF 2.1.0 output renderer.

SARIF is the static-analysis output format that GitHub Advanced Security,
VS Code, and most CI tools consume. The sandbox's findings don't have
file:line locations - the evidence is behavioural - so each result uses
a logical location pointing at the matched event ids, with the full
detection record in the result's properties bag.
"""

from __future__ import annotations

import json

from nyuwaymcpsandbox import __version__
from nyuwaymcpsandbox.output.report import Report

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/Schemata/sarif-schema-2.1.0.json"
)

# SARIF "level": error | warning | note | none
_SEVERITY_TO_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
}


def _build_rule_entry(rule_id: str, title: str, description: str, recommendation: str) -> dict:
    return {
        "id": rule_id,
        "name": rule_id,
        "shortDescription": {"text": title},
        "fullDescription": {"text": description or title},
        "helpUri": "https://nyuway.ai/mcp-sandbox/rules/" + rule_id,
        "help": {"text": recommendation or "See nyuway.ai for remediation guidance."},
    }


def _build_result_entry(report: Report, finding) -> dict:
    level = _SEVERITY_TO_LEVEL.get(finding.severity, "note")
    return {
        "ruleId": finding.rule_id,
        "level": level,
        "message": {"text": finding.title},
        "locations": [
            {
                "logicalLocations": [
                    {"name": event_id, "kind": "behavioralEvent"}
                    for event_id in finding.matched_event_ids
                ]
            }
        ]
        if finding.matched_event_ids
        else [],
        "properties": {
            "severity": finding.severity,
            "weight": finding.weight,
            "category": finding.category,
            "recommendation": finding.recommendation,
            "matched_event_ids": list(finding.matched_event_ids),
        },
    }


def render_sarif(report: Report, indent: int | None = 2) -> str:
    """Return the report as a SARIF 2.1.0 JSON string."""
    # Deduplicate rules: SARIF requires every referenced rule appears in
    # tool.driver.rules exactly once.
    seen_rules: dict[str, dict] = {}
    for finding in report.findings:
        if finding.rule_id not in seen_rules:
            seen_rules[finding.rule_id] = _build_rule_entry(
                finding.rule_id, finding.title, finding.description, finding.recommendation
            )

    sarif = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "nyuwaymcpsandbox",
                        "version": __version__,
                        "informationUri": "https://github.com/Nyuway-Cybersecurity/nyuwaymcpsandbox",
                        "rules": list(seen_rules.values()),
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": report.scanned_at,
                        "properties": {
                            "target": report.target,
                            "mode": report.mode,
                            "duration_seconds": round(report.duration_seconds, 3),
                            "verdict": report.verdict.to_dict(),
                        },
                    }
                ],
                "results": [_build_result_entry(report, f) for f in report.findings],
            }
        ],
    }
    return json.dumps(sarif, indent=indent, sort_keys=False)
