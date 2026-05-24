"""End-to-end detonation pipeline.

Orchestrates every layer the sandbox builds on:

    source resolution -> image selection -> container session
        -> monitor session -> deterministic harness -> [LLM driver]
            -> detection rule eval -> verdict -> report -> render

The pipeline takes injection points for every external dependency
(source resolver, container session, MCP client factory, LLM backend
factory, monitors, rules, prompts) so:

1. Tests inject fakes and verify the full chain.
2. --dry-run mode in the CLI injects the FakeMcpClient / FakeLlmBackend
   so users without Docker / an LLM key can see a real report.
3. Real implementations (stdio MCP transport, litellm) slot in
   without touching the orchestration logic.

The default factories for the real MCP and LLM transports raise
PipelineNotReady - those land when the project moves to Linux CI.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field

from nyuwaymcpsandbox.detection.engine import evaluate_rules
from nyuwaymcpsandbox.detection.rules import DetectionRule, load_builtin_rules
from nyuwaymcpsandbox.detection.verdict import calculate_verdict
from nyuwaymcpsandbox.drivers.deterministic import run_deterministic_harness
from nyuwaymcpsandbox.drivers.llm_backend import LlmBackend
from nyuwaymcpsandbox.drivers.llm_driver import run_llm_driver
from nyuwaymcpsandbox.drivers.mcp_client import McpClient
from nyuwaymcpsandbox.drivers.prompt_library import AdversarialPrompt, load_builtin_prompts
from nyuwaymcpsandbox.output.json_report import render_json
from nyuwaymcpsandbox.output.report import Report
from nyuwaymcpsandbox.output.sarif_report import render_sarif
from nyuwaymcpsandbox.output.timeline_view import render_timeline
from nyuwaymcpsandbox.sandbox.images import select_image
from nyuwaymcpsandbox.sandbox.monitor import Monitor, monitor_session
from nyuwaymcpsandbox.sandbox.monitors import (
    EnvironmentMonitor,
    FilesystemMonitor,
    NetworkMonitor,
    ProcessMonitor,
)
from nyuwaymcpsandbox.sandbox.orchestrator import ContainerConfig, container_session
from nyuwaymcpsandbox.sandbox.timeline import BehavioralTimeline
from nyuwaymcpsandbox.sources import resolve as resolve_source

VALID_MODES = ("fast", "full")
VALID_OUTPUTS = ("timeline", "json", "sarif")


class PipelineNotReady(Exception):
    """A real transport or backend is required but not yet wired."""


def _default_monitors() -> list[Monitor]:
    """Return the four built-in monitor stubs."""
    return [NetworkMonitor(), FilesystemMonitor(), EnvironmentMonitor(), ProcessMonitor()]


def _default_mcp_client_factory(container_handle) -> McpClient:
    raise PipelineNotReady(
        "Real stdio MCP transport is not yet wired. Use --dry-run to exercise "
        "the pipeline with the in-memory fake."
    )


def _default_llm_backend_factory(model: str | None, api_key: str | None) -> LlmBackend:
    raise PipelineNotReady(
        "Real LLM backend is not yet wired. Use --dry-run to exercise the "
        "pipeline with the in-memory fake."
    )


@dataclass
class PipelineDeps:
    """Injection points. Default factories use real implementations."""

    source_resolver: Callable = resolve_source
    image_selector: Callable = select_image
    monitors_factory: Callable[[], list[Monitor]] = _default_monitors
    rules_factory: Callable[[], list[DetectionRule]] = load_builtin_rules
    prompts_factory: Callable[[], list[AdversarialPrompt]] = load_builtin_prompts
    mcp_client_factory: Callable[[object], McpClient] = _default_mcp_client_factory
    llm_backend_factory: Callable[[str | None, str | None], LlmBackend] = (
        _default_llm_backend_factory
    )
    # Passed through to container_session; tests inject a fake docker client.
    docker_client_factory: Callable | None = None


@dataclass
class PipelineConfig:
    """Operator-facing settings for one detonation."""

    target: str
    mode: str = "fast"
    output: str = "timeline"
    fail_on: str | None = None
    api_key: str | None = None
    llm_model: str | None = None
    allow_network: bool = False
    command: list[str] = field(default_factory=list)


@dataclass
class PipelineResult:
    report: Report
    rendered: str


# Severity ordering for --fail-on threshold checks.
_SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def exit_code_for(report: Report, fail_on: str | None) -> int:
    """Determine the CLI exit code from the report + --fail-on threshold."""
    if not fail_on:
        return 0
    threshold = _SEVERITY_RANK.get(fail_on, 0)
    for f in report.findings:
        if _SEVERITY_RANK.get(f.severity, 0) >= threshold:
            return 1
    return 0


def _render(report: Report, output: str) -> str:
    if output == "json":
        return render_json(report)
    if output == "sarif":
        return render_sarif(report)
    # Plain ASCII for terminal output so Windows cp1252 consoles render
    # cleanly. The unicode variant is opt-in once stdout encoding is
    # known to support it - see CLI wiring.
    return render_timeline(report, unicode=False)


def run_pipeline(config: PipelineConfig, deps: PipelineDeps | None = None) -> PipelineResult:
    """Run a full detonation. Returns the Report and the rendered output."""
    if config.mode not in VALID_MODES:
        raise ValueError(f"Invalid mode: {config.mode!r}. Expected one of {VALID_MODES}.")
    if config.output not in VALID_OUTPUTS:
        raise ValueError(f"Invalid output: {config.output!r}. Expected one of {VALID_OUTPUTS}.")

    deps = deps or PipelineDeps()
    scan_start = time.monotonic()
    timeline = BehavioralTimeline()

    with deps.source_resolver(config.target) as local_path:
        image = deps.image_selector(local_path)
        container_config = ContainerConfig(
            image=image,
            source_path=local_path,
            command=list(config.command),
            allow_network=config.allow_network,
        )
        with container_session(
            container_config,
            timeline,
            scan_start,
            client_factory=deps.docker_client_factory,
        ) as container:
            monitors = deps.monitors_factory()
            with monitor_session(monitors, container, timeline, scan_start):
                mcp = deps.mcp_client_factory(container)

                run_deterministic_harness(
                    client=mcp,
                    timeline=timeline,
                    scan_start=scan_start,
                    triggered_by=container.started_event_id,
                )

                if config.mode == "full":
                    llm = deps.llm_backend_factory(config.llm_model, config.api_key)
                    prompts = deps.prompts_factory()
                    run_llm_driver(
                        llm=llm,
                        mcp=mcp,
                        prompts=prompts,
                        timeline=timeline,
                        scan_start=scan_start,
                        triggered_by=container.started_event_id,
                    )

    duration = time.monotonic() - scan_start
    rules = deps.rules_factory()
    findings = evaluate_rules(rules, timeline)
    verdict = calculate_verdict(findings)
    report = Report(
        target=config.target,
        mode=config.mode,
        timeline=timeline,
        findings=findings,
        verdict=verdict,
        duration_seconds=duration,
    )
    rendered = _render(report, config.output)
    return PipelineResult(report=report, rendered=rendered)
