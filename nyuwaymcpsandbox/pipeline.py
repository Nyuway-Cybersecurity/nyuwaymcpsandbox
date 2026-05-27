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
VALID_MCP_TRANSPORTS = ("docker", "subprocess")


class PipelineNotReady(Exception):
    """A real transport or backend is required but not yet wired."""


def _default_monitors() -> list[Monitor]:
    """Return the four built-in monitor stubs."""
    return [NetworkMonitor(), FilesystemMonitor(), EnvironmentMonitor(), ProcessMonitor()]


def _default_mcp_client_factory(container_handle, config, source_path) -> McpClient:
    """Build a real McpClient for the requested transport.

    docker:     run the MCP server inside the orchestrator's container
                via ``docker exec``. Real sandbox.
    subprocess: run the MCP server as a host subprocess (no sandbox).
                Useful for dev and for protocol validation.

    Either transport requires ``config.mcp_command`` to be set so the
    factory knows what to start. Otherwise it raises PipelineNotReady
    with a clear message pointing the operator at --mcp-command.
    """
    from nyuwaymcpsandbox.drivers.docker_exec_stream import DockerExecStdioStream
    from nyuwaymcpsandbox.drivers.stdio_mcp import StdioMcpClient
    from nyuwaymcpsandbox.drivers.subprocess_stream import SubprocessStdioStream

    command = list(config.mcp_command)
    if not command:
        raise PipelineNotReady(
            "Real MCP transport needs --mcp-command (e.g. --mcp-command 'python server.py'). "
            "Use --dry-run to exercise the pipeline with the in-memory fake instead."
        )

    transport = config.mcp_transport
    if transport == "subprocess":
        stream = SubprocessStdioStream(command, cwd=source_path)
        return StdioMcpClient(stream)
    if transport == "docker":
        api = getattr(getattr(container_handle.container, "client", None), "api", None)
        if api is None:
            raise PipelineNotReady(
                "Docker MCP transport needs a real docker API on the container handle. "
                "Use --mcp-transport subprocess or --dry-run for non-Docker runs."
            )
        stream = DockerExecStdioStream(api, container_handle.container_id, command)
        return StdioMcpClient(stream)
    raise ValueError(f"Unknown mcp_transport: {transport!r}")


def _default_llm_backend_factory(model: str | None, api_key: str | None) -> LlmBackend:
    """Build a real LLM backend via litellm.

    Requires ``--llm <model>``. Examples:
        --llm claude-sonnet-4-5
        --llm openai/gpt-4o
        --llm ollama/llama3
        --llm local                 (alias for ollama/llama3)

    The provider's API key is picked up automatically from the standard
    env var (ANTHROPIC_API_KEY / OPENAI_API_KEY / etc) unless --api-key
    is explicitly passed.
    """
    from nyuwaymcpsandbox.drivers.litellm_backend import LiteLlmBackend

    if not model:
        raise PipelineNotReady(
            "Real LLM backend needs --llm <model> (e.g. --llm claude-sonnet-4-5 "
            "or --llm local for Ollama). Use --dry-run to exercise the pipeline "
            "with the in-memory fake instead."
        )
    return LiteLlmBackend(model=model, api_key=api_key)


@dataclass
class PipelineDeps:
    """Injection points. Default factories use real implementations."""

    source_resolver: Callable = resolve_source
    image_selector: Callable = select_image
    monitors_factory: Callable[[], list[Monitor]] = _default_monitors
    rules_factory: Callable[[], list[DetectionRule]] = load_builtin_rules
    prompts_factory: Callable[[], list[AdversarialPrompt]] = load_builtin_prompts
    mcp_client_factory: Callable[..., McpClient] = _default_mcp_client_factory
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
    # MCP transport selection. docker = run inside the sandboxed container
    # via docker exec; subprocess = run as a host subprocess (no sandbox).
    mcp_transport: str = "docker"
    # Argv to start the MCP server (e.g. ["python", "server.py"]).
    # Required by both real transports; empty means rely on the fake
    # injected by --dry-run.
    mcp_command: list[str] = field(default_factory=list)
    # Override the auto-selected container image. When None, image_selector
    # picks the right base image from the source tree (python:3.12-slim or
    # node:20-slim). Set this for servers that need a non-default runtime
    # (e.g. "mcr.microsoft.com/playwright:v1.52.0-noble" for browser-based
    # MCP servers). When set, /tmp is automatically exposed as a writable
    # tmpfs mount so browser runtimes can write crash reports and lock files
    # while the rest of the root filesystem stays read-only.
    container_image: str | None = None


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
    if config.mcp_transport not in VALID_MCP_TRANSPORTS:
        raise ValueError(
            f"Invalid mcp_transport: {config.mcp_transport!r}. "
            f"Expected one of {VALID_MCP_TRANSPORTS}."
        )

    deps = deps or PipelineDeps()
    scan_start = time.monotonic()
    timeline = BehavioralTimeline()

    with deps.source_resolver(config.target) as local_path:
        # Use the caller-supplied image when set; otherwise auto-select from
        # the source tree. The override is the escape hatch for servers that
        # need a non-default runtime (e.g. browser-capable playwright image).
        image = config.container_image or deps.image_selector(local_path)

        # Build monitors before ContainerConfig so we can inspect the list
        # and auto-wire PYTHONPATH when EnvironmentMonitor is active.
        monitors = deps.monitors_factory()

        # Auto-inject PYTHONPATH=/nyuway_runtime into the container env when:
        # - docker transport is in use (subprocess runs on the host and
        #   doesn't go through ContainerConfig.env), and
        # - EnvironmentMonitor is in the monitor list (it drops sitecustomize.py
        #   into /nyuway_runtime; Python only picks it up if that directory
        #   appears on PYTHONPATH at interpreter startup).
        # Previously operators had to add "env PYTHONPATH=/nyuway_runtime" to
        # --mcp-command manually. This wires it automatically with zero effort.
        container_env: dict[str, str] = {}
        if config.mcp_transport == "docker" and any(
            isinstance(m, EnvironmentMonitor) for m in monitors
        ):
            container_env["PYTHONPATH"] = "/nyuway_runtime"

        # When a custom container image is specified, assume a browser-based
        # server and auto-wire the settings Chromium needs inside Docker:
        #
        #   /tmp  tmpfs     — writable temp dir for crash reports / lock files
        #   /dev/shm tmpfs  — Chrome's default 64 MB shm is too small;
        #                     512 MB is the standard recommendation
        #   SYS_PTRACE      — Chrome's Zygote needs to ptrace renderer
        #                     subprocesses; dropped by cap_drop=['ALL']
        #   Chrome wrapper  — Chrome's namespace sandbox (CLONE_NEWUSER) still
        #                     fails with cap_drop=['ALL']+SYS_PTRACE; Chrome must
        #                     start with --no-sandbox. We write a /tmp/chrome wrapper
        #                     that prepends --no-sandbox and point CHROME_EXECUTABLE_PATH
        #                     to it. Running the full container sandbox as the outer
        #                     isolation layer makes --no-sandbox acceptable here.
        #
        # All other security defaults remain: network sinkholed, root
        # filesystem read-only, no-new-privileges, resource caps.
        tmpfs: dict[str, str] = {}
        cap_add: list[str] = []
        shm_size: str | None = None
        seccomp_unconfined = False
        if config.container_image:
            # exec is required so the Chrome --no-sandbox wrapper script
            # written to /tmp can be executed. Default tmpfs is noexec.
            tmpfs["/tmp"] = "size=256m,exec"
            tmpfs["/dev/shm"] = "size=512m"
            cap_add = ["SYS_PTRACE"]
            shm_size = "512m"
            # Docker's default seccomp profile blocks clone(CLONE_NEWNS) and
            # related namespace syscalls that Chrome uses even with --no-sandbox.
            # seccomp=unconfined is the standard Docker recommendation for
            # browser containers.
            seccomp_unconfined = True

        # Docker transport: the container must stay alive while docker exec
        # runs the MCP server command. Without a long-running startup
        # command the container exits immediately using the image's default
        # CMD (node / python3 REPL with no stdin), and exec_create returns
        # 409 "container is not running". Explicit config.command always
        # takes precedence so callers can override the keep-alive if needed.
        #
        # For browser-capable containers we also write a Chrome wrapper to
        # /tmp that adds --no-sandbox (required when Chrome's user-namespace
        # sandbox is blocked by cap_drop=['ALL']). The Docker container is
        # the outer sandbox; disabling Chrome's inner sandbox is acceptable.
        if config.mcp_transport == "docker" and not config.command:
            if config.container_image:
                # Create wrapper first, then stay alive.
                # /ms-playwright is the Playwright Docker image's browser root.
                chrome_bin = "/ms-playwright/chromium-1200/chrome-linux64/chrome"
                # --user-data-dir redirects the Chrome profile (normally
                # ~/.config/chromium) into /tmp so the read-only rootfs
                # doesn't block Chrome's first-run profile creation.
                wrapper_cmd = (
                    f"printf '#!/bin/sh\\nexec {chrome_bin} --no-sandbox"
                    f" --disable-dev-shm-usage"
                    f" --user-data-dir=/tmp/chrome-profile \"$@\"\\n'"
                    f" > /tmp/chrome-wrapper"
                    f" && chmod +x /tmp/chrome-wrapper && sleep infinity"
                )
                startup_cmd: list[str] = ["/bin/sh", "-c", wrapper_cmd]
                container_env["CHROME_EXECUTABLE_PATH"] = "/tmp/chrome-wrapper"
            else:
                startup_cmd = ["sleep", "infinity"]
        else:
            startup_cmd = list(config.command)

        container_config = ContainerConfig(
            image=image,
            source_path=local_path,
            command=startup_cmd,
            allow_network=config.allow_network,
            env=container_env,
            tmpfs=tmpfs,
            cap_add=cap_add,
            shm_size=shm_size,
            seccomp_unconfined=seccomp_unconfined,
            allow_writable_rootfs=bool(config.container_image),
        )
        with container_session(
            container_config,
            timeline,
            scan_start,
            client_factory=deps.docker_client_factory,
        ) as container:
            with monitor_session(monitors, container, timeline, scan_start):
                mcp = deps.mcp_client_factory(container, config, local_path)

                try:
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
                finally:
                    # McpClient is a Protocol that doesn't require close;
                    # call it when present so subprocess/exec transports
                    # release their resources before the source tempdir
                    # is cleaned up.
                    close_fn = getattr(mcp, "close", None)
                    if callable(close_fn):
                        try:
                            close_fn()
                        except Exception:
                            pass

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
