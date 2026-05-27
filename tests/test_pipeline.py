"""End-to-end pipeline tests with everything injected.

Verifies that source resolution -> container session -> monitor session
-> deterministic harness -> [LLM driver] -> rule eval -> verdict ->
render produces a coherent report with all the right causal links.
"""

from __future__ import annotations

import json
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from nyuwaymcpsandbox.detection.engine import Finding
from nyuwaymcpsandbox.detection.rules import DetectionRule, EventPattern
from nyuwaymcpsandbox.drivers.fakes import FakeLlmBackend, FakeMcpClient
from nyuwaymcpsandbox.pipeline import (
    PipelineConfig,
    PipelineDeps,
    PipelineNotReady,
    exit_code_for,
    run_pipeline,
)
from nyuwaymcpsandbox.sandbox.events import (
    EVT_CONTAINER_STARTED,
    EVT_CONTAINER_STOPPED,
    EVT_LLM_PROMPT_SENT,
    EVT_MCP_TOOL_INVOKE,
    EVT_MCP_TOOL_LIST,
)

# ── Fake docker client (reused from orchestrator tests) ──────────────────


@dataclass
class _FakeContainer:
    id: str = "fakecontainer"
    attrs: dict = field(default_factory=lambda: {"State": {"ExitCode": 0}})

    def stop(self, timeout=5):
        return None

    def remove(self, force=False):
        return None


@dataclass
class _FakeContainers:
    def run(self, **kwargs):
        return _FakeContainer()


@dataclass
class _FakeDockerClient:
    containers: _FakeContainers = field(default_factory=_FakeContainers)


def _fake_docker_factory():
    return _FakeDockerClient()


@contextmanager
def _fake_source_resolver(spec):
    """Yield a tmp Path - the pipeline doesn't care what's in it for tests.

    ignore_cleanup_errors keeps Windows happy when a subprocess transport's
    cwd briefly holds the directory after the test exits the with-block.
    """
    import tempfile

    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as d:
        yield Path(d)


def _base_deps(**overrides) -> PipelineDeps:
    """Inject every external dep with a working fake so the pipeline runs."""
    deps = PipelineDeps(
        source_resolver=_fake_source_resolver,
        mcp_client_factory=lambda _c, _cfg, _sp: FakeMcpClient(),
        llm_backend_factory=lambda _m, _k: FakeLlmBackend(),
        docker_client_factory=_fake_docker_factory,
        # Disable monitors for tests so we only see events the harness/driver emit.
        monitors_factory=lambda: [],
        # Empty rules so no findings unless a test injects them.
        rules_factory=lambda: [],
        prompts_factory=lambda: [],
    )
    for k, v in overrides.items():
        setattr(deps, k, v)
    return deps


def _config(**overrides) -> PipelineConfig:
    base = {"target": "./demo"}
    base.update(overrides)
    return PipelineConfig(**base)


# ── Happy-path Fast mode ─────────────────────────────────────────────────


def test_fast_mode_produces_report():
    result = run_pipeline(_config(mode="fast"), _base_deps())
    assert result.report.mode == "fast"
    assert result.report.target == "./demo"


def test_fast_mode_emits_container_lifecycle_and_harness_events():
    result = run_pipeline(_config(mode="fast"), _base_deps())
    types = [e.type for e in result.report.timeline.events]
    assert EVT_CONTAINER_STARTED in types
    assert EVT_MCP_TOOL_LIST in types
    assert EVT_MCP_TOOL_INVOKE in types
    assert EVT_CONTAINER_STOPPED in types


def test_fast_mode_does_not_emit_llm_events():
    """LLM driver only runs in full mode."""
    result = run_pipeline(_config(mode="fast"), _base_deps())
    types = [e.type for e in result.report.timeline.events]
    assert EVT_LLM_PROMPT_SENT not in types


def test_fast_mode_renders_plain_output():
    result = run_pipeline(_config(mode="fast", output="timeline"), _base_deps())
    assert "nyuwaymcpsandbox" in result.rendered
    assert "fast" in result.rendered.lower()


def test_fast_mode_no_findings_means_pass_verdict():
    result = run_pipeline(_config(mode="fast"), _base_deps())
    assert result.report.verdict.tier == "PASS"


# ── Full mode adds LLM driver ────────────────────────────────────────────


def test_full_mode_emits_llm_prompt_event():
    deps = _base_deps(
        prompts_factory=lambda: [
            __import__(
                "nyuwaymcpsandbox.drivers.prompt_library", fromlist=["AdversarialPrompt"]
            ).AdversarialPrompt(
                id="p1",
                category="tool_poisoning",
                description="test",
                user_message="probe",
            )
        ]
    )
    result = run_pipeline(_config(mode="full"), deps)
    types = [e.type for e in result.report.timeline.events]
    assert EVT_LLM_PROMPT_SENT in types


def test_full_mode_with_no_prompts_still_works():
    """An empty prompt library is a degenerate but valid Full run."""
    result = run_pipeline(_config(mode="full"), _base_deps())
    assert result.report.mode == "full"


# ── Rule evaluation runs against the assembled timeline ─────────────────


def test_rule_evaluation_produces_findings():
    """Inject a rule that matches on mcp.tool_invocation to verify wiring."""
    deps = _base_deps(
        rules_factory=lambda: [
            DetectionRule(
                id="any_tool_call",
                title="Any tool call",
                severity="high",
                weight=25,
                category="test",
                event_patterns=[EventPattern(type=EVT_MCP_TOOL_INVOKE)],
            )
        ]
    )
    result = run_pipeline(_config(mode="fast"), deps)
    rule_ids = {f.rule_id for f in result.report.findings}
    assert "any_tool_call" in rule_ids
    # Score from a single high finding (weight 25, no critical floor) = LOW.
    assert result.report.verdict.tier == "LOW"


# ── Output formats ───────────────────────────────────────────────────────


def test_json_output_parses():
    result = run_pipeline(_config(mode="fast", output="json"), _base_deps())
    parsed = json.loads(result.rendered)
    assert parsed["tool"] == "nyuwaymcpsandbox"
    assert parsed["mode"] == "fast"


def test_sarif_output_parses():
    result = run_pipeline(_config(mode="fast", output="sarif"), _base_deps())
    parsed = json.loads(result.rendered)
    assert parsed["version"] == "2.1.0"


# ── Validation ───────────────────────────────────────────────────────────


def test_invalid_mode_raises_value_error():
    with pytest.raises(ValueError, match="Invalid mode"):
        run_pipeline(_config(mode="warp"), _base_deps())


def test_invalid_output_raises_value_error():
    with pytest.raises(ValueError, match="Invalid output"):
        run_pipeline(_config(output="xml"), _base_deps())


# ── Default factories raise PipelineNotReady ─────────────────────────────


def test_default_mcp_client_factory_without_command_raises_pipeline_not_ready():
    """Real transports require --mcp-command; absence is a clear configuration error."""
    deps = PipelineDeps(
        source_resolver=_fake_source_resolver,
        docker_client_factory=_fake_docker_factory,
        monitors_factory=lambda: [],
    )
    with pytest.raises(PipelineNotReady, match="mcp-command"):
        run_pipeline(_config(mode="fast"), deps)


def test_default_mcp_client_factory_subprocess_transport_runs_real_server(tmp_path):
    """End-to-end: real default factory with subprocess transport against the echo fixture."""
    import sys
    from pathlib import Path

    fixture = Path(__file__).parent / "fixtures" / "echo_mcp_server.py"
    deps = PipelineDeps(
        source_resolver=_fake_source_resolver,
        docker_client_factory=_fake_docker_factory,
        monitors_factory=lambda: [],
        rules_factory=lambda: [],
        prompts_factory=lambda: [],
        llm_backend_factory=lambda _m, _k: FakeLlmBackend(),
        # Use the real default mcp_client_factory.
    )
    config = _config(
        mode="fast",
        mcp_transport="subprocess",
        mcp_command=[sys.executable, str(fixture)],
    )
    result = run_pipeline(config, deps)
    # The harness should have probed the echo server's two tools.
    timeline_events = [e for e in result.report.timeline.events]
    tool_invokes = [e for e in timeline_events if e.type == "mcp.tool_invocation"]
    invoked_names = {e.payload["name"] for e in tool_invokes}
    assert "echo" in invoked_names
    assert "fail" in invoked_names


def test_default_mcp_client_factory_docker_without_api_raises_pipeline_not_ready():
    """Docker transport needs a real docker API; the fake docker client has no .client attr."""
    deps = PipelineDeps(
        source_resolver=_fake_source_resolver,
        docker_client_factory=_fake_docker_factory,
        monitors_factory=lambda: [],
    )
    config = _config(
        mode="fast",
        mcp_transport="docker",
        mcp_command=["python", "server.py"],
    )
    with pytest.raises(PipelineNotReady, match="docker API"):
        run_pipeline(config, deps)


def test_invalid_mcp_transport_raises_value_error():
    deps = _base_deps()
    config = _config(mcp_transport="ssh")
    with pytest.raises(ValueError, match="mcp_transport"):
        run_pipeline(config, deps)


def test_default_llm_backend_factory_without_model_raises_pipeline_not_ready():
    """Real LLM backend needs --llm; absence produces a clear configuration error."""
    deps = _base_deps(
        llm_backend_factory=PipelineDeps().llm_backend_factory,
        prompts_factory=lambda: [
            __import__(
                "nyuwaymcpsandbox.drivers.prompt_library", fromlist=["AdversarialPrompt"]
            ).AdversarialPrompt(
                id="p1",
                category="tool_poisoning",
                description="test",
                user_message="probe",
            )
        ],
    )
    with pytest.raises(PipelineNotReady, match="--llm"):
        run_pipeline(_config(mode="full"), deps)


def test_default_llm_backend_factory_with_model_builds_litellm_backend():
    """When --llm is set, the default factory returns a real LiteLlmBackend."""
    from nyuwaymcpsandbox.drivers.litellm_backend import LiteLlmBackend
    from nyuwaymcpsandbox.pipeline import _default_llm_backend_factory

    backend = _default_llm_backend_factory(model="claude-sonnet-4-5", api_key="sk-x")
    assert isinstance(backend, LiteLlmBackend)
    assert backend.model == "claude-sonnet-4-5"


# ── exit_code_for ────────────────────────────────────────────────────────


def _finding(severity: str) -> Finding:
    return Finding(
        rule_id="r",
        title="t",
        severity=severity,
        weight=25,
        category="c",
        description="",
        recommendation="",
    )


def test_exit_code_none_threshold_always_zero():
    class _R:
        findings = [_finding("critical")]

    assert exit_code_for(_R(), None) == 0


def test_exit_code_threshold_unmet_returns_zero():
    class _R:
        findings = [_finding("low")]

    assert exit_code_for(_R(), "high") == 0


def test_exit_code_threshold_met_returns_one():
    class _R:
        findings = [_finding("high")]

    assert exit_code_for(_R(), "high") == 1


def test_exit_code_threshold_exceeded_returns_one():
    class _R:
        findings = [_finding("critical")]

    assert exit_code_for(_R(), "medium") == 1


def test_exit_code_no_findings_returns_zero():
    class _R:
        findings = []

    assert exit_code_for(_R(), "low") == 0


# ── Auto-wire PYTHONPATH=/nyuway_runtime ─────────────────────────────────


def test_pythonpath_auto_wired_for_docker_transport_with_env_monitor():
    """When docker transport + EnvironmentMonitor, PYTHONPATH is set automatically."""
    from nyuwaymcpsandbox.sandbox.monitors.environment import EnvironmentMonitor

    captured_env: dict = {}

    class _CapturingContainers:
        def run(self, **kwargs):
            captured_env.update(kwargs.get("environment", {}))
            return _FakeContainer()

    class _CapturingDockerClient:
        containers = _CapturingContainers()

    deps = _base_deps(
        docker_client_factory=lambda: _CapturingDockerClient(),
        monitors_factory=lambda: [EnvironmentMonitor()],
    )
    config = _config(mcp_transport="docker", mcp_command=["python", "server.py"])
    run_pipeline(config, deps)

    assert captured_env.get("PYTHONPATH") == "/nyuway_runtime", (
        f"Expected PYTHONPATH=/nyuway_runtime in container env, got: {captured_env}"
    )


def test_pythonpath_not_injected_for_subprocess_transport():
    """subprocess transport runs on the host - PYTHONPATH injection is skipped."""
    from nyuwaymcpsandbox.sandbox.monitors.environment import EnvironmentMonitor

    captured_env: dict = {}

    class _CapturingContainers:
        def run(self, **kwargs):
            captured_env.update(kwargs.get("environment", {}))
            return _FakeContainer()

    class _CapturingDockerClient:
        containers = _CapturingContainers()

    deps = _base_deps(
        docker_client_factory=lambda: _CapturingDockerClient(),
        monitors_factory=lambda: [EnvironmentMonitor()],
    )
    # subprocess transport - fake docker still runs for the session but
    # PYTHONPATH should not be injected since the server runs on the host.
    import sys
    from pathlib import Path

    fixture = Path(__file__).parent / "fixtures" / "echo_mcp_server.py"
    config = _config(
        mcp_transport="subprocess",
        mcp_command=[sys.executable, str(fixture)],
    )
    run_pipeline(config, deps)

    assert "PYTHONPATH" not in captured_env, (
        f"PYTHONPATH should not be set for subprocess transport, got: {captured_env}"
    )


# ── Docker transport keep-alive (sleep infinity) ─────────────────────────


def test_docker_transport_injects_sleep_infinity_as_container_command():
    """Docker transport must start the container with sleep infinity so it
    stays alive for docker exec. Without this the container exits immediately
    and exec_create returns 409 'container is not running'."""
    captured: dict = {}

    class _CapturingContainers:
        def run(self, **kwargs):
            captured["command"] = kwargs.get("command")
            return _FakeContainer()

    class _CapturingDockerClient:
        containers = _CapturingContainers()

    deps = _base_deps(
        docker_client_factory=lambda: _CapturingDockerClient(),
    )
    config = _config(mcp_transport="docker", mcp_command=["node", "dist/index.js"])
    run_pipeline(config, deps)

    assert captured.get("command") == ["sleep", "infinity"], (
        f"Expected container command ['sleep', 'infinity'], got: {captured.get('command')}"
    )


def test_docker_transport_explicit_command_takes_precedence_over_sleep_infinity():
    """If config.command is explicitly set, it overrides the sleep infinity default."""
    captured: dict = {}

    class _CapturingContainers:
        def run(self, **kwargs):
            captured["command"] = kwargs.get("command")
            return _FakeContainer()

    class _CapturingDockerClient:
        containers = _CapturingContainers()

    deps = _base_deps(
        docker_client_factory=lambda: _CapturingDockerClient(),
    )
    config = _config(
        mcp_transport="docker",
        mcp_command=["node", "dist/index.js"],
        command=["my_custom_entrypoint"],
    )
    run_pipeline(config, deps)

    assert captured.get("command") == ["my_custom_entrypoint"], (
        f"Expected explicit command, got: {captured.get('command')}"
    )


def test_subprocess_transport_does_not_inject_sleep_infinity():
    """subprocess transport runs the server on the host; the container command
    stays empty (None in docker-py) so the image's default CMD is used."""
    import sys
    from pathlib import Path

    captured: dict = {}

    class _CapturingContainers:
        def run(self, **kwargs):
            captured["command"] = kwargs.get("command")
            return _FakeContainer()

    class _CapturingDockerClient:
        containers = _CapturingContainers()

    fixture = Path(__file__).parent / "fixtures" / "echo_mcp_server.py"
    deps = _base_deps(
        docker_client_factory=lambda: _CapturingDockerClient(),
        monitors_factory=lambda: [],
        rules_factory=lambda: [],
        prompts_factory=lambda: [],
    )
    config = _config(
        mcp_transport="subprocess",
        mcp_command=[sys.executable, str(fixture)],
    )
    run_pipeline(config, deps)

    assert captured.get("command") is None, (
        f"subprocess transport should not inject sleep infinity, got: {captured.get('command')}"
    )


# ── container_image override + tmpfs auto-wire ───────────────────────────


def test_container_image_override_uses_custom_image():
    """--container-image bypasses image_selector and uses the supplied image."""
    captured: dict = {}

    class _CapturingContainers:
        def run(self, **kwargs):
            captured["image"] = kwargs.get("image")
            return _FakeContainer()

    class _CapturingDockerClient:
        containers = _CapturingContainers()

    deps = _base_deps(
        docker_client_factory=lambda: _CapturingDockerClient(),
        # image_selector would normally be called but should be bypassed.
        image_selector=lambda _p: "should-not-be-used:latest",
    )
    config = _config(
        mcp_transport="docker",
        mcp_command=["node", "dist/index.js"],
        container_image="mcr.microsoft.com/playwright:v1.52.0-noble",
    )
    run_pipeline(config, deps)

    assert captured.get("image") == "mcr.microsoft.com/playwright:v1.52.0-noble", (
        f"Expected playwright image, got: {captured.get('image')}"
    )


def test_no_container_image_override_uses_image_selector():
    """Without container_image, image_selector is called as normal."""
    captured: dict = {}

    class _CapturingContainers:
        def run(self, **kwargs):
            captured["image"] = kwargs.get("image")
            return _FakeContainer()

    class _CapturingDockerClient:
        containers = _CapturingContainers()

    deps = _base_deps(
        docker_client_factory=lambda: _CapturingDockerClient(),
        image_selector=lambda _p: "custom-selector-result:latest",
    )
    config = _config(
        mcp_transport="docker",
        mcp_command=["python", "server.py"],
    )
    run_pipeline(config, deps)

    assert captured.get("image") == "custom-selector-result:latest", (
        f"Expected selector result, got: {captured.get('image')}"
    )


def test_tmpfs_auto_wired_when_container_image_overridden():
    """/tmp tmpfs is injected automatically when --container-image is set.
    Browser runtimes (playwright, puppeteer) need a writable /tmp for crash
    reports and lock files even when the root filesystem is read-only."""
    captured: dict = {}

    class _CapturingContainers:
        def run(self, **kwargs):
            captured["tmpfs"] = kwargs.get("tmpfs")
            return _FakeContainer()

    class _CapturingDockerClient:
        containers = _CapturingContainers()

    deps = _base_deps(
        docker_client_factory=lambda: _CapturingDockerClient(),
    )
    config = _config(
        mcp_transport="docker",
        mcp_command=["node", "dist/index.js"],
        container_image="mcr.microsoft.com/playwright:v1.52.0-noble",
    )
    run_pipeline(config, deps)

    assert captured.get("tmpfs") == {"/tmp": "size=256m,exec", "/dev/shm": "size=512m"}, (
        f"Expected /tmp (exec) and /dev/shm tmpfs mounts, got: {captured.get('tmpfs')}"
    )


def test_cap_add_sys_ptrace_auto_wired_when_container_image_overridden():
    """SYS_PTRACE is added when --container-image is set so Chrome's Zygote
    can trace renderer subprocesses (dropped by the cap_drop=['ALL'] baseline)."""
    captured: dict = {}

    class _CapturingContainers:
        def run(self, **kwargs):
            captured["cap_add"] = kwargs.get("cap_add")
            return _FakeContainer()

    class _CapturingDockerClient:
        containers = _CapturingContainers()

    deps = _base_deps(
        docker_client_factory=lambda: _CapturingDockerClient(),
    )
    config = _config(
        mcp_transport="docker",
        mcp_command=["node", "dist/index.js"],
        container_image="mcr.microsoft.com/playwright:v1.57.0-noble",
    )
    run_pipeline(config, deps)

    assert captured.get("cap_add") == ["SYS_PTRACE"], (
        f"Expected ['SYS_PTRACE'] in cap_add, got: {captured.get('cap_add')}"
    )


def test_shm_size_auto_wired_when_container_image_overridden():
    """/dev/shm is bumped to 512m when --container-image is set.
    Chrome's default 64 MB shm causes crashes on large pages."""
    captured: dict = {}

    class _CapturingContainers:
        def run(self, **kwargs):
            captured["shm_size"] = kwargs.get("shm_size")
            return _FakeContainer()

    class _CapturingDockerClient:
        containers = _CapturingContainers()

    deps = _base_deps(
        docker_client_factory=lambda: _CapturingDockerClient(),
    )
    config = _config(
        mcp_transport="docker",
        mcp_command=["node", "dist/index.js"],
        container_image="mcr.microsoft.com/playwright:v1.57.0-noble",
    )
    run_pipeline(config, deps)

    assert captured.get("shm_size") == "512m", (
        f"Expected shm_size='512m', got: {captured.get('shm_size')}"
    )


def test_cap_add_and_shm_not_set_without_container_image_override():
    """Without a custom image, cap_add and shm_size stay at secure defaults."""
    captured: dict = {}

    class _CapturingContainers:
        def run(self, **kwargs):
            captured["cap_add"] = kwargs.get("cap_add")
            captured["shm_size"] = kwargs.get("shm_size")
            return _FakeContainer()

    class _CapturingDockerClient:
        containers = _CapturingContainers()

    deps = _base_deps(
        docker_client_factory=lambda: _CapturingDockerClient(),
    )
    config = _config(mcp_transport="docker", mcp_command=["node", "dist/index.js"])
    run_pipeline(config, deps)

    assert captured.get("cap_add") is None, (
        "cap_add should not be set without container_image override"
    )
    assert captured.get("shm_size") is None, (
        "shm_size should not be set without container_image override"
    )


def test_seccomp_unconfined_auto_set_when_container_image_overridden():
    """seccomp=unconfined is needed for Chrome's namespace syscalls in Docker.
    Automatically set when --container-image is used."""
    captured: dict = {}

    class _CapturingContainers:
        def run(self, **kwargs):
            captured["security_opt"] = kwargs.get("security_opt", [])
            return _FakeContainer()

    class _CapturingDockerClient:
        containers = _CapturingContainers()

    deps = _base_deps(
        docker_client_factory=lambda: _CapturingDockerClient(),
    )
    config = _config(
        mcp_transport="docker",
        mcp_command=["node", "dist/index.js"],
        container_image="mcr.microsoft.com/playwright:v1.57.0-noble",
    )
    run_pipeline(config, deps)

    assert "seccomp=unconfined" in captured.get("security_opt", []), (
        f"Expected seccomp=unconfined in security_opt, got: {captured.get('security_opt')}"
    )
    assert "no-new-privileges:true" in captured.get("security_opt", []), (
        "no-new-privileges must be preserved alongside seccomp=unconfined"
    )


def test_writable_rootfs_when_container_image_overridden():
    """Browser containers need a writable rootfs: Chrome's crashpad init
    fails when it cannot write to /var/cache/fontconfig and crash database
    paths that are not predictable enough to cover with tmpfs alone."""
    captured: dict = {}

    class _CapturingContainers:
        def run(self, **kwargs):
            captured["read_only"] = kwargs.get("read_only")
            return _FakeContainer()

    class _CapturingDockerClient:
        containers = _CapturingContainers()

    deps = _base_deps(
        docker_client_factory=lambda: _CapturingDockerClient(),
    )
    config = _config(
        mcp_transport="docker",
        mcp_command=["node", "dist/index.js"],
        container_image="mcr.microsoft.com/playwright:v1.57.0-noble",
    )
    run_pipeline(config, deps)

    assert captured.get("read_only") is False, (
        f"Expected read_only=False for browser container, got: {captured.get('read_only')}"
    )


def test_readonly_rootfs_without_container_image_override():
    """Standard (non-browser) containers keep read_only=True for maximum hardening."""
    captured: dict = {}

    class _CapturingContainers:
        def run(self, **kwargs):
            captured["read_only"] = kwargs.get("read_only")
            return _FakeContainer()

    class _CapturingDockerClient:
        containers = _CapturingContainers()

    deps = _base_deps(
        docker_client_factory=lambda: _CapturingDockerClient(),
    )
    config = _config(mcp_transport="docker", mcp_command=["node", "dist/index.js"])
    run_pipeline(config, deps)

    assert captured.get("read_only") is True, (
        "Expected read_only=True without container_image override"
    )


def test_seccomp_confined_without_container_image_override():
    """Without a custom image, seccomp=unconfined must NOT be added."""
    captured: dict = {}

    class _CapturingContainers:
        def run(self, **kwargs):
            captured["security_opt"] = kwargs.get("security_opt", [])
            return _FakeContainer()

    class _CapturingDockerClient:
        containers = _CapturingContainers()

    deps = _base_deps(
        docker_client_factory=lambda: _CapturingDockerClient(),
    )
    config = _config(mcp_transport="docker", mcp_command=["node", "dist/index.js"])
    run_pipeline(config, deps)

    assert "seccomp=unconfined" not in captured.get("security_opt", [])


def test_tmpfs_not_added_without_container_image_override():
    """Without a custom image, no tmpfs is injected (default images don't need it)."""
    captured: dict = {}

    class _CapturingContainers:
        def run(self, **kwargs):
            captured["tmpfs"] = kwargs.get("tmpfs")
            return _FakeContainer()

    class _CapturingDockerClient:
        containers = _CapturingContainers()

    deps = _base_deps(
        docker_client_factory=lambda: _CapturingDockerClient(),
    )
    config = _config(
        mcp_transport="docker",
        mcp_command=["node", "dist/index.js"],
    )
    run_pipeline(config, deps)

    assert captured.get("tmpfs") is None, (
        f"tmpfs should not be set without container_image override, got: {captured.get('tmpfs')}"
    )


def test_browser_image_startup_cmd_is_chrome_wrapper_not_sleep_infinity():
    """When --container-image is set and no explicit command is given, the
    container startup command is a /bin/sh -c script that writes a Chrome
    --no-sandbox wrapper to /tmp, NOT bare 'sleep infinity'."""
    captured: dict = {}

    class _CapturingContainers:
        def run(self, **kwargs):
            captured["command"] = kwargs.get("command")
            return _FakeContainer()

    class _CapturingDockerClient:
        containers = _CapturingContainers()

    deps = _base_deps(
        docker_client_factory=lambda: _CapturingDockerClient(),
    )
    config = _config(
        mcp_transport="docker",
        mcp_command=["node", "dist/index.js"],
        container_image="mcr.microsoft.com/playwright:v1.57.0-noble",
    )
    run_pipeline(config, deps)

    cmd = captured.get("command", [])
    assert cmd[:2] == ["/bin/sh", "-c"], (
        f"Expected startup via /bin/sh -c, got: {cmd}"
    )
    script = cmd[2] if len(cmd) > 2 else ""
    assert "--no-sandbox" in script, "Chrome wrapper must include --no-sandbox"
    assert "/tmp/chrome-wrapper" in script, "Wrapper must be written to /tmp/chrome-wrapper"
    assert "sleep infinity" in script, "Must still sleep infinity after writing wrapper"


def test_browser_image_injects_chrome_executable_path_env():
    """CHROME_EXECUTABLE_PATH is set to /tmp/chrome-wrapper when
    --container-image is used, so the server picks up our no-sandbox wrapper."""
    captured: dict = {}

    class _CapturingContainers:
        def run(self, **kwargs):
            captured["environment"] = kwargs.get("environment", {})
            return _FakeContainer()

    class _CapturingDockerClient:
        containers = _CapturingContainers()

    deps = _base_deps(
        docker_client_factory=lambda: _CapturingDockerClient(),
    )
    config = _config(
        mcp_transport="docker",
        mcp_command=["node", "dist/index.js"],
        container_image="mcr.microsoft.com/playwright:v1.57.0-noble",
    )
    run_pipeline(config, deps)

    env = captured.get("environment", {})
    assert env.get("CHROME_EXECUTABLE_PATH") == "/tmp/chrome-wrapper", (
        f"Expected CHROME_EXECUTABLE_PATH=/tmp/chrome-wrapper, got: {env.get('CHROME_EXECUTABLE_PATH')}"
    )


def test_pythonpath_not_injected_without_env_monitor():
    """Without EnvironmentMonitor in the list, PYTHONPATH is not touched."""
    captured_env: dict = {}

    class _CapturingContainers:
        def run(self, **kwargs):
            captured_env.update(kwargs.get("environment", {}))
            return _FakeContainer()

    class _CapturingDockerClient:
        containers = _CapturingContainers()

    deps = _base_deps(
        docker_client_factory=lambda: _CapturingDockerClient(),
        monitors_factory=lambda: [],  # no EnvironmentMonitor
    )
    config = _config(mcp_transport="docker", mcp_command=["python", "server.py"])
    run_pipeline(config, deps)

    assert "PYTHONPATH" not in captured_env, (
        f"PYTHONPATH should not be set without EnvironmentMonitor, got: {captured_env}"
    )
