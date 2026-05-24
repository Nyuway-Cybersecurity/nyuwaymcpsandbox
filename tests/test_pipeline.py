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


def test_default_llm_backend_factory_raises_pipeline_not_ready():
    """Real LLM backend not wired; Full mode without --dry-run fails clearly."""
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
    with pytest.raises(PipelineNotReady, match="LLM backend"):
        run_pipeline(_config(mode="full"), deps)


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
