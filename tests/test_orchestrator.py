"""Docker orchestrator tests.

The docker SDK is replaced end-to-end with a stub. These tests verify
the secure-by-default lifecycle without requiring Docker on the host.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from nyuwaymcpsandbox.sandbox.events import (
    EVT_CONTAINER_ERROR,
    EVT_CONTAINER_STARTED,
    EVT_CONTAINER_STOPPED,
)
from nyuwaymcpsandbox.sandbox.orchestrator import (
    ContainerConfig,
    OrchestratorError,
    _build_run_kwargs,
    container_session,
)
from nyuwaymcpsandbox.sandbox.timeline import BehavioralTimeline

# ── Fake docker client ───────────────────────────────────────────────────


@dataclass
class FakeContainer:
    id: str = "fakecontainer123"
    attrs: dict = field(default_factory=lambda: {"State": {"ExitCode": 0}})
    stopped: bool = False
    removed: bool = False
    stop_should_raise: Exception | None = None
    remove_should_raise: Exception | None = None

    def stop(self, timeout=5):
        if self.stop_should_raise:
            raise self.stop_should_raise
        self.stopped = True

    def remove(self, force=False):
        if self.remove_should_raise:
            raise self.remove_should_raise
        self.removed = True


@dataclass
class FakeContainers:
    container_to_return: FakeContainer = field(default_factory=FakeContainer)
    run_kwargs_captured: dict = field(default_factory=dict)
    run_should_raise: Exception | None = None

    def run(self, **kwargs):
        self.run_kwargs_captured = kwargs
        if self.run_should_raise:
            raise self.run_should_raise
        return self.container_to_return


@dataclass
class FakeDockerClient:
    containers: FakeContainers = field(default_factory=FakeContainers)


def _make_factory(client=None, container=None, run_raises=None):
    """Build a client_factory callable for container_session."""
    if client is None:
        client = FakeDockerClient()
    if container is not None:
        client.containers.container_to_return = container
    if run_raises is not None:
        client.containers.run_should_raise = run_raises

    def factory():
        return client

    return factory, client


def _config(tmp_path: Path, **overrides) -> ContainerConfig:
    base = {
        "image": "python:3.12-slim",
        "source_path": tmp_path,
        "command": ["python", "server.py"],
    }
    base.update(overrides)
    return ContainerConfig(**base)


# ── _build_run_kwargs ────────────────────────────────────────────────────


def test_run_kwargs_network_mode_none_by_default(tmp_path):
    kw = _build_run_kwargs(_config(tmp_path))
    assert kw["network_mode"] == "none"


def test_run_kwargs_network_mode_bridge_when_allow_network(tmp_path):
    kw = _build_run_kwargs(_config(tmp_path, allow_network=True))
    assert kw["network_mode"] == "bridge"


def test_run_kwargs_mounts_source_read_only(tmp_path):
    kw = _build_run_kwargs(_config(tmp_path))
    volumes = kw["volumes"]
    bind = next(iter(volumes.values()))
    assert bind["mode"] == "ro"
    assert bind["bind"] == "/src"


def test_run_kwargs_drops_all_capabilities(tmp_path):
    kw = _build_run_kwargs(_config(tmp_path))
    assert kw["cap_drop"] == ["ALL"]


def test_run_kwargs_no_new_privileges(tmp_path):
    kw = _build_run_kwargs(_config(tmp_path))
    assert "no-new-privileges:true" in kw["security_opt"]


def test_run_kwargs_read_only_root(tmp_path):
    kw = _build_run_kwargs(_config(tmp_path))
    assert kw["read_only"] is True


def test_run_kwargs_resource_limits(tmp_path):
    kw = _build_run_kwargs(_config(tmp_path, mem_limit="256m", cpu_quota=0.5, pids_limit=50))
    assert kw["mem_limit"] == "256m"
    assert kw["nano_cpus"] == 500_000_000
    assert kw["pids_limit"] == 50


def test_run_kwargs_detached(tmp_path):
    kw = _build_run_kwargs(_config(tmp_path))
    assert kw["detach"] is True


def test_run_kwargs_no_tmpfs_by_default(tmp_path):
    kw = _build_run_kwargs(_config(tmp_path))
    assert "tmpfs" not in kw


def test_run_kwargs_tmpfs_included_when_set(tmp_path):
    kw = _build_run_kwargs(_config(tmp_path, tmpfs={"/tmp": "size=256m"}))
    assert kw["tmpfs"] == {"/tmp": "size=256m"}


def test_run_kwargs_tmpfs_multiple_mounts(tmp_path):
    kw = _build_run_kwargs(_config(tmp_path, tmpfs={"/tmp": "size=128m", "/run": "size=64m"}))
    assert kw["tmpfs"] == {"/tmp": "size=128m", "/run": "size=64m"}


def test_run_kwargs_no_cap_add_by_default(tmp_path):
    kw = _build_run_kwargs(_config(tmp_path))
    assert "cap_add" not in kw


def test_run_kwargs_cap_add_included_when_set(tmp_path):
    kw = _build_run_kwargs(_config(tmp_path, cap_add=["SYS_PTRACE"]))
    assert kw["cap_add"] == ["SYS_PTRACE"]


def test_run_kwargs_no_shm_size_by_default(tmp_path):
    kw = _build_run_kwargs(_config(tmp_path))
    assert "shm_size" not in kw


def test_run_kwargs_shm_size_included_when_set(tmp_path):
    kw = _build_run_kwargs(_config(tmp_path, shm_size="512m"))
    assert kw["shm_size"] == "512m"


def test_run_kwargs_seccomp_unconfined_false_by_default(tmp_path):
    kw = _build_run_kwargs(_config(tmp_path))
    assert "seccomp=unconfined" not in kw.get("security_opt", [])


def test_run_kwargs_seccomp_unconfined_appended_when_set(tmp_path):
    kw = _build_run_kwargs(_config(tmp_path, seccomp_unconfined=True))
    assert "seccomp=unconfined" in kw["security_opt"]
    assert "no-new-privileges:true" in kw["security_opt"]


def test_run_kwargs_read_only_true_by_default(tmp_path):
    kw = _build_run_kwargs(_config(tmp_path))
    assert kw["read_only"] is True


def test_run_kwargs_read_only_false_when_allow_writable_rootfs(tmp_path):
    kw = _build_run_kwargs(_config(tmp_path, allow_writable_rootfs=True))
    assert kw["read_only"] is False


def test_run_kwargs_passes_environment(tmp_path):
    kw = _build_run_kwargs(_config(tmp_path, env={"FOO": "bar"}))
    assert kw["environment"] == {"FOO": "bar"}


# ── container_session lifecycle ──────────────────────────────────────────


def test_session_emits_started_and_stopped(tmp_path):
    timeline = BehavioralTimeline()
    factory, client = _make_factory()
    config = _config(tmp_path)
    with container_session(config, timeline, scan_start=time.monotonic(), client_factory=factory):
        pass
    types = [e.type for e in timeline.events]
    assert EVT_CONTAINER_STARTED in types
    assert EVT_CONTAINER_STOPPED in types


def test_session_stopped_event_carries_exit_code(tmp_path):
    timeline = BehavioralTimeline()
    container = FakeContainer(attrs={"State": {"ExitCode": 42}})
    factory, _ = _make_factory(container=container)
    with container_session(
        _config(tmp_path), timeline, scan_start=time.monotonic(), client_factory=factory
    ):
        pass
    stopped = next(e for e in timeline.events if e.type == EVT_CONTAINER_STOPPED)
    assert stopped.payload["exit_code"] == 42


def test_session_stopped_event_triggered_by_started(tmp_path):
    """The container.stopped event must causally link to container.started."""
    timeline = BehavioralTimeline()
    factory, _ = _make_factory()
    with container_session(
        _config(tmp_path), timeline, scan_start=time.monotonic(), client_factory=factory
    ):
        pass
    started = next(e for e in timeline.events if e.type == EVT_CONTAINER_STARTED)
    stopped = next(e for e in timeline.events if e.type == EVT_CONTAINER_STOPPED)
    assert stopped.triggered_by == started.event_id


def test_session_yields_handle_with_container_id(tmp_path):
    timeline = BehavioralTimeline()
    container = FakeContainer(id="abc123def")
    factory, _ = _make_factory(container=container)
    with container_session(
        _config(tmp_path), timeline, scan_start=time.monotonic(), client_factory=factory
    ) as handle:
        assert handle.container_id == "abc123def"
        assert handle.image == "python:3.12-slim"


def test_session_runs_stop_and_remove(tmp_path):
    timeline = BehavioralTimeline()
    container = FakeContainer()
    factory, _ = _make_factory(container=container)
    with container_session(
        _config(tmp_path), timeline, scan_start=time.monotonic(), client_factory=factory
    ):
        pass
    assert container.stopped
    assert container.removed


def test_session_swallows_stop_errors_as_container_error(tmp_path):
    """A stop() failure must not raise from the context manager."""
    timeline = BehavioralTimeline()
    container = FakeContainer(stop_should_raise=RuntimeError("stop boom"))
    factory, _ = _make_factory(container=container)
    with container_session(
        _config(tmp_path), timeline, scan_start=time.monotonic(), client_factory=factory
    ):
        pass
    errors = [e for e in timeline.events if e.type == EVT_CONTAINER_ERROR]
    assert any("stop" in e.payload.get("message", "") for e in errors)
    # Remove should still run.
    assert container.removed


def test_session_swallows_remove_errors_as_container_error(tmp_path):
    timeline = BehavioralTimeline()
    container = FakeContainer(remove_should_raise=RuntimeError("remove boom"))
    factory, _ = _make_factory(container=container)
    with container_session(
        _config(tmp_path), timeline, scan_start=time.monotonic(), client_factory=factory
    ):
        pass
    errors = [e for e in timeline.events if e.type == EVT_CONTAINER_ERROR]
    assert any("remove" in e.payload.get("message", "") for e in errors)


def test_session_run_failure_raises_orchestrator_error(tmp_path):
    timeline = BehavioralTimeline()
    factory, _ = _make_factory(run_raises=RuntimeError("docker daemon down"))
    with pytest.raises(OrchestratorError, match="Could not start container"):
        with container_session(
            _config(tmp_path), timeline, scan_start=time.monotonic(), client_factory=factory
        ):
            pass
    # An error event is still recorded before raising.
    errors = [e for e in timeline.events if e.type == EVT_CONTAINER_ERROR]
    assert any("container.run failed" in e.payload.get("message", "") for e in errors)


def test_session_cleanup_happens_on_driver_exception(tmp_path):
    """If the user code inside the `with` raises, cleanup still runs."""
    timeline = BehavioralTimeline()
    container = FakeContainer()
    factory, _ = _make_factory(container=container)
    with pytest.raises(RuntimeError, match="driver exploded"):
        with container_session(
            _config(tmp_path), timeline, scan_start=time.monotonic(), client_factory=factory
        ):
            raise RuntimeError("driver exploded")
    assert container.stopped
    assert container.removed
    # Stopped event must still have been emitted.
    assert any(e.type == EVT_CONTAINER_STOPPED for e in timeline.events)


def test_session_event_payloads_carry_image_and_command(tmp_path):
    timeline = BehavioralTimeline()
    factory, _ = _make_factory()
    config = _config(tmp_path, command=["python", "server.py", "--port", "8080"])
    with container_session(config, timeline, scan_start=time.monotonic(), client_factory=factory):
        pass
    started = next(e for e in timeline.events if e.type == EVT_CONTAINER_STARTED)
    assert started.payload["image"] == "python:3.12-slim"
    assert started.payload["command"] == ["python", "server.py", "--port", "8080"]
    assert started.payload["network_mode"] == "none"
