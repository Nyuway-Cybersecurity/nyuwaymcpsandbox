"""Tests for the real EnvironmentMonitor + sitecustomize shim.

Three layers of coverage:

1. The shim file: existence as package data + key code patterns.
2. The host-side parser: log-line decoding and event emission via the
   injected ``log_source_factory``.
3. The docker install path: mocked APIClient verifies put_archive +
   exec_create + exec_start are wired correctly.
"""

from __future__ import annotations

import io
import json
import tarfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from nyuwaymcpsandbox.sandbox.events import EVT_ENV_READ
from nyuwaymcpsandbox.sandbox.monitors.environment import (
    LOG_PATH_IN_CONTAINER,
    RUNTIME_DIR_IN_CONTAINER,
    EnvironmentMonitor,
    _build_shim_tar,
    _parse_env_log_line,
)
from nyuwaymcpsandbox.sandbox.timeline import BehavioralTimeline

_SHIM_PATH = (
    Path(__file__).resolve().parent.parent
    / "nyuwaymcpsandbox"
    / "sandbox"
    / "preload"
    / "sitecustomize.py"
)

_WAIT_TIMEOUT = 3.0
_WAIT_TICK = 0.02


def _wait_for(predicate, timeout: float = _WAIT_TIMEOUT) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(_WAIT_TICK)
    return predicate()


def _names(timeline: BehavioralTimeline) -> list[str]:
    return [e.payload["name"] for e in timeline.events if e.type == EVT_ENV_READ]


# ── Sitecustomize shim (package data) ───────────────────────────────────


def test_sitecustomize_ships_as_package_data():
    assert _SHIM_PATH.is_file(), f"missing shim: {_SHIM_PATH}"


def test_sitecustomize_patches_environ_class():
    """The shim must patch os._Environ (the type), not the instance."""
    source = _SHIM_PATH.read_text(encoding="utf-8")
    assert "type(os.environ)" in source
    assert "__getitem__" in source
    assert "get" in source


def test_sitecustomize_uses_known_log_path():
    """The shim writes to the path the host monitor tails."""
    source = _SHIM_PATH.read_text(encoding="utf-8")
    assert "/nyuway_runtime/env_reads.log" in source


def test_sitecustomize_filters_internal_vars():
    """NYUWAY_* should be skipped to avoid recursive logging."""
    source = _SHIM_PATH.read_text(encoding="utf-8")
    assert "NYUWAY_" in source


# ── _build_shim_tar ─────────────────────────────────────────────────────


def test_build_shim_tar_contains_sitecustomize():
    tar_bytes = _build_shim_tar("print('hello')")
    buf = io.BytesIO(tar_bytes)
    with tarfile.open(fileobj=buf, mode="r") as tar:
        names = tar.getnames()
        assert "sitecustomize.py" in names
        member = tar.extractfile("sitecustomize.py")
        assert member is not None
        assert member.read() == b"print('hello')"


def test_build_shim_tar_preserves_size_metadata():
    src = "x = 1\n" * 50
    tar_bytes = _build_shim_tar(src)
    buf = io.BytesIO(tar_bytes)
    with tarfile.open(fileobj=buf, mode="r") as tar:
        info = tar.getmember("sitecustomize.py")
        assert info.size == len(src.encode("utf-8"))


# ── _parse_env_log_line ─────────────────────────────────────────────────


def test_parse_log_line_returns_name():
    line = json.dumps({"name": "AWS_SECRET_ACCESS_KEY", "t": 1.5})
    assert _parse_env_log_line(line) == "AWS_SECRET_ACCESS_KEY"


def test_parse_log_line_ignores_malformed_json():
    assert _parse_env_log_line("not json") is None
    assert _parse_env_log_line("") is None
    assert _parse_env_log_line("   ") is None


def test_parse_log_line_ignores_missing_name():
    assert _parse_env_log_line(json.dumps({"t": 1.5})) is None
    assert _parse_env_log_line(json.dumps({"name": ""})) is None
    assert _parse_env_log_line(json.dumps({"name": None})) is None
    assert _parse_env_log_line(json.dumps([1, 2, 3])) is None


def test_parse_log_line_strips_surrounding_whitespace():
    line = "   " + json.dumps({"name": "HOME"}) + "  \n"
    assert _parse_env_log_line(line) == "HOME"


# ── Reader loop via injected log source ─────────────────────────────────


def _record(name: str) -> bytes:
    return (json.dumps({"name": name, "t": time.monotonic()}) + "\n").encode("utf-8")


def test_env_read_in_log_emits_event():
    monitor = EnvironmentMonitor(
        log_source_factory=lambda: iter([_record("AWS_SECRET_ACCESS_KEY")])
    )
    timeline = BehavioralTimeline()
    monitor.start(container_handle=None, timeline=timeline, scan_start=time.monotonic())
    try:
        assert _wait_for(lambda: "AWS_SECRET_ACCESS_KEY" in _names(timeline))
    finally:
        monitor.stop()


def test_multiple_records_yield_multiple_events():
    chunks = [_record("HOME"), _record("PATH"), _record("AWS_ACCESS_KEY_ID")]
    monitor = EnvironmentMonitor(log_source_factory=lambda: iter(chunks))
    timeline = BehavioralTimeline()
    monitor.start(container_handle=None, timeline=timeline, scan_start=time.monotonic())
    try:
        assert _wait_for(lambda: len(_names(timeline)) == 3)
        assert _names(timeline) == ["HOME", "PATH", "AWS_ACCESS_KEY_ID"]
    finally:
        monitor.stop()


def test_records_split_across_chunks_reassemble():
    """A record split across two stream chunks must still parse."""
    record = _record("SPLIT_VAR")
    half = len(record) // 2
    monitor = EnvironmentMonitor(log_source_factory=lambda: iter([record[:half], record[half:]]))
    timeline = BehavioralTimeline()
    monitor.start(container_handle=None, timeline=timeline, scan_start=time.monotonic())
    try:
        assert _wait_for(lambda: "SPLIT_VAR" in _names(timeline))
    finally:
        monitor.stop()


def test_string_chunks_supported():
    monitor = EnvironmentMonitor(
        log_source_factory=lambda: iter([json.dumps({"name": "STR_VAR"}) + "\n"])
    )
    timeline = BehavioralTimeline()
    monitor.start(container_handle=None, timeline=timeline, scan_start=time.monotonic())
    try:
        assert _wait_for(lambda: "STR_VAR" in _names(timeline))
    finally:
        monitor.stop()


def test_malformed_json_lines_are_skipped():
    chunks = [
        b"not valid json\n",
        _record("VALID_VAR"),
        b"\n",
        b"another bad line\n",
    ]
    monitor = EnvironmentMonitor(log_source_factory=lambda: iter(chunks))
    timeline = BehavioralTimeline()
    monitor.start(container_handle=None, timeline=timeline, scan_start=time.monotonic())
    try:
        assert _wait_for(lambda: "VALID_VAR" in _names(timeline))
        # Only the one valid record should produce an event.
        time.sleep(0.05)
        assert _names(timeline) == ["VALID_VAR"]
    finally:
        monitor.stop()


def test_event_payload_carries_name():
    monitor = EnvironmentMonitor(log_source_factory=lambda: iter([_record("CARRIED")]))
    timeline = BehavioralTimeline()
    monitor.start(container_handle=None, timeline=timeline, scan_start=time.monotonic())
    try:
        assert _wait_for(lambda: any(_names(timeline)))
        event = next(e for e in timeline.events if e.type == EVT_ENV_READ)
        assert event.payload == {"name": "CARRIED"}
    finally:
        monitor.stop()


def test_log_source_exception_swallowed():
    def bad():
        yield _record("FIRST")
        raise OSError("stream broke")

    monitor = EnvironmentMonitor(log_source_factory=bad)
    timeline = BehavioralTimeline()
    monitor.start(container_handle=None, timeline=timeline, scan_start=time.monotonic())
    try:
        assert _wait_for(lambda: "FIRST" in _names(timeline))
    finally:
        monitor.stop()


# ── Lifecycle ───────────────────────────────────────────────────────────


def test_no_docker_handle_is_noop():
    monitor = EnvironmentMonitor()
    timeline = BehavioralTimeline()
    monitor.start(container_handle=None, timeline=timeline, scan_start=time.monotonic())
    assert monitor.is_running
    assert not monitor.install_attempted
    monitor.stop()
    assert timeline.events == []


def test_stop_is_idempotent():
    monitor = EnvironmentMonitor(log_source_factory=lambda: iter([_record("X")]))
    timeline = BehavioralTimeline()
    monitor.start(container_handle=None, timeline=timeline, scan_start=time.monotonic())
    monitor.stop()
    monitor.stop()
    assert not monitor.is_running


def test_no_events_after_stop():
    monitor = EnvironmentMonitor(log_source_factory=lambda: iter([_record("EARLY")]))
    timeline = BehavioralTimeline()
    monitor.start(container_handle=None, timeline=timeline, scan_start=time.monotonic())
    assert _wait_for(lambda: "EARLY" in _names(timeline))
    monitor.stop()
    pre_count = len(timeline.events)
    time.sleep(0.1)
    assert len(timeline.events) == pre_count


def test_reader_thread_is_daemon():
    monitor = EnvironmentMonitor(log_source_factory=lambda: iter([_record("X")]))
    timeline = BehavioralTimeline()
    monitor.start(container_handle=None, timeline=timeline, scan_start=time.monotonic())
    try:
        matches = [t for t in threading.enumerate() if t.name == "env_monitor"]
        if matches:
            assert all(t.daemon for t in matches)
    finally:
        monitor.stop()


# ── Docker install path (mocked APIClient) ──────────────────────────────


@dataclass
class _FakeApi:
    exec_create_calls: list = field(default_factory=list)
    exec_start_calls: list = field(default_factory=list)
    put_archive_calls: list = field(default_factory=list)
    log_stream: list = field(default_factory=list)
    exec_create_raises: Exception | None = None
    put_archive_raises: Exception | None = None
    exec_start_raises: Exception | None = None
    _next_id: int = 0

    def exec_create(self, container, cmd=None, **kwargs):
        self._next_id += 1
        rec = {"container": container, "cmd": cmd, **kwargs}
        self.exec_create_calls.append(rec)
        if self.exec_create_raises is not None:
            raise self.exec_create_raises
        return {"Id": f"exec-{self._next_id}"}

    def exec_start(self, exec_id, **kwargs):
        rec = {"exec_id": exec_id, **kwargs}
        self.exec_start_calls.append(rec)
        if self.exec_start_raises is not None:
            raise self.exec_start_raises
        # For the streaming tail call, return our log generator.
        if kwargs.get("stream"):
            return iter(self.log_stream)
        return b""

    def put_archive(self, container, path, data):
        self.put_archive_calls.append({"container": container, "path": path, "data": data})
        if self.put_archive_raises is not None:
            raise self.put_archive_raises
        return True


@dataclass
class _FakeClient:
    api: _FakeApi


@dataclass
class _FakeTargetContainer:
    client: _FakeClient
    id: str = "target-abc"


@dataclass
class _FakeHandle:
    container: _FakeTargetContainer
    container_id: str = "target-abc"


def _make_handle(*, log_stream=None, **api_overrides) -> tuple[_FakeHandle, _FakeApi]:
    api = _FakeApi(log_stream=log_stream or [], **api_overrides)
    handle = _FakeHandle(container=_FakeTargetContainer(client=_FakeClient(api=api)))
    return handle, api


def test_install_creates_runtime_dir_via_exec():
    handle, api = _make_handle(log_stream=[_record("AWS_SECRET_ACCESS_KEY")])
    monitor = EnvironmentMonitor(shim_source="print('shim')")
    timeline = BehavioralTimeline()
    monitor.start(container_handle=handle, timeline=timeline, scan_start=time.monotonic())
    try:
        # First exec_create call should mkdir + touch.
        first = api.exec_create_calls[0]
        assert first["container"] == "target-abc"
        joined = " ".join(first["cmd"])
        assert RUNTIME_DIR_IN_CONTAINER in joined
        assert LOG_PATH_IN_CONTAINER in joined
        assert "mkdir" in joined
    finally:
        monitor.stop()


def test_install_uses_put_archive_for_shim():
    handle, api = _make_handle(log_stream=[_record("X")])
    monitor = EnvironmentMonitor(shim_source="print('shim')")
    timeline = BehavioralTimeline()
    monitor.start(container_handle=handle, timeline=timeline, scan_start=time.monotonic())
    try:
        assert len(api.put_archive_calls) == 1
        call = api.put_archive_calls[0]
        assert call["container"] == "target-abc"
        assert call["path"] == RUNTIME_DIR_IN_CONTAINER
        # Verify the tar bytes contain our shim source.
        with tarfile.open(fileobj=io.BytesIO(call["data"]), mode="r") as tar:
            member = tar.extractfile("sitecustomize.py")
            assert member is not None
            assert member.read() == b"print('shim')"
    finally:
        monitor.stop()


def test_install_starts_tail_stream():
    handle, api = _make_handle(log_stream=[_record("X")])
    monitor = EnvironmentMonitor(shim_source="print('shim')")
    timeline = BehavioralTimeline()
    monitor.start(container_handle=handle, timeline=timeline, scan_start=time.monotonic())
    try:
        # Second exec_create is the tail.
        tail_call = api.exec_create_calls[1]
        assert "tail" in tail_call["cmd"]
        assert LOG_PATH_IN_CONTAINER in tail_call["cmd"]
        assert tail_call["tty"] is True
        # And exec_start for tail used stream=True.
        tail_start = next(c for c in api.exec_start_calls if c.get("stream"))
        assert tail_start["tty"] is True
    finally:
        monitor.stop()


def test_install_attempted_flag_set():
    handle, _ = _make_handle(log_stream=[_record("X")])
    monitor = EnvironmentMonitor(shim_source="print('shim')")
    timeline = BehavioralTimeline()
    monitor.start(container_handle=handle, timeline=timeline, scan_start=time.monotonic())
    try:
        assert monitor.install_attempted
        assert monitor.install_succeeded
    finally:
        monitor.stop()


def test_install_failure_is_noop():
    handle, _ = _make_handle(exec_create_raises=RuntimeError("daemon down"))
    monitor = EnvironmentMonitor(shim_source="print('shim')")
    timeline = BehavioralTimeline()
    monitor.start(container_handle=handle, timeline=timeline, scan_start=time.monotonic())
    assert monitor.is_running
    assert monitor.install_attempted
    assert not monitor.install_succeeded
    monitor.stop()
    assert timeline.events == []


def test_put_archive_failure_is_noop():
    handle, _ = _make_handle(put_archive_raises=RuntimeError("permission denied"))
    monitor = EnvironmentMonitor(shim_source="print('shim')")
    timeline = BehavioralTimeline()
    monitor.start(container_handle=handle, timeline=timeline, scan_start=time.monotonic())
    monitor.stop()
    assert not monitor.install_succeeded
    assert timeline.events == []


def test_install_end_to_end_emits_events():
    """Full happy path: install + tail stream + JSON parser + event emission."""
    handle, _ = _make_handle(
        log_stream=[
            _record("AWS_SECRET_ACCESS_KEY"),
            _record("ANTHROPIC_API_KEY"),
        ]
    )
    monitor = EnvironmentMonitor(shim_source="print('shim')")
    timeline = BehavioralTimeline()
    monitor.start(container_handle=handle, timeline=timeline, scan_start=time.monotonic())
    try:
        assert _wait_for(lambda: len(_names(timeline)) == 2)
        assert set(_names(timeline)) == {"AWS_SECRET_ACCESS_KEY", "ANTHROPIC_API_KEY"}
    finally:
        monitor.stop()


def test_handle_without_container_id_is_noop():
    @dataclass
    class _NoIdHandle:
        container: Any = None
        container_id: str | None = None

    monitor = EnvironmentMonitor(shim_source="print('shim')")
    timeline = BehavioralTimeline()
    monitor.start(_NoIdHandle(), timeline, time.monotonic())
    assert monitor.is_running
    monitor.stop()
    assert timeline.events == []


def test_empty_shim_source_is_noop():
    handle, _ = _make_handle(log_stream=[_record("X")])
    monitor = EnvironmentMonitor(shim_source="")
    timeline = BehavioralTimeline()
    monitor.start(container_handle=handle, timeline=timeline, scan_start=time.monotonic())
    # install_attempted may remain False because we bail before exec.
    assert not monitor.install_succeeded
    monitor.stop()
    assert timeline.events == []
