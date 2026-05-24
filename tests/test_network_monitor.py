"""Tests for the real DNS-only NetworkMonitor.

The reader loop is exercised with an injected ``log_source_factory``
that produces canned tcpdump-style lines. The sidecar spawn path is
mock-tested separately so we don't need Docker on the test runner.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any

from nyuwaymcpsandbox.sandbox.events import EVT_NETWORK_DNS
from nyuwaymcpsandbox.sandbox.monitors.network import (
    DEFAULT_SIDECAR_IMAGE,
    NetworkMonitor,
    _parse_dns_queries,
)
from nyuwaymcpsandbox.sandbox.timeline import BehavioralTimeline

_WAIT_TIMEOUT = 3.0
_WAIT_TICK = 0.02


def _wait_for(predicate, timeout: float = _WAIT_TIMEOUT) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(_WAIT_TICK)
    return predicate()


def _domains(timeline: BehavioralTimeline) -> list[str]:
    return [e.payload["domain"] for e in timeline.events if e.type == EVT_NETWORK_DNS]


# ── _parse_dns_queries ───────────────────────────────────────────────────


def test_parse_simple_A_query():
    line = "21:14:42.987654 IP 172.17.0.2.35462 > 192.168.65.7.53: 12345+ A? evil.com. (40)"
    assert _parse_dns_queries(line) == [("A", "evil.com")]


def test_parse_AAAA_query():
    line = "12:00:00 IP x.53 > y.53: 1+ AAAA? example.org. (40)"
    assert _parse_dns_queries(line) == [("AAAA", "example.org")]


def test_parse_strips_trailing_root_dot():
    """tcpdump prints names with trailing '.'; detection rules don't expect it."""
    line = "12:00:00 IP x > y: 1+ A? subdomain.example.com. (1)"
    assert _parse_dns_queries(line) == [("A", "subdomain.example.com")]


def test_parse_multiple_queries_on_one_line():
    """Some packet captures combine multiple records in a single output line."""
    line = "12:00 1+ A? foo.com. (1)  2+ AAAA? bar.org. (1)"
    assert _parse_dns_queries(line) == [("A", "foo.com"), ("AAAA", "bar.org")]


def test_parse_handles_unknown_rr_types():
    """Anything outside the known set is ignored."""
    line = "12:00 1+ ANY? x.com. (1)"
    assert _parse_dns_queries(line) == []


def test_parse_non_dns_lines_yield_no_matches():
    assert _parse_dns_queries("hello world") == []
    assert _parse_dns_queries("") == []
    assert _parse_dns_queries("12:00:00 IP x > y: HTTP GET /thing") == []


def test_parse_handles_punycode_and_dashes():
    line = "12:00 1+ A? xn--bar-fda-q1aaa.example-host.com. (1)"
    result = _parse_dns_queries(line)
    assert result == [("A", "xn--bar-fda-q1aaa.example-host.com")]


def test_parse_other_known_rr_types():
    for qtype in ("MX", "TXT", "CNAME", "NS", "PTR", "SOA", "SRV"):
        line = f"12:00 1+ {qtype}? probe.example. (1)"
        assert _parse_dns_queries(line) == [(qtype, "probe.example")]


# ── Reader loop via injected log source ──────────────────────────────────


def _line(*parts: str) -> bytes:
    """Build a tcpdump-style bytes line (the real source yields bytes)."""
    return (" ".join(parts) + "\n").encode("utf-8")


def test_dns_query_in_log_emits_event():
    lines = [
        _line("12:00 1+ A? evil.com. (40)"),
    ]
    monitor = NetworkMonitor(log_source_factory=lambda: iter(lines))
    timeline = BehavioralTimeline()
    monitor.start(container_handle=None, timeline=timeline, scan_start=time.monotonic())
    try:
        assert _wait_for(lambda: "evil.com" in _domains(timeline))
    finally:
        monitor.stop()


def test_multiple_lines_yield_multiple_events():
    lines = [
        _line("12:00 1+ A? alpha.example. (40)"),
        _line("12:01 2+ AAAA? beta.example. (40)"),
        _line("12:02 3+ A? gamma.example. (40)"),
    ]
    monitor = NetworkMonitor(log_source_factory=lambda: iter(lines))
    timeline = BehavioralTimeline()
    monitor.start(container_handle=None, timeline=timeline, scan_start=time.monotonic())
    try:
        assert _wait_for(lambda: len(_domains(timeline)) == 3)
        assert _domains(timeline) == ["alpha.example", "beta.example", "gamma.example"]
    finally:
        monitor.stop()


def test_string_lines_also_supported():
    """log_source may yield str (debug paths); decode is best-effort."""
    monitor = NetworkMonitor(
        log_source_factory=lambda: iter(["12:00 1+ A? str-domain.com. (40)\n"])
    )
    timeline = BehavioralTimeline()
    monitor.start(container_handle=None, timeline=timeline, scan_start=time.monotonic())
    try:
        assert _wait_for(lambda: "str-domain.com" in _domains(timeline))
    finally:
        monitor.stop()


def test_event_payload_carries_domain():
    lines = [_line("12:00 1+ A? exact-domain.com. (40)")]
    monitor = NetworkMonitor(log_source_factory=lambda: iter(lines))
    timeline = BehavioralTimeline()
    monitor.start(container_handle=None, timeline=timeline, scan_start=time.monotonic())
    try:
        assert _wait_for(lambda: any(_domains(timeline)))
        event = next(e for e in timeline.events if e.type == EVT_NETWORK_DNS)
        assert event.payload == {"domain": "exact-domain.com"}
    finally:
        monitor.stop()


def test_timestamps_are_scan_relative():
    lines = [_line("12:00 1+ A? probe.com. (40)")]
    monitor = NetworkMonitor(log_source_factory=lambda: iter(lines))
    timeline = BehavioralTimeline()
    scan_start = time.monotonic()
    monitor.start(container_handle=None, timeline=timeline, scan_start=scan_start)
    try:
        assert _wait_for(lambda: any(_domains(timeline)))
        event = next(e for e in timeline.events if e.type == EVT_NETWORK_DNS)
        assert 0 <= event.timestamp < 30
    finally:
        monitor.stop()


def test_non_dns_log_lines_emit_nothing():
    lines = [_line("hello world"), _line("server started"), _line("INFO: ready")]
    monitor = NetworkMonitor(log_source_factory=lambda: iter(lines))
    timeline = BehavioralTimeline()
    monitor.start(container_handle=None, timeline=timeline, scan_start=time.monotonic())
    try:
        time.sleep(0.1)
        assert _domains(timeline) == []
    finally:
        monitor.stop()


def test_reader_exception_in_log_source_does_not_propagate():
    """A log source that errors mid-stream must not crash the monitor."""

    def bad_source():
        yield _line("12:00 1+ A? first.com. (40)")
        raise OSError("stream broke")

    monitor = NetworkMonitor(log_source_factory=bad_source)
    timeline = BehavioralTimeline()
    monitor.start(container_handle=None, timeline=timeline, scan_start=time.monotonic())
    try:
        # The first event still lands; the exception is swallowed.
        assert _wait_for(lambda: "first.com" in _domains(timeline))
    finally:
        monitor.stop()


# ── Lifecycle ────────────────────────────────────────────────────────────


def test_no_log_source_factory_and_no_docker_is_noop():
    """Without a factory and without a real docker client, no-op cleanly."""
    monitor = NetworkMonitor()
    timeline = BehavioralTimeline()
    # container_handle is None: no .container, no docker.
    monitor.start(container_handle=None, timeline=timeline, scan_start=time.monotonic())
    assert monitor.is_running
    monitor.stop()
    assert timeline.events == []


def test_stop_is_idempotent():
    lines = [_line("12:00 1+ A? x.com. (40)")]
    monitor = NetworkMonitor(log_source_factory=lambda: iter(lines))
    timeline = BehavioralTimeline()
    monitor.start(container_handle=None, timeline=timeline, scan_start=time.monotonic())
    monitor.stop()
    monitor.stop()  # second call must not raise
    assert not monitor.is_running


def test_no_events_after_stop():
    """Pump a finite source through, stop, verify no late events arrive."""
    lines = [_line("12:00 1+ A? early.com. (40)")]
    monitor = NetworkMonitor(log_source_factory=lambda: iter(lines))
    timeline = BehavioralTimeline()
    monitor.start(container_handle=None, timeline=timeline, scan_start=time.monotonic())
    assert _wait_for(lambda: "early.com" in _domains(timeline))
    monitor.stop()
    pre_count = len(timeline.events)
    time.sleep(0.1)
    assert len(timeline.events) == pre_count


def test_reader_thread_is_daemon():
    """Daemon reader so process exit isn't blocked if stop is missed."""
    lines = [_line("12:00 1+ A? x.com. (40)")]
    monitor = NetworkMonitor(log_source_factory=lambda: iter(lines))
    timeline = BehavioralTimeline()
    monitor.start(container_handle=None, timeline=timeline, scan_start=time.monotonic())
    try:
        matches = [t for t in threading.enumerate() if t.name == "network_monitor"]
        # Thread may have already exited if the source was tiny; just
        # require that when it did exist it was daemonised.
        if matches:
            assert all(t.daemon for t in matches)
    finally:
        monitor.stop()


# ── Sidecar spawn (mocked docker) ────────────────────────────────────────


@dataclass
class _FakeSidecarContainer:
    log_lines: list[bytes] = field(default_factory=list)
    stop_called: bool = False
    remove_called: bool = False
    log_kwargs_captured: dict = field(default_factory=dict)

    def logs(self, **kwargs):
        self.log_kwargs_captured = kwargs
        return iter(self.log_lines)

    def stop(self, timeout=5):
        self.stop_called = True

    def remove(self, force=False):
        self.remove_called = True


@dataclass
class _FakeContainers:
    sidecar_to_return: _FakeSidecarContainer = field(default_factory=_FakeSidecarContainer)
    run_kwargs_captured: dict = field(default_factory=dict)
    run_should_raise: Exception | None = None

    def run(self, image, **kwargs):
        self.run_kwargs_captured = {"image": image, **kwargs}
        if self.run_should_raise is not None:
            raise self.run_should_raise
        return self.sidecar_to_return


@dataclass
class _FakeDockerClient:
    containers: _FakeContainers = field(default_factory=_FakeContainers)


@dataclass
class _FakeTargetContainer:
    client: Any
    id: str = "target-abc"


@dataclass
class _FakeHandle:
    container: _FakeTargetContainer
    container_id: str = "target-abc"


def _make_handle_with_docker(sidecar_lines: list[bytes] | None = None):
    sidecar = _FakeSidecarContainer(log_lines=sidecar_lines or [])
    client = _FakeDockerClient(containers=_FakeContainers(sidecar_to_return=sidecar))
    handle = _FakeHandle(container=_FakeTargetContainer(client=client))
    return handle, client, sidecar


def test_sidecar_run_uses_target_network_namespace():
    handle, client, _ = _make_handle_with_docker([_line("12:00 1+ A? x.com. (40)")])
    monitor = NetworkMonitor()
    timeline = BehavioralTimeline()
    monitor.start(container_handle=handle, timeline=timeline, scan_start=time.monotonic())
    try:
        kw = client.containers.run_kwargs_captured
        assert kw["network_mode"] == "container:target-abc"
        assert kw["image"] == DEFAULT_SIDECAR_IMAGE
        assert "NET_RAW" in kw["cap_add"]
        assert "NET_ADMIN" in kw["cap_add"]
        assert kw["detach"] is True
    finally:
        monitor.stop()


def test_sidecar_produces_dns_events_end_to_end():
    handle, _, _ = _make_handle_with_docker(
        [
            _line("12:00 1+ A? alpha.com. (40)"),
            _line("12:01 2+ AAAA? beta.com. (40)"),
        ]
    )
    monitor = NetworkMonitor()
    timeline = BehavioralTimeline()
    monitor.start(container_handle=handle, timeline=timeline, scan_start=time.monotonic())
    try:
        assert _wait_for(lambda: set(_domains(timeline)) == {"alpha.com", "beta.com"})
    finally:
        monitor.stop()


def test_sidecar_stopped_and_removed_on_stop():
    handle, _, sidecar = _make_handle_with_docker([_line("12:00 1+ A? x.com. (40)")])
    monitor = NetworkMonitor()
    timeline = BehavioralTimeline()
    monitor.start(container_handle=handle, timeline=timeline, scan_start=time.monotonic())
    monitor.stop()
    assert sidecar.stop_called
    assert sidecar.remove_called


def test_sidecar_logs_called_with_stream_and_follow():
    handle, _, sidecar = _make_handle_with_docker([_line("12:00 1+ A? x.com. (40)")])
    monitor = NetworkMonitor()
    timeline = BehavioralTimeline()
    monitor.start(container_handle=handle, timeline=timeline, scan_start=time.monotonic())
    try:
        assert sidecar.log_kwargs_captured.get("stream") is True
        assert sidecar.log_kwargs_captured.get("follow") is True
    finally:
        monitor.stop()


def test_sidecar_run_failure_falls_back_to_noop():
    sidecar = _FakeSidecarContainer()
    client = _FakeDockerClient(
        containers=_FakeContainers(
            sidecar_to_return=sidecar,
            run_should_raise=RuntimeError("netshoot image missing"),
        )
    )
    handle = _FakeHandle(container=_FakeTargetContainer(client=client))
    monitor = NetworkMonitor()
    timeline = BehavioralTimeline()
    monitor.start(container_handle=handle, timeline=timeline, scan_start=time.monotonic())
    # No crash; no DNS events; stop() is clean.
    assert monitor.is_running
    monitor.stop()
    assert timeline.events == []
    # Sidecar was never alive so cleanup didn't call stop/remove.
    assert not sidecar.stop_called


def test_custom_sidecar_image_and_command():
    handle, client, _ = _make_handle_with_docker([])
    monitor = NetworkMonitor(
        sidecar_image="myorg/custom-tcpdump:latest",
        sidecar_command=["tcpdump", "-i", "eth0", "udp"],
    )
    timeline = BehavioralTimeline()
    monitor.start(container_handle=handle, timeline=timeline, scan_start=time.monotonic())
    try:
        kw = client.containers.run_kwargs_captured
        assert kw["image"] == "myorg/custom-tcpdump:latest"
        assert kw["command"] == ["tcpdump", "-i", "eth0", "udp"]
    finally:
        monitor.stop()
