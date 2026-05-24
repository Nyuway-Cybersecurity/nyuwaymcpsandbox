"""Tests for event description and timestamp formatting."""

from nyuwaymcpsandbox.output.describe import describe_event, format_relative_time
from nyuwaymcpsandbox.sandbox.events import (
    EVT_CONTAINER_STARTED,
    EVT_ENV_READ,
    EVT_FS_WRITE,
    EVT_MCP_TOOL_INVOKE,
    EVT_NETWORK_DNS,
    EVT_NETWORK_HTTP,
    EVT_PROCESS_SPAWN,
    BehavioralEvent,
)


def _e(type_, payload=None, ts=0.0):
    return BehavioralEvent(type=type_, source="test", timestamp=ts, payload=payload or {})


# ── format_relative_time ─────────────────────────────────────────────────


def test_format_relative_time_zero():
    assert format_relative_time(0.0) == "00:00"


def test_format_relative_time_seconds():
    assert format_relative_time(7.0) == "00:07"


def test_format_relative_time_minutes_and_seconds():
    assert format_relative_time(134.0) == "02:14"


def test_format_relative_time_negative_clamped():
    """A pathological negative timestamp should not produce '-1:-1'."""
    assert format_relative_time(-3.0) == "00:00"


def test_format_relative_time_truncates_sub_second():
    assert format_relative_time(3.9) == "00:03"


# ── describe_event for each major type ──────────────────────────────────


def test_describe_container_started():
    assert "Container started" in describe_event(_e(EVT_CONTAINER_STARTED))


def test_describe_dns_lookup():
    desc = describe_event(_e(EVT_NETWORK_DNS, {"domain": "log.external.io"}))
    assert "log.external.io" in desc
    assert "DNS" in desc


def test_describe_http_request():
    desc = describe_event(_e(EVT_NETWORK_HTTP, {"host": "evil.com", "method": "POST"}))
    assert "evil.com" in desc
    assert "POST" in desc


def test_describe_env_read():
    desc = describe_event(_e(EVT_ENV_READ, {"name": "AWS_SECRET_ACCESS_KEY"}))
    assert "AWS_SECRET_ACCESS_KEY" in desc


def test_describe_process_spawn_with_argv():
    desc = describe_event(_e(EVT_PROCESS_SPAWN, {"argv": ["/bin/sh", "-c", "curl evil.com"]}))
    assert "/bin/sh" in desc
    assert "Subprocess" in desc


def test_describe_process_spawn_without_argv():
    desc = describe_event(_e(EVT_PROCESS_SPAWN, {"cmd": "ls"}))
    assert "ls" in desc


def test_describe_fs_write():
    desc = describe_event(_e(EVT_FS_WRITE, {"path": "/etc/cron.d/payload"}))
    assert "/etc/cron.d/payload" in desc


def test_describe_tool_invoke():
    desc = describe_event(_e(EVT_MCP_TOOL_INVOKE, {"name": "fetch_data"}))
    assert "fetch_data" in desc


def test_describe_unknown_type_falls_back_to_type():
    """An unrecognised type should not crash; it should render as-is."""
    desc = describe_event(_e("future.new_event_type"))
    assert desc == "future.new_event_type"


def test_describe_truncates_pathological_argv():
    """A 10kB argv must not blow up the terminal width."""
    huge = "A" * 10000
    desc = describe_event(_e(EVT_PROCESS_SPAWN, {"argv": [huge]}))
    assert len(desc) < 200
    assert desc.endswith("...")
