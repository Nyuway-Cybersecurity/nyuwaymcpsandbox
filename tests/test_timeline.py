"""Tests for BehavioralTimeline."""

import json

from nyuwaymcpsandbox.sandbox.events import (
    EVT_FS_WRITE,
    EVT_NETWORK_DNS,
    EVT_NETWORK_HTTP,
    EVT_PROCESS_SPAWN,
    SRC_FILESYSTEM,
    SRC_NETWORK,
    SRC_PROCESS,
    BehavioralEvent,
)
from nyuwaymcpsandbox.sandbox.timeline import BehavioralTimeline


def _evt(type_, source, ts, payload=None, triggered_by=None):
    return BehavioralEvent(
        type=type_,
        source=source,
        timestamp=ts,
        payload=payload or {},
        triggered_by=triggered_by,
    )


def test_empty_timeline_has_zero_length():
    tl = BehavioralTimeline()
    assert len(tl) == 0
    assert tl.events == []


def test_add_single_event_appends():
    tl = BehavioralTimeline()
    e = _evt(EVT_NETWORK_DNS, SRC_NETWORK, 0.5)
    tl.add(e)
    assert len(tl) == 1
    assert tl.events[0] is e


def test_events_returned_sorted_by_timestamp():
    tl = BehavioralTimeline()
    tl.add(_evt(EVT_NETWORK_DNS, SRC_NETWORK, 5.0))
    tl.add(_evt(EVT_FS_WRITE, SRC_FILESYSTEM, 1.0))
    tl.add(_evt(EVT_PROCESS_SPAWN, SRC_PROCESS, 3.0))
    timestamps = [e.timestamp for e in tl.events]
    assert timestamps == [1.0, 3.0, 5.0]


def test_equal_timestamps_preserve_insertion_order():
    """Two captures firing at the same instant must keep emission order."""
    tl = BehavioralTimeline()
    first = _evt(EVT_NETWORK_DNS, SRC_NETWORK, 2.0)
    second = _evt(EVT_PROCESS_SPAWN, SRC_PROCESS, 2.0)
    tl.add(first)
    tl.add(second)
    ordered = tl.events
    assert ordered[0] is first
    assert ordered[1] is second


def test_merge_combines_two_timelines():
    a = BehavioralTimeline()
    a.add(_evt(EVT_NETWORK_DNS, SRC_NETWORK, 1.0))
    b = BehavioralTimeline()
    b.add(_evt(EVT_FS_WRITE, SRC_FILESYSTEM, 2.0))
    a.merge(b)
    assert len(a) == 2
    # b is untouched
    assert len(b) == 1


def test_merge_resorts_correctly():
    """After merge, the combined order must still be chronological."""
    a = BehavioralTimeline()
    a.add(_evt(EVT_NETWORK_DNS, SRC_NETWORK, 5.0))
    b = BehavioralTimeline()
    b.add(_evt(EVT_FS_WRITE, SRC_FILESYSTEM, 1.0))
    b.add(_evt(EVT_PROCESS_SPAWN, SRC_PROCESS, 3.0))
    a.merge(b)
    timestamps = [e.timestamp for e in a.events]
    assert timestamps == [1.0, 3.0, 5.0]


def test_filter_by_type_exact():
    tl = BehavioralTimeline()
    tl.add(_evt(EVT_NETWORK_DNS, SRC_NETWORK, 1.0))
    tl.add(_evt(EVT_NETWORK_HTTP, SRC_NETWORK, 2.0))
    tl.add(_evt(EVT_FS_WRITE, SRC_FILESYSTEM, 3.0))
    dns_only = tl.filter_by_type(EVT_NETWORK_DNS)
    assert len(dns_only) == 1
    assert dns_only[0].type == EVT_NETWORK_DNS


def test_filter_by_type_wildcard():
    tl = BehavioralTimeline()
    tl.add(_evt(EVT_NETWORK_DNS, SRC_NETWORK, 1.0))
    tl.add(_evt(EVT_NETWORK_HTTP, SRC_NETWORK, 2.0))
    tl.add(_evt(EVT_FS_WRITE, SRC_FILESYSTEM, 3.0))
    network_only = tl.filter_by_type("network.*")
    assert len(network_only) == 2
    assert {e.type for e in network_only} == {EVT_NETWORK_DNS, EVT_NETWORK_HTTP}


def test_filter_by_source():
    tl = BehavioralTimeline()
    tl.add(_evt(EVT_NETWORK_DNS, SRC_NETWORK, 1.0))
    tl.add(_evt(EVT_FS_WRITE, SRC_FILESYSTEM, 2.0))
    net = tl.filter_by_source(SRC_NETWORK)
    assert len(net) == 1
    assert net[0].source == SRC_NETWORK


def test_caused_by_returns_correlated_events():
    """An outbound HTTP triggered by a tool invocation should be linked."""
    tl = BehavioralTimeline()
    tool_event = _evt(EVT_PROCESS_SPAWN, SRC_PROCESS, 1.0)
    tl.add(tool_event)
    tl.add(
        _evt(
            EVT_NETWORK_HTTP,
            SRC_NETWORK,
            1.1,
            triggered_by=tool_event.event_id,
        )
    )
    tl.add(_evt(EVT_FS_WRITE, SRC_FILESYSTEM, 2.0))  # unrelated
    caused = tl.caused_by(tool_event.event_id)
    assert len(caused) == 1
    assert caused[0].type == EVT_NETWORK_HTTP


def test_to_json_round_trips():
    tl = BehavioralTimeline()
    tl.add(_evt(EVT_NETWORK_DNS, SRC_NETWORK, 1.0, payload={"domain": "evil.com"}))
    parsed = json.loads(tl.to_json())
    assert parsed["event_count"] == 1
    assert parsed["events"][0]["type"] == EVT_NETWORK_DNS
    assert parsed["events"][0]["payload"]["domain"] == "evil.com"


def test_iter_yields_sorted_events():
    """Iterating a timeline directly should be chronological."""
    tl = BehavioralTimeline()
    tl.add(_evt(EVT_NETWORK_DNS, SRC_NETWORK, 2.0))
    tl.add(_evt(EVT_FS_WRITE, SRC_FILESYSTEM, 1.0))
    timestamps = [e.timestamp for e in tl]
    assert timestamps == [1.0, 2.0]
