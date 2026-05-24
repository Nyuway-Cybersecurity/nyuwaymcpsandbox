"""Network capture monitor.

Watches outbound DNS lookups, TCP/UDP connections, and HTTP/HTTPS
requests originating from the sandboxed container. Each observed event
is emitted into the BehavioralTimeline so detection rules can correlate
them with MCP tool invocations.

v1 LINUX IMPLEMENTATION (TODO):
    Attach iptables NFQUEUE in the container's network namespace.
    Parse packets with scapy: DNS queries -> network.dns_lookup events,
    new TCP connections -> network.outbound_connection events, HTTP
    request lines -> network.http_request / .https_request events.
    HTTPS payload introspection lands in v1.1 via mitmproxy intercept.

This module ships the Protocol-compliant skeleton today so CLI wiring,
the MonitorRunner, and detection rules can be developed end-to-end.
The stub emits no events; on a Linux host with the integration
implementation installed, it will start the NFQUEUE worker and stream
captures into the timeline.
"""

from __future__ import annotations

from nyuwaymcpsandbox.sandbox.timeline import BehavioralTimeline


class NetworkMonitor:
    """Capture outbound network activity from the sandboxed container."""

    name = "network_monitor"

    def __init__(self) -> None:
        self._started = False

    def start(
        self,
        container_handle: object,
        timeline: BehavioralTimeline,
        scan_start: float,
    ) -> None:
        # TODO(linux): attach NFQUEUE to the container's network ns and
        # start a worker thread parsing packets into events.
        self._started = True

    def stop(self) -> None:
        # TODO(linux): join the NFQUEUE worker and tear down the queue.
        self._started = False

    @property
    def is_running(self) -> bool:
        return self._started
