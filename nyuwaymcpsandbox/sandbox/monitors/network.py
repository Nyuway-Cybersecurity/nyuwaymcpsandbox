"""Network capture monitor - DNS lookups, v1 scope.

Catches outbound DNS resolutions performed by the sandboxed server.
This is the lightest-weight network signal that's still genuinely
useful: a server reaching out to ``log.external.io`` or a suspicious
TLD shows up as a DNS query well before any payload is exchanged.

Implementation: spawn a sidecar container that shares the target
container's network namespace (``--network container:<id>``) and runs
``tcpdump`` filtered to UDP port 53. The sidecar's stdout is streamed
back to the host and parsed for DNS query names; each name becomes a
``network.dns_lookup`` BehavioralEvent.

Full packet introspection (HTTP request lines, HTTPS host headers via
mitmproxy intercept, TCP/UDP connection metadata) lands in v1.1 with
NFQUEUE + scapy. The Monitor Protocol surface is unchanged so the
broader engine can be swapped underneath without touching pipeline
wiring or detection rules.

Cross-platform note: the sidecar requires Docker, ``nicolaka/netshoot``
(or any image with tcpdump + ``cap_add: NET_RAW``), and the kernel
support for sharing network namespaces. On hosts where the container
handle has no docker client (mocked, --dry-run) the monitor is a
silent no-op.
"""

from __future__ import annotations

import re
import threading
import time
from collections.abc import Callable, Iterable

from nyuwaymcpsandbox.sandbox.events import (
    EVT_NETWORK_DNS,
    SRC_NETWORK,
    BehavioralEvent,
)
from nyuwaymcpsandbox.sandbox.timeline import BehavioralTimeline

DEFAULT_SIDECAR_IMAGE = "nicolaka/netshoot"
# tcpdump in -ln mode: -l line-buffered (so logs stream), -n no DNS
# lookup of IPs (we don't need the names of the resolvers), -i any
# every interface in the shared namespace. The BPF filter narrows to
# DNS traffic so the sidecar stays cheap.
DEFAULT_TCPDUMP_COMMAND = ["tcpdump", "-ln", "-i", "any", "udp", "port", "53"]

# tcpdump's DNS query lines look like:
#   21:14:42.987654 IP 172.17.0.2.35462 > 192.168.65.7.53: 12345+ A? evil.com. (40)
#   21:14:43.011223 IP 172.17.0.2.35462 > 192.168.65.7.53: 12346+ AAAA? evil.com. (40)
#
# The query type and target name are reliably present after the ":". We
# match a known RR type immediately followed by ``? <domain>``.
_DNS_QUERY_RE = re.compile(r"\b(A|AAAA|MX|TXT|CNAME|NS|PTR|SOA|SRV)\?\s+([A-Za-z0-9._\-]+)")


def _parse_dns_queries(line: str) -> list[tuple[str, str]]:
    """Return ``(qtype, domain)`` pairs found in a tcpdump line.

    The domain has any trailing ``.`` (DNS root marker) stripped so
    detection rules can match against ``example.com`` directly.
    """
    out: list[tuple[str, str]] = []
    for match in _DNS_QUERY_RE.finditer(line):
        qtype, domain = match.group(1), match.group(2).rstrip(".")
        if domain:
            out.append((qtype, domain))
    return out


class NetworkMonitor:
    """Capture DNS lookups inside the sandboxed container via a sidecar."""

    name = "network_monitor"

    def __init__(
        self,
        *,
        sidecar_image: str = DEFAULT_SIDECAR_IMAGE,
        sidecar_command: list[str] | None = None,
        log_source_factory: Callable[[], Iterable] | None = None,
    ) -> None:
        """
        Parameters:
            sidecar_image: image with tcpdump. Override only if the
                operator needs a custom toolchain.
            sidecar_command: argv that produces tcpdump-style DNS lines
                on stdout. The default streams DNS traffic from every
                interface in the shared namespace.
            log_source_factory: test injection point. When provided,
                bypasses the sidecar entirely and uses the factory's
                iterable as the line source.
        """
        self._sidecar_image = sidecar_image
        self._sidecar_command = sidecar_command or list(DEFAULT_TCPDUMP_COMMAND)
        self._log_source_factory = log_source_factory
        self._sidecar_container = None
        self._reader_thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._started = False

    # ── Monitor Protocol ────────────────────────────────────────────────

    def start(
        self,
        container_handle: object,
        timeline: BehavioralTimeline,
        scan_start: float,
    ) -> None:
        # Tests override with a canned iterable; production spawns the
        # sidecar against the live docker client.
        if self._log_source_factory is not None:
            log_source = self._log_source_factory()
        else:
            log_source = self._spawn_sidecar(container_handle)

        if log_source is None:
            # No way to capture (no docker, sidecar failed, etc.). Be
            # a silent no-op so the runner doesn't flag start failure.
            self._started = True
            return

        self._stop.clear()
        thread = threading.Thread(
            target=self._reader_loop,
            args=(log_source, timeline, scan_start),
            name="network_monitor",
            daemon=True,
        )
        thread.start()
        self._reader_thread = thread
        self._started = True

    def stop(self) -> None:
        self._stop.set()
        thread = self._reader_thread
        self._reader_thread = None
        if thread is not None:
            try:
                thread.join(timeout=5)
            except Exception:
                pass
        self._cleanup_sidecar()
        self._started = False

    @property
    def is_running(self) -> bool:
        return self._started

    # ── Sidecar lifecycle ───────────────────────────────────────────────

    def _spawn_sidecar(self, container_handle: object):
        """Run tcpdump in the target container's network namespace.

        Returns an iterable of log lines (bytes or str), or None if the
        sidecar couldn't be started. Errors are swallowed - the monitor
        is best-effort.
        """
        container = getattr(container_handle, "container", None)
        if container is None:
            return None
        docker_client = getattr(container, "client", None)
        if docker_client is None or not hasattr(docker_client, "containers"):
            return None
        container_id = getattr(container_handle, "container_id", None) or getattr(
            container, "id", None
        )
        if not container_id:
            return None

        try:
            self._sidecar_container = docker_client.containers.run(
                self._sidecar_image,
                command=list(self._sidecar_command),
                network_mode=f"container:{container_id}",
                cap_add=["NET_RAW", "NET_ADMIN"],
                detach=True,
                stdout=True,
                stderr=True,
            )
        except Exception:
            return None

        try:
            return self._sidecar_container.logs(stream=True, follow=True)
        except Exception:
            return None

    def _cleanup_sidecar(self) -> None:
        sidecar = self._sidecar_container
        self._sidecar_container = None
        if sidecar is None:
            return
        # Stop then force-remove. Errors swallowed - the runner records
        # them as container.error via its own try/except.
        try:
            sidecar.stop(timeout=5)
        except Exception:
            pass
        try:
            sidecar.remove(force=True)
        except Exception:
            pass

    # ── Reader loop ─────────────────────────────────────────────────────

    def _reader_loop(
        self,
        log_source: Iterable,
        timeline: BehavioralTimeline,
        scan_start: float,
    ) -> None:
        try:
            for raw in log_source:
                if self._stop.is_set():
                    return
                if isinstance(raw, bytes):
                    line = raw.decode("utf-8", errors="replace")
                else:
                    line = str(raw)
                for _qtype, domain in _parse_dns_queries(line):
                    timeline.add(
                        BehavioralEvent(
                            type=EVT_NETWORK_DNS,
                            source=SRC_NETWORK,
                            timestamp=time.monotonic() - scan_start,
                            payload={"domain": domain},
                        )
                    )
        except Exception:
            # Reader thread errors are swallowed; the rest of the
            # session still produces a usable report.
            return
