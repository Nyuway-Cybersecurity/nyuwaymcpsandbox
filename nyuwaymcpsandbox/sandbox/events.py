"""Behavioral event types and the BehavioralEvent record.

Every capture source (network, filesystem, env, process, MCP protocol, LLM
driver) emits BehavioralEvent records into a shared BehavioralTimeline. The
detection engine evaluates rules against the merged timeline; output
renderers serialize it for the user.

Event types follow a dotted hierarchy so detection rules can match on
prefix ("network.*", "filesystem.write") without enumerating every leaf.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any

# ── Event type taxonomy ───────────────────────────────────────────────────
# Keep additions here; freeform strings elsewhere risk typos that silently
# skip detection rules.

# Container lifecycle
EVT_CONTAINER_STARTED = "container.started"
EVT_CONTAINER_STOPPED = "container.stopped"
EVT_CONTAINER_ERROR = "container.error"

# Network
EVT_NETWORK_DNS = "network.dns_lookup"
EVT_NETWORK_CONNECT = "network.outbound_connection"
EVT_NETWORK_HTTP = "network.http_request"
EVT_NETWORK_HTTPS = "network.https_request"

# Filesystem
EVT_FS_READ = "filesystem.read"
EVT_FS_WRITE = "filesystem.write"
EVT_FS_DELETE = "filesystem.delete"
EVT_FS_CHMOD = "filesystem.chmod"

# Environment variables
EVT_ENV_READ = "environment.read"

# Process / subprocess
EVT_PROCESS_SPAWN = "process.spawn"
EVT_PROCESS_EXIT = "process.exit"

# MCP protocol
EVT_MCP_TOOL_LIST = "mcp.tool_list"
EVT_MCP_TOOL_INVOKE = "mcp.tool_invocation"
EVT_MCP_PROMPT = "mcp.prompt_response"
EVT_MCP_RESOURCE = "mcp.resource_access"

# LLM driver (Full mode only)
EVT_LLM_PROMPT_SENT = "llm.prompt_sent"
EVT_LLM_RESPONSE = "llm.response_received"

# Event source identifiers - which capture layer produced the event.
SRC_CONTAINER = "container"
SRC_NETWORK = "network_monitor"
SRC_FILESYSTEM = "filesystem_monitor"
SRC_ENV = "env_monitor"
SRC_PROCESS = "process_monitor"
SRC_MCP_CLIENT = "mcp_client"
SRC_LLM_DRIVER = "llm_driver"


@dataclass
class BehavioralEvent:
    """A single observed event in the sandbox.

    Attributes:
        type: dotted event type from the taxonomy above (e.g. "network.dns_lookup")
        source: capture layer that produced the event (e.g. "network_monitor")
        timestamp: seconds since scan start (monotonic-relative, not wall clock)
        payload: type-specific structured data; schema depends on type
        triggered_by: optional event_id of a causally upstream event
            (e.g. an outbound connection triggered_by a tool invocation)
        event_id: stable unique identifier for cross-event references
    """

    type: str
    source: str
    timestamp: float
    payload: dict[str, Any] = field(default_factory=dict)
    triggered_by: str | None = None
    event_id: str = field(default_factory=lambda: uuid.uuid4().hex)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "event_id": self.event_id,
            "type": self.type,
            "source": self.source,
            "timestamp": round(self.timestamp, 6),
            "payload": self.payload,
            "triggered_by": self.triggered_by,
        }

    def matches_type(self, type_or_prefix: str) -> bool:
        """Return True if event matches an exact type or a dotted prefix.

        "network.*" matches every network event; "network.dns_lookup"
        matches only DNS lookups. The trailing ".*" form is the only
        wildcard supported - keep matching cheap and predictable.
        """
        if type_or_prefix.endswith(".*"):
            prefix = type_or_prefix[:-2]
            return self.type == prefix or self.type.startswith(prefix + ".")
        return self.type == type_or_prefix


def now_relative(scan_start_monotonic: float) -> float:
    """Compute scan-relative timestamp from a recorded scan start."""
    return time.monotonic() - scan_start_monotonic
