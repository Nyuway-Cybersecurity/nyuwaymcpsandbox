"""Event description and timestamp formatting helpers.

Every renderer needs to turn a BehavioralEvent into a one-line human
description (for the timeline column) and to format a relative
timestamp as mm:ss. Centralising the logic here keeps the three
renderers in lockstep.
"""

from __future__ import annotations

from nyuwaymcpsandbox.sandbox.events import (
    EVT_CONTAINER_ERROR,
    EVT_CONTAINER_STARTED,
    EVT_CONTAINER_STOPPED,
    EVT_ENV_READ,
    EVT_FS_CHMOD,
    EVT_FS_DELETE,
    EVT_FS_READ,
    EVT_FS_WRITE,
    EVT_LLM_PROMPT_SENT,
    EVT_LLM_RESPONSE,
    EVT_MCP_DELAYED_INIT,
    EVT_MCP_PROMPT,
    EVT_MCP_RESOURCE,
    EVT_MCP_SLOW_TOOL,
    EVT_MCP_TOOL_INVOKE,
    EVT_MCP_TOOL_LIST,
    EVT_NETWORK_CONNECT,
    EVT_NETWORK_DNS,
    EVT_NETWORK_HTTP,
    EVT_NETWORK_HTTPS,
    EVT_PROCESS_EXIT,
    EVT_PROCESS_SPAWN,
    BehavioralEvent,
)

# Max characters for argv / payload strings in one-line descriptions.
# Prevents a malicious 10MB argv from blowing up the terminal view.
_MAX_INLINE = 80


def _truncate(value: str, limit: int = _MAX_INLINE) -> str:
    if len(value) <= limit:
        return value
    return value[: limit - 3] + "..."


def format_relative_time(seconds: float) -> str:
    """Format a scan-relative timestamp as mm:ss (or mm:ss.ms for sub-second)."""
    total = max(0.0, seconds)
    minutes = int(total // 60)
    secs = total - minutes * 60
    # Whole-second display for the timeline, two zero-padded digits.
    return f"{minutes:02d}:{int(secs):02d}"


def describe_event(event: BehavioralEvent) -> str:
    """Return a one-line human description of an event.

    Falls back to the event type when no specialised description exists.
    """
    t = event.type
    p = event.payload or {}

    if t == EVT_CONTAINER_STARTED:
        return "Container started, MCP server listening"
    if t == EVT_CONTAINER_STOPPED:
        return "Container stopped"
    if t == EVT_CONTAINER_ERROR:
        return f"Container error: {_truncate(str(p.get('message', '?')))}"

    if t == EVT_NETWORK_DNS:
        return f"DNS lookup: {_truncate(str(p.get('domain', '?')))}"
    if t == EVT_NETWORK_CONNECT:
        host = p.get("host") or p.get("address") or "?"
        port = p.get("port", "?")
        return f"Outbound connection: {host}:{port}"
    if t == EVT_NETWORK_HTTP:
        host = p.get("host", "?")
        method = p.get("method", "GET")
        return f"HTTP {method} {_truncate(str(host))}"
    if t == EVT_NETWORK_HTTPS:
        host = p.get("host", "?")
        method = p.get("method", "GET")
        return f"HTTPS {method} {_truncate(str(host))}"

    if t == EVT_FS_READ:
        return f"File read: {_truncate(str(p.get('path', '?')))}"
    if t == EVT_FS_WRITE:
        return f"File write: {_truncate(str(p.get('path', '?')))}"
    if t == EVT_FS_DELETE:
        return f"File delete: {_truncate(str(p.get('path', '?')))}"
    if t == EVT_FS_CHMOD:
        return f"File chmod: {_truncate(str(p.get('path', '?')))}"

    if t == EVT_ENV_READ:
        return f"Environment variable read: {_truncate(str(p.get('name', '?')))}"

    if t == EVT_PROCESS_SPAWN:
        argv = p.get("argv")
        if isinstance(argv, list) and argv:
            cmd = " ".join(str(a) for a in argv)
        else:
            cmd = str(p.get("cmd", "?"))
        return f"Subprocess spawned: {_truncate(cmd)}"
    if t == EVT_PROCESS_EXIT:
        return f"Subprocess exited (code {p.get('exit_code', '?')})"

    if t == EVT_MCP_TOOL_LIST:
        return "MCP server listed tools"
    if t == EVT_MCP_TOOL_INVOKE:
        return f"Tool '{_truncate(str(p.get('name', '?')))}' invoked"
    if t == EVT_MCP_SLOW_TOOL:
        name = _truncate(str(p.get("name", "?")))
        dur = p.get("duration_seconds", "?")
        return f"Slow tool response: '{name}' took {dur}s"
    if t == EVT_MCP_DELAYED_INIT:
        secs = p.get("startup_seconds", "?")
        return f"Server delayed initialisation: {secs}s before tools/list"
    if t == EVT_MCP_PROMPT:
        return f"MCP prompt: {_truncate(str(p.get('name', '?')))}"
    if t == EVT_MCP_RESOURCE:
        return f"MCP resource access: {_truncate(str(p.get('uri', '?')))}"

    if t == EVT_LLM_PROMPT_SENT:
        return f"LLM driver sent prompt: {_truncate(str(p.get('summary', '?')))}"
    if t == EVT_LLM_RESPONSE:
        return f"LLM driver received response: {_truncate(str(p.get('summary', '?')))}"

    return t
