"""Tiny MCP server used by tests to exercise the real stdio transport.

Handles initialize -> notifications/initialized -> tools/list -> tools/call
for two demo tools:

    echo(text)     - returns text verbatim
    fail()         - returns an MCP tool error so we can test that path

This file is intentionally self-contained: no nyuwaymcpsandbox imports,
no external deps. It runs as `python echo_mcp_server.py` from any
process that needs a real MCP server to talk to.
"""

from __future__ import annotations

import json
import os
import sys

# On Windows, sys.stdout is opened in text mode and translates "\n" to
# "\r\n", which the test client tolerates. Force binary mode anyway so
# the wire output is exactly what we wrote.
if os.name == "nt":  # pragma: no cover - Windows-only
    import msvcrt

    msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)
    msvcrt.setmode(sys.stdin.fileno(), os.O_BINARY)


def _send(msg: dict) -> None:
    line = json.dumps(msg) + "\n"
    sys.stdout.buffer.write(line.encode("utf-8"))
    sys.stdout.buffer.flush()


def _result(msg_id, result: dict) -> dict:
    return {"jsonrpc": "2.0", "id": msg_id, "result": result}


def _error(msg_id, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}}


def _handle(msg: dict) -> dict | None:
    method = msg.get("method")
    msg_id = msg.get("id")

    if method == "initialize":
        return _result(
            msg_id,
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "echo-test", "version": "0.1"},
            },
        )

    if method == "notifications/initialized":
        # Notification - no response.
        return None

    if method == "tools/list":
        return _result(
            msg_id,
            {
                "tools": [
                    {
                        "name": "echo",
                        "description": "Echo the given text",
                        "inputSchema": {
                            "type": "object",
                            "properties": {"text": {"type": "string"}},
                            "required": ["text"],
                        },
                    },
                    {
                        "name": "fail",
                        "description": "Always returns an error",
                        "inputSchema": {"type": "object"},
                    },
                ]
            },
        )

    if method == "tools/call":
        params = msg.get("params") or {}
        name = params.get("name")
        args = params.get("arguments") or {}
        if name == "echo":
            return _result(
                msg_id,
                {
                    "content": [{"type": "text", "text": str(args.get("text", ""))}],
                    "isError": False,
                },
            )
        if name == "fail":
            return _result(
                msg_id,
                {
                    "content": [{"type": "text", "text": "this tool fails on purpose"}],
                    "isError": True,
                },
            )
        return _error(msg_id, -32602, f"Unknown tool: {name}")

    return _error(msg_id, -32601, f"Unknown method: {method}")


def main() -> None:
    stdin = sys.stdin.buffer
    while True:
        line = stdin.readline()
        if not line:
            return
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        response = _handle(msg)
        if response is not None:
            _send(response)


if __name__ == "__main__":
    main()
