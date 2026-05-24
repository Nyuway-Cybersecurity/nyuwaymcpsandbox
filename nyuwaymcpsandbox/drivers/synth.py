"""Synthesize a benign-but-identifiable input from a JSON Schema.

The deterministic harness's job is to *trigger* a tool, not to attack it
with malicious inputs. The job of catching bad behaviour belongs to the
detection rules - they fire on the server's behaviour regardless of
what we sent in.

Inputs therefore use a sentinel string ("nyuway_sandbox_probe") that:

1. Is recognisable in captured logs and rule evidence.
2. Won't accidentally trip benign servers into surprising paths.
3. Survives most string-validation patterns (alphanumeric + underscore).

For JSON-Schema features we don't model yet (oneOf, allOf, $ref, etc.),
the synthesizer returns a best-effort placeholder rather than raising.
"""

from __future__ import annotations

from typing import Any

# Sentinel string written into every string field. Easy to grep for.
PROBE_STRING = "nyuway_sandbox_probe"


def synthesize_input(schema: dict | None) -> Any:
    """Walk a JSON Schema and return a value that satisfies its required shape.

    Returns ``{}`` for missing or trivially empty schemas - many MCP tools
    take no arguments and a missing ``inputSchema`` is fine.
    """
    if not schema or not isinstance(schema, dict):
        return {}
    return _synth(schema)


def _synth(schema: dict) -> Any:
    # An explicit enum: use the first member, regardless of type.
    if "enum" in schema and isinstance(schema["enum"], list) and schema["enum"]:
        return schema["enum"][0]

    schema_type = schema.get("type")
    # JSON Schema allows type to be a list of types ("string"|"null"); take the first.
    if isinstance(schema_type, list):
        schema_type = schema_type[0] if schema_type else None

    if schema_type == "object" or "properties" in schema:
        return _synth_object(schema)
    if schema_type == "array":
        return _synth_array(schema)
    if schema_type == "string":
        return _synth_string(schema)
    if schema_type in ("integer", "number"):
        return _synth_number(schema)
    if schema_type == "boolean":
        return False
    if schema_type == "null":
        return None

    # Unknown / unspecified type. Default to an empty dict - the harness
    # logs the call attempt and the server's reaction (or rejection) is
    # itself useful behavioural data.
    return {}


def _synth_object(schema: dict) -> dict:
    """Generate a dict satisfying the required properties of an object schema."""
    properties = schema.get("properties") or {}
    required = schema.get("required") or []

    result: dict[str, Any] = {}
    # Always include the required keys; include any other properties too
    # so optional fields exercise their code paths.
    keys = list(required) + [k for k in properties if k not in required]
    for key in keys:
        prop_schema = properties.get(key) or {}
        result[key] = _synth(prop_schema)
    return result


def _synth_array(schema: dict) -> list:
    """Generate a one-element array satisfying the items schema."""
    items = schema.get("items")
    if isinstance(items, dict):
        return [_synth(items)]
    # Tuple-typed arrays (items as list) - synthesize each tuple position.
    if isinstance(items, list):
        return [_synth(i) if isinstance(i, dict) else None for i in items]
    return []


def _synth_string(schema: dict) -> str:
    """Generate a string satisfying length and format hints when present."""
    # Hardcoded sentinel for most strings.
    value = PROBE_STRING
    min_length = schema.get("minLength")
    if isinstance(min_length, int) and min_length > len(value):
        value = value + "_" + "x" * (min_length - len(value) - 1)
    max_length = schema.get("maxLength")
    if isinstance(max_length, int) and max_length < len(value):
        value = value[:max_length]
    return value


def _synth_number(schema: dict) -> int | float:
    """Generate a number satisfying minimum / maximum when present."""
    minimum = schema.get("minimum")
    maximum = schema.get("maximum")
    if isinstance(minimum, (int, float)):
        return minimum
    if isinstance(maximum, (int, float)):
        # No minimum: any value <= maximum works; 0 is safest.
        return min(0, maximum) if isinstance(maximum, (int, float)) else 0
    return 0
