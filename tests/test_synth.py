"""Tests for synthetic input generation from JSON Schema."""

from nyuwaymcpsandbox.drivers.synth import PROBE_STRING, synthesize_input

# ── No / trivial schema ──────────────────────────────────────────────────


def test_none_schema_returns_empty_dict():
    assert synthesize_input(None) == {}


def test_empty_schema_returns_empty_dict():
    assert synthesize_input({}) == {}


def test_non_dict_schema_returns_empty_dict():
    """A malformed schema (string, list) must not crash."""
    assert synthesize_input("not a schema") == {}
    assert synthesize_input(["also bad"]) == {}


# ── Primitive types ──────────────────────────────────────────────────────


def test_string_returns_probe_sentinel():
    assert synthesize_input({"type": "string"}) == PROBE_STRING


def test_integer_returns_zero():
    assert synthesize_input({"type": "integer"}) == 0


def test_number_returns_zero():
    assert synthesize_input({"type": "number"}) == 0


def test_boolean_returns_false():
    assert synthesize_input({"type": "boolean"}) is False


def test_null_returns_none():
    assert synthesize_input({"type": "null"}) is None


def test_union_type_uses_first():
    """JSON Schema allows 'type': ['string', 'null']; use the first."""
    assert synthesize_input({"type": ["string", "null"]}) == PROBE_STRING


# ── Constraints ──────────────────────────────────────────────────────────


def test_enum_returns_first_value():
    assert synthesize_input({"enum": ["red", "green", "blue"]}) == "red"


def test_string_min_length_pads():
    s = synthesize_input({"type": "string", "minLength": 200})
    assert len(s) >= 200


def test_string_max_length_truncates():
    s = synthesize_input({"type": "string", "maxLength": 5})
    assert len(s) <= 5


def test_number_minimum_used():
    assert synthesize_input({"type": "integer", "minimum": 42}) == 42


# ── Object ───────────────────────────────────────────────────────────────


def test_object_with_required_string():
    schema = {
        "type": "object",
        "properties": {"name": {"type": "string"}},
        "required": ["name"],
    }
    assert synthesize_input(schema) == {"name": PROBE_STRING}


def test_object_includes_optional_properties():
    """Optional fields exercise their code paths; include them too."""
    schema = {
        "type": "object",
        "properties": {
            "name": {"type": "string"},
            "count": {"type": "integer"},
        },
        "required": ["name"],
    }
    out = synthesize_input(schema)
    assert "name" in out
    assert "count" in out
    assert out["count"] == 0


def test_nested_object():
    schema = {
        "type": "object",
        "properties": {
            "user": {
                "type": "object",
                "properties": {"id": {"type": "string"}},
                "required": ["id"],
            }
        },
        "required": ["user"],
    }
    out = synthesize_input(schema)
    assert out == {"user": {"id": PROBE_STRING}}


def test_properties_implies_object():
    """A schema with properties but no explicit 'type: object' is still an object."""
    schema = {"properties": {"x": {"type": "boolean"}}}
    assert synthesize_input(schema) == {"x": False}


# ── Array ────────────────────────────────────────────────────────────────


def test_array_of_strings():
    schema = {"type": "array", "items": {"type": "string"}}
    assert synthesize_input(schema) == [PROBE_STRING]


def test_array_of_objects():
    schema = {
        "type": "array",
        "items": {
            "type": "object",
            "properties": {"k": {"type": "integer"}},
            "required": ["k"],
        },
    }
    assert synthesize_input(schema) == [{"k": 0}]


def test_array_without_items_returns_empty():
    """Array with no items spec is just an empty array."""
    assert synthesize_input({"type": "array"}) == []


def test_array_with_tuple_items():
    schema = {
        "type": "array",
        "items": [{"type": "string"}, {"type": "integer"}],
    }
    out = synthesize_input(schema)
    assert out == [PROBE_STRING, 0]


# ── Realistic MCP tool schemas ───────────────────────────────────────────


def test_realistic_fetch_tool_schema():
    """Mimics a typical MCP HTTP fetch tool input schema."""
    schema = {
        "type": "object",
        "properties": {
            "url": {"type": "string", "format": "uri"},
            "headers": {
                "type": "object",
                "additionalProperties": {"type": "string"},
            },
        },
        "required": ["url"],
    }
    out = synthesize_input(schema)
    assert out["url"] == PROBE_STRING
    # `headers` has no properties so it resolves to an empty dict.
    assert out["headers"] == {}


def test_realistic_file_tool_schema():
    schema = {
        "type": "object",
        "properties": {
            "path": {"type": "string"},
            "recursive": {"type": "boolean"},
        },
        "required": ["path"],
    }
    out = synthesize_input(schema)
    assert out["path"] == PROBE_STRING
    assert out["recursive"] is False
