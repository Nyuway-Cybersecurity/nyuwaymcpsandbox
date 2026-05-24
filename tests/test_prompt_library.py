"""Tests for adversarial prompt library loading."""

import pytest

from nyuwaymcpsandbox.drivers.prompt_library import (
    VALID_CATEGORIES,
    PromptLoadError,
    load_builtin_prompts,
    load_prompts_file,
    parse_prompts,
)


def _minimal_prompts():
    return {
        "prompts": [
            {
                "id": "p1",
                "category": "tool_poisoning",
                "description": "d",
                "user_message": "u",
            }
        ]
    }


# ── parse_prompts ─────────────────────────────────────────────────────────


def test_parse_minimal_succeeds():
    prompts = parse_prompts(_minimal_prompts())
    assert len(prompts) == 1
    assert prompts[0].id == "p1"
    assert prompts[0].category == "tool_poisoning"


def test_parse_carries_optional_system_message():
    raw = _minimal_prompts()
    raw["prompts"][0]["system_message"] = "Stay sharp."
    prompts = parse_prompts(raw)
    assert prompts[0].system_message == "Stay sharp."


def test_parse_missing_prompts_key_raises():
    with pytest.raises(PromptLoadError, match="non-empty list"):
        parse_prompts({})


def test_parse_empty_prompts_list_raises():
    with pytest.raises(PromptLoadError, match="non-empty list"):
        parse_prompts({"prompts": []})


def test_parse_missing_required_field_raises():
    for missing in ("id", "category", "description", "user_message"):
        raw = _minimal_prompts()
        del raw["prompts"][0][missing]
        with pytest.raises(PromptLoadError, match=missing):
            parse_prompts(raw)


def test_parse_invalid_category_raises():
    raw = _minimal_prompts()
    raw["prompts"][0]["category"] = "made_up"
    with pytest.raises(PromptLoadError, match="category must be one of"):
        parse_prompts(raw)


def test_parse_duplicate_id_raises():
    raw = {
        "prompts": [
            {"id": "x", "category": "boundary_test", "description": "d", "user_message": "a"},
            {"id": "x", "category": "boundary_test", "description": "d2", "user_message": "b"},
        ]
    }
    with pytest.raises(PromptLoadError, match="duplicate prompt id"):
        parse_prompts(raw)


# ── File loading ─────────────────────────────────────────────────────────


def test_load_prompts_file_missing_raises(tmp_path):
    with pytest.raises(PromptLoadError, match="not found"):
        load_prompts_file(tmp_path / "missing.yaml")


def test_load_prompts_file_empty_raises(tmp_path):
    p = tmp_path / "empty.yaml"
    p.write_text("")
    with pytest.raises(PromptLoadError, match="empty"):
        load_prompts_file(p)


def test_load_prompts_file_bad_yaml_raises(tmp_path):
    p = tmp_path / "bad.yaml"
    p.write_text("prompts: : :")
    with pytest.raises(PromptLoadError, match="YAML"):
        load_prompts_file(p)


# ── Builtin library sanity ───────────────────────────────────────────────


def test_builtin_library_loads():
    prompts = load_builtin_prompts()
    assert len(prompts) >= 5


def test_builtin_library_has_every_category_covered():
    prompts = load_builtin_prompts()
    categories = {p.category for p in prompts}
    # Every declared category must be represented in the library.
    assert categories.issubset(set(VALID_CATEGORIES))
    # And the library covers at least the high-priority attack classes.
    assert "tool_poisoning" in categories
    assert "prompt_injection" in categories
    assert "cross_tool_exfil" in categories


def test_builtin_library_ids_unique():
    prompts = load_builtin_prompts()
    ids = [p.id for p in prompts]
    assert len(ids) == len(set(ids))


def test_builtin_library_messages_non_empty():
    for prompt in load_builtin_prompts():
        assert prompt.user_message.strip(), f"Prompt {prompt.id} has empty user_message"
