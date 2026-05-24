"""Loader for the adversarial prompt library used by the LLM driver."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

BUILTIN_PROMPT_FILE = Path(__file__).resolve().parent / "prompts" / "adversarial_library.yaml"

VALID_CATEGORIES = (
    "tool_poisoning",
    "prompt_injection",
    "cross_tool_exfil",
    "boundary_test",
    "shadow_tool",
)


class PromptLoadError(Exception):
    """Adversarial prompt library is malformed."""


@dataclass(frozen=True)
class AdversarialPrompt:
    """One adversarial prompt from the library."""

    id: str
    category: str
    description: str
    user_message: str
    system_message: str = ""


def parse_prompts(raw: dict, source: str = "<dict>") -> list[AdversarialPrompt]:
    """Parse a YAML-decoded mapping into a list of AdversarialPrompt records."""
    if not isinstance(raw, dict):
        raise PromptLoadError(f"{source}: top-level must be a mapping")
    items = raw.get("prompts")
    if not isinstance(items, list) or not items:
        raise PromptLoadError(f"{source}: 'prompts' must be a non-empty list")

    seen: set[str] = set()
    result: list[AdversarialPrompt] = []
    for i, item in enumerate(items):
        ctx = f"{source}.prompts[{i}]"
        if not isinstance(item, dict):
            raise PromptLoadError(f"{ctx}: entry must be a mapping")
        for field_name in ("id", "category", "description", "user_message"):
            if field_name not in item or not isinstance(item[field_name], str):
                raise PromptLoadError(f"{ctx}: missing or non-string '{field_name}'")
        if item["id"] in seen:
            raise PromptLoadError(f"{ctx}: duplicate prompt id {item['id']!r}")
        if item["category"] not in VALID_CATEGORIES:
            raise PromptLoadError(
                f"{ctx}: category must be one of {VALID_CATEGORIES}, got {item['category']!r}"
            )
        seen.add(item["id"])
        result.append(
            AdversarialPrompt(
                id=item["id"],
                category=item["category"],
                description=item["description"],
                user_message=item["user_message"],
                system_message=item.get("system_message", ""),
            )
        )
    return result


def load_prompts_file(path: Path | str) -> list[AdversarialPrompt]:
    """Load a single prompt library YAML file."""
    p = Path(path)
    if not p.is_file():
        raise PromptLoadError(f"Prompt library file not found: {p}")
    try:
        with p.open("r", encoding="utf-8") as f:
            raw = yaml.safe_load(f)
    except yaml.YAMLError as e:
        raise PromptLoadError(f"{p}: YAML parse error: {e}") from e
    if raw is None:
        raise PromptLoadError(f"{p}: file is empty")
    return parse_prompts(raw, source=str(p))


def load_builtin_prompts() -> list[AdversarialPrompt]:
    """Load every prompt bundled with the package."""
    return load_prompts_file(BUILTIN_PROMPT_FILE)
