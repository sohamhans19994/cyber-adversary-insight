"""Versioned prompt resource loading."""

from __future__ import annotations

from importlib.resources import files

PROMPT_VERSION = "v1"


def load_prompt(name: str, *, version: str = PROMPT_VERSION) -> str:
    """Read a prompt only when an analysis stage requests it."""

    resource = files("gambit").joinpath("prompts", version, f"{name}.txt")
    text = resource.read_text(encoding="utf-8")
    if name in {"suricata_phase_strategy", "suricata_phase", "suricata_mitre"}:
        # These class-level triple-quoted strings ended with four indentation
        # spaces after their final newline in the original module.
        return text + "    "
    return text
