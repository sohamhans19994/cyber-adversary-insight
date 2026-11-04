"""OPNOTES loaders for canonical JSON, legacy JSON, timestamped text, and CTD."""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any

import xmltodict
from pydantic import ValidationError

from gambit.errors import InputValidationError
from gambit.models import OpNoteDocument, OpNoteEntry
from gambit.time_utils import normalize_datetime, parse_timestamp_prefix


def _build_entries(
    text_fragments: Iterable[str],
    *,
    default_year: int | None = None,
    malformed_timestamp_as_text: bool = False,
) -> list[OpNoteEntry]:
    entries: list[OpNoteEntry] = []
    pending_preamble: list[str] = []
    current_timestamp = None
    current_lines: list[str] = []

    def finish_entry() -> None:
        nonlocal current_lines
        text = "\n".join(line for line in current_lines if line).strip()
        if current_timestamp is not None and text:
            entries.append(OpNoteEntry(timestamp=current_timestamp, text=text))
        current_lines = []

    for fragment in text_fragments:
        for raw_line in fragment.splitlines():
            line = raw_line.strip()
            try:
                parsed = parse_timestamp_prefix(line, default_year=default_year)
            except InputValidationError:
                if not malformed_timestamp_as_text:
                    raise
                parsed = None
            if parsed is not None:
                finish_entry()
                current_timestamp, trailing = parsed
                if not entries and pending_preamble:
                    current_lines.extend(pending_preamble)
                    pending_preamble = []
                if trailing:
                    current_lines.append(trailing)
            elif current_timestamp is None:
                if line:
                    pending_preamble.append(line)
            elif line:
                current_lines.append(line)
    finish_entry()

    if not entries and pending_preamble:
        raise InputValidationError(
            "OPNOTES content contains text but no recognized timestamp; "
            "timestamps without a year require default_year"
        )
    return sorted(entries, key=lambda entry: entry.timestamp)


def _text_values(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, list):
        for item in value:
            yield from _text_values(item)
    elif isinstance(value, dict):
        text = value.get("#text")
        if isinstance(text, str):
            yield text
        for key, child in value.items():
            if key not in {"#text", "encoded_png"} and isinstance(child, dict | list):
                yield from _text_values(child)


def _find_named_nodes(value: Any, *, exact: bool) -> Iterator[dict[str, Any]]:
    if isinstance(value, dict):
        name = str(value.get("@name", "")).strip().casefold()
        matches = name == "opnotes" if exact else name.endswith("opnotes")
        if matches:
            yield value
        for child in value.values():
            if isinstance(child, dict | list):
                yield from _find_named_nodes(child, exact=exact)
    elif isinstance(value, list):
        for child in value:
            yield from _find_named_nodes(child, exact=exact)


def _rich_text_values(value: Any) -> Iterator[str]:
    if isinstance(value, dict):
        if "rich_text" in value:
            yield from _text_values(value["rich_text"])
        for key, child in value.items():
            if key != "rich_text" and isinstance(child, dict | list):
                yield from _rich_text_values(child)
    elif isinstance(value, list):
        for child in value:
            yield from _rich_text_values(child)


def parse_ctd(
    path: str | Path,
    *,
    source_id: str | None = None,
    default_year: int | None = None,
) -> OpNoteDocument:
    """Convert a CherryTree-style CTD XML document to canonical OPNOTES."""

    input_path = Path(path)
    try:
        raw = input_path.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeError) as exc:
        raise InputValidationError(f"cannot read CTD file {input_path}: {exc}") from exc
    try:
        parsed = xmltodict.parse(raw, disable_entities=True)
    except Exception as exc:
        raise InputValidationError(f"invalid CTD XML in {input_path}: {exc}") from exc

    nodes = list(_find_named_nodes(parsed, exact=True))
    if not nodes:
        nodes = list(_find_named_nodes(parsed, exact=False))
    if not nodes:
        raise InputValidationError("CTD contains no node named OPNOTES")

    fragments = [text for node in nodes for text in _rich_text_values(node)]
    try:
        entries = _build_entries(
            fragments,
            # The original CTD parser supplied 2024 for its yearless forms.
            default_year=default_year if default_year is not None else 2024,
            malformed_timestamp_as_text=True,
        )
    except InputValidationError as exc:
        if "no recognized timestamp" not in str(exc):
            raise
        # Several original CTDs contain free-form or separately formatted
        # date/time notes. Preserve their complete text for the original
        # action-splitting prompt instead of inventing a timestamp.
        entries = []
    return OpNoteDocument(
        source_id=source_id or input_path.stem,
        entries=entries,
        source_text="\n".join(fragments),
    )


def _load_json(
    path: Path, *, source_id: str | None = None, default_year: int | None = None
) -> OpNoteDocument:
    try:
        payload = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise InputValidationError(f"cannot load OPNOTES JSON {path}: {exc}") from exc

    if isinstance(payload, dict) and {"source_id", "entries"} <= payload.keys():
        if source_id is not None:
            payload = {**payload, "source_id": source_id}
        try:
            return OpNoteDocument.model_validate(payload)
        except ValidationError as exc:
            raise InputValidationError(f"invalid canonical OPNOTES JSON: {exc}") from exc

    legacy = payload
    if isinstance(payload, list) and len(payload) == 1 and isinstance(payload[0], dict):
        legacy = payload[0]
    if not isinstance(legacy, dict):
        raise InputValidationError(
            "OPNOTES JSON must be canonical or a legacy timestamp-to-text object"
        )

    entries: list[OpNoteEntry] = []
    errors: list[str] = []
    for raw_timestamp, raw_text in legacy.items():
        try:
            timestamp = normalize_datetime(str(raw_timestamp), default_year=default_year)
            text = str(raw_text).strip()
            if not text:
                continue
            entries.append(OpNoteEntry(timestamp=timestamp, text=text))
        except (TypeError, ValueError, ValidationError) as exc:
            errors.append(f"{raw_timestamp!r}: {exc}")
    if errors:
        raise InputValidationError("invalid legacy OPNOTES entries:\n- " + "\n- ".join(errors))
    entries.sort(key=lambda entry: entry.timestamp)
    return OpNoteDocument(source_id=source_id or path.stem, entries=entries)


def load_opnotes(
    path: str | Path,
    *,
    source_id: str | None = None,
    default_year: int | None = None,
) -> OpNoteDocument:
    """Load any supported OPNOTES representation."""

    input_path = Path(path)
    suffix = input_path.suffix.casefold()
    if suffix == ".ctd":
        return parse_ctd(input_path, source_id=source_id, default_year=default_year)
    if suffix == ".json":
        return _load_json(input_path, source_id=source_id, default_year=default_year)
    if suffix == ".txt":
        try:
            raw = input_path.read_text(encoding="utf-8-sig")
        except (OSError, UnicodeError) as exc:
            raise InputValidationError(f"cannot read OPNOTES text {input_path}: {exc}") from exc
        return OpNoteDocument(
            source_id=source_id or input_path.stem,
            entries=_build_entries([raw], default_year=default_year),
            source_text=raw,
        )
    raise InputValidationError(
        f"unsupported OPNOTES extension {input_path.suffix!r}; expected .ctd, .json, or .txt"
    )
