"""Timestamp parsing and normalization shared by all inputs."""

from __future__ import annotations

import re
from datetime import UTC, datetime

from dateutil import parser as dateutil_parser

from gambit.errors import InputValidationError

DISPLAY_TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"

_PREFIX_PATTERNS = (
    re.compile(
        r"^(?P<stamp>\d{4}[-/]\d{2}[-/]\d{2}(?:\s+-?\s*|T)"
        r"\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:\s*(?:Z|[+-]\d{2}:?\d{2}))?)"
        r"(?P<text>.*)$"
    ),
    re.compile(
        r"^(?P<stamp>\d{2}[-/]\d{2}[-/]\d{4}(?:\s+-?\s*)"
        r"\d{2}:\d{2}(?::\d{2})?)(?P<text>.*)$"
    ),
    re.compile(
        r"^(?P<stamp>\d{2}[-/]\d{2}(?:\s+-?\s*)"
        r"\d{2}:\d{2}(?::\d{2})?)(?P<text>.*)$"
    ),
    re.compile(
        r"^(?P<stamp>[A-Za-z]{3}\s+[A-Za-z]{3}\s+\d{1,2}\s+"
        r"\d{1,2}:\d{2}:\d{2}\s+(?:AM|PM)\s+[A-Za-z]{2,5}\s+\d{4})"
        r"(?P<text>.*)$",
        re.IGNORECASE,
    ),
)


def normalize_datetime(value: datetime | str, *, default_year: int | None = None) -> datetime:
    """Parse a supported timestamp and return an aware UTC datetime.

    Naive timestamps are interpreted as UTC. Timestamps without a year are rejected
    unless the caller explicitly supplies ``default_year``.
    """

    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        candidate = value.strip()
        if not candidate:
            raise ValueError("timestamp cannot be empty")
        candidate = re.sub(r"\s+-\s+(?=\d{2}:\d{2})", " ", candidate)
        has_year = bool(re.search(r"\b\d{4}\b", candidate))
        if not has_year and default_year is None:
            raise ValueError("timestamp has no year; supply default_year explicitly")
        try:
            parsed = dateutil_parser.parse(candidate, default=datetime(default_year or 2000, 1, 1))
        except (ValueError, OverflowError) as exc:
            raise ValueError(f"unsupported timestamp {value!r}") from exc
    else:
        raise TypeError("timestamp must be a datetime or string")

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def parse_timestamp_prefix(
    line: str, *, default_year: int | None = None
) -> tuple[datetime, str] | None:
    """Return a timestamp and trailing text when a line starts with a known timestamp."""

    stripped = line.strip()
    for pattern in _PREFIX_PATTERNS:
        match = pattern.match(stripped)
        if not match:
            continue
        try:
            timestamp = normalize_datetime(match.group("stamp"), default_year=default_year)
        except ValueError as exc:
            raise InputValidationError(str(exc)) from exc
        trailing = match.group("text").lstrip(" \t:-")
        return timestamp, trailing
    return None


def display_timestamp(value: datetime) -> str:
    """Format a UTC timestamp for human-readable prompt content."""

    return normalize_datetime(value).strftime(DISPLAY_TIMESTAMP_FORMAT) + "Z"
