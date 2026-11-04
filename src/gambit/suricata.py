"""Suricata combined-CSV validation and deterministic normalization."""

from __future__ import annotations

import ast
import ipaddress
import json
from datetime import date, datetime
from pathlib import Path
from typing import Any

import pandas as pd
from pydantic import ValidationError

from gambit.errors import InputValidationError
from gambit.models import SuricataEvent

REQUIRED_COLUMNS = ("timestamp", "src_ip", "dest_ip", "alert")
OPTIONAL_COLUMNS = ("src_port", "dest_port", "proto", "app_proto", "metadata")
PHASE_DROP_COLUMNS = {
    "packet",
    "pkt_src",
    "in_iface",
    "packet_info",
    "payload_printable",
}
LEGACY_SHORTEN_THRESHOLD = 5000


def _is_missing(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, str):
        return not value.strip()
    try:
        missing = pd.isna(value)
        return bool(missing) if isinstance(missing, bool) else False
    except (TypeError, ValueError):
        return False


def _json_safe(value: Any) -> Any:
    if _is_missing(value):
        return None
    if isinstance(value, str | bool | int | float):
        return value
    if isinstance(value, datetime | date | pd.Timestamp):
        return value.isoformat()
    if isinstance(value, dict):
        return {str(key): _json_safe(child) for key, child in value.items()}
    if isinstance(value, list | tuple | set):
        return [_json_safe(child) for child in value]
    if hasattr(value, "item"):
        return _json_safe(value.item())
    return str(value)


def _parse_mapping(value: Any, *, field: str, row_number: int) -> dict[str, Any]:
    if _is_missing(value):
        if field in {"alert", "metadata"}:
            return {}
        raise ValueError(f"row {row_number} field {field}: value is required")
    if isinstance(value, dict):
        return _json_safe(value)
    if not isinstance(value, str):
        raise ValueError(f"row {row_number} field {field}: expected an object")

    for loader in (json.loads, ast.literal_eval):
        try:
            parsed = loader(value)
        except (ValueError, SyntaxError, json.JSONDecodeError):
            continue
        if isinstance(parsed, dict):
            return _json_safe(parsed)
    raise ValueError(f"row {row_number} field {field}: malformed object")


def _validate_ip(value: Any, *, field: str, row_number: int) -> str:
    if _is_missing(value):
        raise ValueError(f"row {row_number} field {field}: value is required")
    candidate = str(value).strip()
    try:
        ipaddress.ip_address(candidate)
    except ValueError as exc:
        raise ValueError(f"row {row_number} field {field}: invalid IP address") from exc
    return candidate


def _optional_int(value: Any, *, field: str, row_number: int) -> int | None:
    if _is_missing(value):
        return None
    try:
        converted = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"row {row_number} field {field}: expected an integer") from exc
    if not 0 <= converted <= 65535:
        raise ValueError(f"row {row_number} field {field}: port must be between 0 and 65535")
    return converted


def _phase_fields_from_row(
    row: pd.Series,
    alert_with_metadata: dict[str, Any],
) -> dict[str, Any]:
    """Reproduce the columns passed to the original phase prompt.

    Missing optional packet, metadata, and community columns are deliberately
    ignored instead of raising (B7).
    """

    result: dict[str, Any] = {}
    for column, value in row.items():
        if (
            column in PHASE_DROP_COLUMNS
            or column in {"alert", "community_id"}
            or _is_missing(value)
        ):
            continue
        result[str(column)] = _json_safe(value)

    for key, value in alert_with_metadata.items():
        if key == "metadata":
            if isinstance(value, dict):
                for metadata_key, metadata_value in value.items():
                    if not _is_missing(metadata_value):
                        result[f"alert_metadata_{metadata_key}"] = _json_safe(
                            metadata_value
                        )
            continue
        if not _is_missing(value):
            result[f"alert_{key}"] = _json_safe(value)
    return result


def load_suricata(path: str | Path, *, aggregate: bool = True) -> list[SuricataEvent]:
    """Load, validate, flatten, sort, and optionally aggregate a combined CSV."""

    input_path = Path(path)
    try:
        frame = pd.read_csv(input_path)
    except (OSError, UnicodeError, pd.errors.ParserError, pd.errors.EmptyDataError) as exc:
        raise InputValidationError(f"cannot read Suricata CSV {input_path}: {exc}") from exc

    missing_columns = [column for column in REQUIRED_COLUMNS if column not in frame.columns]
    if missing_columns:
        raise InputValidationError(
            "Suricata CSV is missing required columns: " + ", ".join(missing_columns)
        )

    events: list[SuricataEvent] = []
    errors: list[str] = []
    for index, row in frame.iterrows():
        row_number = int(index) + 2
        try:
            parsed_alert = _parse_mapping(
                row["alert"], field="alert", row_number=row_number
            )
            nested_metadata = parsed_alert.get("metadata", {})
            if nested_metadata and not isinstance(nested_metadata, dict):
                raise ValueError(
                    f"row {row_number} field alert.metadata: expected an object"
                )
            top_metadata = (
                _parse_mapping(row["metadata"], field="metadata", row_number=row_number)
                if "metadata" in frame.columns
                else {}
            )
            metadata = {**_json_safe(nested_metadata), **top_metadata}
            alert = {
                key: value for key, value in parsed_alert.items() if key != "metadata"
            }

            known = set(REQUIRED_COLUMNS) | set(OPTIONAL_COLUMNS)
            network_fields = {
                str(column): _json_safe(row[column])
                for column in frame.columns
                if column not in known and not _is_missing(row[column])
            }
            network_fields["_raw_alert_group"] = (
                f"__missing_alert_row_{row_number}"
                if _is_missing(row["alert"])
                else _json_safe(row["alert"])
            )
            network_fields["_phase_fields"] = _phase_fields_from_row(
                row,
                parsed_alert,
            )
            event = SuricataEvent(
                timestamp=row["timestamp"],
                src_ip=_validate_ip(row["src_ip"], field="src_ip", row_number=row_number),
                dest_ip=_validate_ip(row["dest_ip"], field="dest_ip", row_number=row_number),
                alert=alert,
                src_port=_optional_int(
                    row.get("src_port"), field="src_port", row_number=row_number
                ),
                dest_port=_optional_int(
                    row.get("dest_port"), field="dest_port", row_number=row_number
                ),
                proto=(
                    str(row["proto"]).strip()
                    if "proto" in frame.columns and not _is_missing(row["proto"])
                    else None
                ),
                app_proto=(
                    str(row["app_proto"]).strip()
                    if "app_proto" in frame.columns and not _is_missing(row["app_proto"])
                    else None
                ),
                metadata=metadata,
                network_fields=network_fields,
            )
            events.append(event)
        except (TypeError, ValueError, ValidationError) as exc:
            errors.append(str(exc))

    if errors:
        raise InputValidationError("invalid Suricata rows:\n- " + "\n- ".join(errors))
    events.sort(key=lambda event: event.timestamp)
    # The research implementation shortened only logs over 5,000 rows. Always
    # aggregating changed which entries reached phase detection.
    if aggregate and len(events) > LEGACY_SHORTEN_THRESHOLD:
        return aggregate_consecutive_alerts(events)
    return events


def _alert_key(event: SuricataEvent) -> str:
    if "_raw_alert_group" in event.network_fields:
        return json.dumps(
            event.network_fields["_raw_alert_group"],
            sort_keys=True,
            separators=(",", ":"),
        )
    return json.dumps(event.alert, sort_keys=True, separators=(",", ":"))


def aggregate_consecutive_alerts(events: list[SuricataEvent]) -> list[SuricataEvent]:
    """Merge adjacent events with the same alert object, preserving their time range."""

    if not events:
        return []
    groups: list[list[SuricataEvent]] = [[events[0]]]
    for event in events[1:]:
        if _alert_key(event) == _alert_key(groups[-1][-1]):
            groups[-1].append(event)
        else:
            groups.append([event])

    aggregated: list[SuricataEvent] = []
    for group in groups:
        first, last = group[0], group[-1]
        if len(group) == 1:
            aggregated.append(first)
            continue
        varying: dict[str, list[Any]] = {}
        for field in ("src_ip", "dest_ip", "src_port", "dest_port", "proto", "app_proto"):
            distinct = list(dict.fromkeys(getattr(event, field) for event in group))
            if len(distinct) > 1:
                varying[field] = distinct
        phase_rows = [
            event.network_fields.get("_phase_fields", {}) for event in group
        ]
        phase_fields: dict[str, Any] = {}
        ordered_keys = list(
            dict.fromkeys(key for row in phase_rows for key in row)
        )
        for key in ordered_keys:
            values = [row.get(key) for row in phase_rows]
            distinct = list(dict.fromkeys(json.dumps(value, sort_keys=True) for value in values))
            if len(distinct) == 1:
                phase_fields[key] = values[0]
            elif key == "timestamp":
                phase_fields[key] = {
                    "start": str(min(values)),
                    "end": str(max(values)),
                }
            elif key in {"src_port", "dest_port"}:
                numeric = [int(value) for value in values if value is not None]
                phase_fields[key] = {
                    "min": min(numeric),
                    "max": max(numeric),
                    "num_unique": len(set(numeric)),
                }
            elif key in {"src_ip", "dest_ip"}:
                from os.path import commonprefix

                strings = [str(value) for value in values]
                phase_fields[key] = {
                    "IP addresses": "All start with " + commonprefix(strings),
                    "num_unique": len(set(strings)),
                }
            else:
                phase_fields[key] = {"num_unique": len(distinct)}

        network_fields = dict(first.network_fields)
        network_fields["_phase_fields"] = phase_fields
        network_fields["aggregation"] = {
            "occurrences": sum(event.occurrence_count for event in group),
            "varying_fields": _json_safe(varying),
        }
        aggregated.append(
            SuricataEvent(
                timestamp=first.timestamp,
                end_timestamp=last.end_timestamp or last.timestamp,
                occurrence_count=sum(event.occurrence_count for event in group),
                src_ip=first.src_ip,
                dest_ip=first.dest_ip,
                alert=first.alert,
                src_port=first.src_port,
                dest_port=first.dest_port,
                proto=first.proto,
                app_proto=first.app_proto,
                metadata=first.metadata,
                network_fields=network_fields,
            )
        )
    return aggregated
