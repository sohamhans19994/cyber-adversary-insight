"""Faithful, dependency-injected ports of the original analysis stages."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any

from gambit.errors import LLMResponseError
from gambit.llm import LLMClient
from gambit.models import Action, AttackPhase, OpNoteDocument, SuricataEvent
from gambit.prompts import load_prompt


@dataclass(frozen=True)
class AnalysisConfig:
    max_retries: int = 3
    phase_lookback: int = 5

    def __post_init__(self) -> None:
        if self.max_retries < 1:
            raise ValueError("max_retries must be at least 1")
        if self.phase_lookback < 1:
            raise ValueError("phase_lookback must be at least 1")

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def _strip_json_fence(value: str) -> str:
    """Match the explicit prefix/suffix removal used by OPNOTES scripts."""

    text = value
    if text.startswith("```json"):
        text = text[len("```json") :].strip()
    if text.endswith("```"):
        text = text[: -len("```")]
    return text


def _prompt_text(document: OpNoteDocument) -> str:
    if document.source_text is not None:
        return document.source_text
    return "\n".join(
        f"{entry.timestamp.strftime('%Y-%m-%d %H:%M:%S')} {entry.text}"
        for entry in document.entries
    )


def _parse_original_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None


def _action_timestamp_details(
    actions: list[dict[str, Any]],
    *,
    break_start_timestamp: datetime | None = None,
    break_end_timestamp: datetime | None = None,
) -> list[Action]:
    """Port the original duration logic, with its invalid-time crash fixed (B3)."""

    day_break = break_start_timestamp is not None and break_end_timestamp is not None
    normalized: list[Action] = []
    for index, raw_action in enumerate(actions):
        action = dict(raw_action)
        start = _parse_original_timestamp(action.get("timestamp"))
        end: datetime | None = None
        if start is not None:
            for later_action in actions[index + 1 :]:
                candidate = _parse_original_timestamp(later_action.get("timestamp"))
                if candidate is not None and candidate >= start:
                    end = candidate
                    break
            if end is None:
                end = start

        duration: float | None = None
        if start is not None and end is not None:
            duration = (end - start).total_seconds()
            if (
                day_break
                and break_start_timestamp is not None
                and break_end_timestamp is not None
                and start < break_end_timestamp
                and end >= break_end_timestamp
            ):
                duration -= (
                    break_end_timestamp - max(break_start_timestamp, start)
                ).total_seconds()

        action["start_datetime"] = (
            start.strftime("%Y-%m-%d %H:%M:%S") if start is not None else None
        )
        action["end_datetime"] = (
            end.strftime("%Y-%m-%d %H:%M:%S") if end is not None else None
        )
        action["time_spent"] = duration
        normalized.append(
            Action(
                title=str(action.get("title") or "Untitled action"),
                description=str(action.get("action") or ""),
                start_timestamp=start,
                end_timestamp=end,
                duration_seconds=duration,
                original=action,
            )
        )
    return normalized


def extract_actions(
    document: OpNoteDocument,
    llm: LLMClient,
    *,
    utility_llm: LLMClient | None = None,
    config: AnalysisConfig | None = None,
) -> list[Action]:
    """Run the original split, JSON-conversion, and day-break sequence."""

    if not document.entries and not document.source_text:
        return []
    resolved_config = config or AnalysisConfig()
    converter = utility_llm or llm
    errors: list[str] = []
    timestamps = [
        entry.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        for entry in document.entries
    ]

    # The original had nested retries whose exhausted inner loop could repeat
    # forever. One bounded whole-sequence retry preserves intent and fixes B2.
    for _attempt in range(resolved_config.max_retries):
        try:
            split_text = llm.complete(
                load_prompt("opnotes_split").format(
                    opnotes_text=_prompt_text(document)
                )
            )
            converted = converter.complete(
                load_prompt("opnotes_json").format(actions_split_text=split_text)
            )
            raw_actions = json.loads(converted)
            if not isinstance(raw_actions, list):
                raise ValueError("converted action response must be a JSON list")
            if not raw_actions:
                return []
            if not all(isinstance(action, dict) for action in raw_actions):
                raise ValueError("every converted action must be a JSON object")

            day_break_text = llm.complete(
                load_prompt("opnotes_day_break").format(
                    timestamps_list=timestamps
                )
            )
            day_break = json.loads(_strip_json_fence(day_break_text))
            if not isinstance(day_break, dict) or "day_break" not in day_break:
                raise ValueError("day-break response is missing day_break")
            break_start = None
            break_end = None
            if day_break["day_break"]:
                break_start = datetime.strptime(
                    day_break["first_day_end_timestamp"],
                    "%Y-%m-%d %H:%M:%S",
                )
                break_end = datetime.strptime(
                    day_break["second_day_start_timestamp"],
                    "%Y-%m-%d %H:%M:%S",
                )
            return _action_timestamp_details(
                raw_actions,
                break_start_timestamp=break_start,
                break_end_timestamp=break_end,
            )
        except Exception as exc:
            errors.append(f"{type(exc).__name__}: {exc}")
    raise LLMResponseError(
        "action extraction failed after "
        f"{resolved_config.max_retries} attempts: {' | '.join(errors)}"
    )


def _phase_payload(event: SuricataEvent) -> dict[str, Any]:
    saved = event.network_fields.get("_phase_fields")
    if isinstance(saved, dict):
        return saved
    payload = event.model_dump(mode="json")
    network = payload.pop("network_fields", {})
    payload.update(network)
    return payload


def _calculate_differences(
    previous: dict[str, Any],
    latest: dict[str, Any],
) -> tuple[dict[str, tuple[Any, Any]], str]:
    differences: dict[str, tuple[Any, Any]] = {}
    texts: list[str] = []
    for key in previous:
        if key not in {"timestamp", "tx_id"} and previous.get(key) != latest.get(key):
            differences[key] = (previous.get(key), latest.get(key))
            texts.append(f"{key} is different, updated to {latest.get(key)}")
    return differences, "\n".join(texts)


def _differences_summary(differences: list[str], lookback: int) -> str:
    result = "..." if len(differences) > lookback else ""
    for index, text in enumerate(differences):
        if index + lookback < len(differences):
            continue
        result += f"{index + 1}) {text}\n"
    return result


def _phase_timestamp(payload: dict[str, Any]) -> datetime | None:
    raw = payload.get("timestamp")
    if not isinstance(raw, str):
        return None
    try:
        return datetime.strptime(raw, "%Y-%m-%dT%H:%M:%S.%f%z")
    except ValueError:
        return None


def _finish_phase(state: dict[str, Any]) -> AttackPhase:
    events: list[SuricataEvent] = state["events"]
    start = events[0].timestamp
    end = max(event.end_timestamp or event.timestamp for event in events)
    reasoning = list(state["reasoning"])
    return AttackPhase(
        summary=state["summary"],
        reason=reasoning[-1] if reasoning else "",
        start_timestamp=start,
        end_timestamp=end,
        events=events,
        differences=list(state["differences"]),
        reasoning=reasoning,
        new_phase_start_summary=state["new_phase_start_summary"],
    )


def segment_phases(
    events: list[SuricataEvent],
    llm: LLMClient,
    *,
    config: AnalysisConfig | None = None,
) -> list[AttackPhase]:
    """Port the original sequential phase detector without new heuristics."""

    if not events:
        return []
    resolved_config = config or AnalysisConfig()
    state: dict[str, Any] = {
        "events": [events[0]],
        "differences": [],
        "summary": (
            "This is the first entry, so there is no summary yet. If you will be "
            "adding entries to this phase, you should form a new sumary of the phase."
        ),
        "reasoning": ["first entry"],
        "new_phase_start_summary": "Logs Start",
    }
    phases: list[AttackPhase] = []

    for event in events[1:]:
        previous_payload = _phase_payload(state["events"][-1])
        latest_payload = _phase_payload(event)
        current_time = _phase_timestamp(latest_payload)
        previous_time = _phase_timestamp(previous_payload)
        elapsed: float | str = "unknown"
        if current_time is not None and previous_time is not None:
            elapsed = (current_time - previous_time).total_seconds()
        _, latest_differences = _calculate_differences(
            previous_payload,
            latest_payload,
        )
        prompt = load_prompt("suricata_phase").format(
            previous_phase_first_entry=_phase_payload(state["events"][0]),
            previous_phase_differences=_differences_summary(
                state["differences"],
                resolved_config.phase_lookback,
            ),
            latest_log_entry=latest_payload,
            time_since_previous_entry=elapsed,
            latest_log_entry_differences=latest_differences,
            ongoing_phase_summary=state["summary"],
            phase_start_detection_strategy=load_prompt(
                "suricata_phase_strategy"
            ),
        )

        decision: dict[str, Any] | None = None
        for _attempt in range(resolved_config.max_retries):
            try:
                candidate = json.loads(
                    # Intentional parity with the original character-set strip.
                    llm.complete(prompt).strip("```json\n").strip("```")  # noqa: B005
                )
                required = {"phase_start_prediction", "reasoning", "summary"}
                if not isinstance(candidate, dict) or not required <= candidate.keys():
                    raise KeyError(
                        "phase response requires phase_start_prediction, reasoning, "
                        "and summary"
                    )
                decision = candidate
                break
            except Exception:
                continue

        # Preserve the original fallback: retain an unprocessed entry in the
        # current phase rather than aborting the run.
        if decision is None:
            state["events"].append(event)
            state["reasoning"].append(
                "This entry was not processed because the LLM failed to return "
                "a valid response"
            )
            continue

        if decision["phase_start_prediction"]:
            phases.append(_finish_phase(state))
            state = {
                "events": [event],
                "differences": [],
                "summary": decision["summary"],
                "reasoning": [decision["reasoning"]],
                "new_phase_start_summary": decision["summary"],
            }
        else:
            state["events"].append(event)
            state["differences"].append(latest_differences)
            state["summary"] = decision["summary"]
            state["reasoning"].append(decision["reasoning"])

    phases.append(_finish_phase(state))
    return phases
