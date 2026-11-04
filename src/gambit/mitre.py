"""MITRE corpus loading and faithful ports of both original mapping paths."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from gambit.analysis import _phase_payload, _strip_json_fence
from gambit.errors import MitreCorpusError
from gambit.llm import LLMClient, QueryDocument
from gambit.models import Action, AttackPhase, MitreFinding
from gambit.prompts import load_prompt

TACTIC_SPECS = (
    ("Collection", "collection", "Is_Collection", "Collection"),
    (
        "Command and Control",
        "command_and_control",
        "Is_Command_and_Control",
        "Command_and_Control",
    ),
    (
        "Credential Access",
        "credential_access",
        "Is_Credential_Access",
        "Credential_Access",
    ),
    ("Discovery", "discovery", "Is_Discovery", "Discovery"),
    ("Execution", "execution", "Is_Execution", "Execution"),
    ("Exfiltration", "exfiltration", "Is_Exfiltration", "Exfiltration"),
    ("Initial Access", "initial_access", "Initial_access", "Initial_access"),
    (
        "Lateral Movement",
        "lateral_movement",
        "Is_Lateral_Movement",
        "Lateral_Movement",
    ),
    ("Persistence", "persistence", "Is_Persistence", "Persistence"),
    (
        "Privilege Escalation",
        "privilege_escalation",
        "Is_Privilege_Escalation",
        "Privilege_Escalation",
    ),
)

FILENAME_CATEGORIES = {
    slug: category for category, slug, _boolean_key, _prefix in TACTIC_SPECS
}


@dataclass(frozen=True)
class MitreTechnique:
    category: str
    technique_id: str
    technique_name: str
    parent_id: str | None = None


@dataclass(frozen=True)
class MitreCategory:
    name: str
    raw_document: str
    source_path: str


class MitreCorpus:
    def __init__(
        self,
        techniques: list[MitreTechnique],
        categories: list[MitreCategory],
        corpus_hash: str,
    ) -> None:
        self.techniques = tuple(techniques)
        self.categories = {category.name: category for category in categories}
        self.corpus_hash = corpus_hash
        self._index = {
            (technique.category, technique.technique_id): technique
            for technique in techniques
        }

    def find(self, category: str, technique_id: str) -> MitreTechnique | None:
        return self._index.get((category, technique_id))

    def documents(self) -> list[QueryDocument]:
        return [
            QueryDocument(
                text=category.raw_document,
                file_path=category.source_path,
            )
            for category in self.categories.values()
        ]


def _require_text(mapping: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = mapping.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    raise ValueError(f"missing non-empty {'/'.join(keys)}")


def _flatten_techniques(
    category: str,
    raw_techniques: list[Any],
) -> list[MitreTechnique]:
    techniques: list[MitreTechnique] = []
    for index, raw in enumerate(raw_techniques):
        if not isinstance(raw, dict):
            raise ValueError(f"Techniques[{index}] must be an object")
        technique_id = _require_text(raw, "ID", "id")
        name = _require_text(raw, "Name", "name")
        techniques.append(
            MitreTechnique(
                category=category,
                technique_id=technique_id,
                technique_name=name,
            )
        )
        children = raw.get(
            "subtechniques",
            raw.get("sub_techniques", raw.get("SubTechniques", [])),
        )
        if children is None:
            children = []
        if not isinstance(children, list):
            raise ValueError(f"Techniques[{index}] subtechniques must be a list")
        for child_index, child in enumerate(children):
            if not isinstance(child, dict):
                raise ValueError(
                    f"Techniques[{index}] subtechniques[{child_index}] "
                    "must be an object"
                )
            techniques.append(
                MitreTechnique(
                    category=category,
                    technique_id=_require_text(child, "ID", "id"),
                    technique_name=_require_text(child, "Name", "name"),
                    parent_id=technique_id,
                )
            )
    return techniques


def load_mitre_corpus(path: str | Path) -> MitreCorpus:
    """Accept the public category-object format and the original tactic lists."""

    corpus_path = Path(path)
    if not corpus_path.is_dir():
        raise MitreCorpusError(f"MITRE corpus directory does not exist: {corpus_path}")
    files = sorted(corpus_path.rglob("*.json"))
    if not files:
        raise MitreCorpusError("MITRE corpus contains no JSON files")

    digest = hashlib.sha256()
    techniques: list[MitreTechnique] = []
    categories: list[MitreCategory] = []
    errors: list[str] = []
    for file_path in files:
        relative = file_path.relative_to(corpus_path).as_posix()
        try:
            raw_bytes = file_path.read_bytes()
            raw_text = raw_bytes.decode("utf-8")
            digest.update(relative.encode("utf-8"))
            digest.update(b"\0")
            digest.update(raw_bytes)
            payload = json.loads(raw_text)
            if isinstance(payload, dict):
                category = _require_text(payload, "MITRE Category")
                raw_techniques = payload.get(
                    "Techniques",
                    payload.get("techniques"),
                )
            elif isinstance(payload, list):
                slug = file_path.stem.removesuffix("_mitre").casefold()
                category = FILENAME_CATEGORIES.get(slug)
                if category is None:
                    raise ValueError(
                        "a legacy top-level list requires a recognized "
                        "*_mitre.json tactic filename"
                    )
                raw_techniques = payload
            else:
                raise ValueError("top level must be an object or list")
            if not isinstance(raw_techniques, list):
                raise ValueError("Techniques must be a list")
            categories.append(
                MitreCategory(
                    name=category,
                    raw_document=raw_text,
                    source_path=str(file_path.resolve()),
                )
            )
            techniques.extend(_flatten_techniques(category, raw_techniques))
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
            errors.append(f"{relative}: {exc}")
    if errors:
        raise MitreCorpusError("invalid MITRE corpus:\n- " + "\n- ".join(errors))
    if not techniques:
        raise MitreCorpusError("MITRE corpus contains no techniques")

    # Some public-format corpora list canonical sub-techniques at the top level.
    known_ids = {
        (technique.category, technique.technique_id) for technique in techniques
    }
    normalized: list[MitreTechnique] = []
    for technique in techniques:
        parent_id = technique.parent_id
        if (
            parent_id is None
            and "." in technique.technique_id
            and (technique.category, technique.technique_id.split(".", 1)[0])
            in known_ids
        ):
            parent_id = technique.technique_id.split(".", 1)[0]
        normalized.append(
            MitreTechnique(
                category=technique.category,
                technique_id=technique.technique_id,
                technique_name=technique.technique_name,
                parent_id=parent_id,
            )
        )
    return MitreCorpus(normalized, categories, digest.hexdigest())


def _action_payload(action: Action) -> dict[str, Any]:
    if action.original:
        return dict(action.original)
    return {
        "title": action.title,
        "action": action.description,
        "timestamp": (
            action.start_timestamp.strftime("%Y-%m-%d %H:%M:%S")
            if action.start_timestamp
            else None
        ),
        "start_datetime": (
            action.start_timestamp.strftime("%Y-%m-%d %H:%M:%S")
            if action.start_timestamp
            else None
        ),
        "end_datetime": (
            action.end_timestamp.strftime("%Y-%m-%d %H:%M:%S")
            if action.end_timestamp
            else None
        ),
        "time_spent": action.duration_seconds,
    }


def _map_actions(
    actions: list[Action],
    corpus: MitreCorpus,
    llm: LLMClient,
    *,
    max_retries: int,
) -> list[MitreFinding]:
    findings: list[MitreFinding] = []
    for category, prompt_name, boolean_key, prefix in TACTIC_SPECS:
        category_document = corpus.categories.get(category)
        if category_document is None:
            continue
        for action in actions:
            payload = _action_payload(action)
            prompt = load_prompt(f"tactic_{prompt_name}").format(
                action=json.dumps(payload)
            )
            parsed: dict[str, Any] | None = None
            detected: MitreTechnique | None = None
            for _attempt in range(max_retries):
                try:
                    response = llm.query(
                        prompt,
                        [
                            QueryDocument(
                                text=category_document.raw_document,
                                file_path=category_document.source_path,
                            )
                        ],
                    )
                    candidate = json.loads(_strip_json_fence(response.text))
                    if not isinstance(candidate, dict) or boolean_key not in candidate:
                        raise ValueError(
                            f"response is missing {boolean_key}"
                        )
                    if candidate[boolean_key]:
                        raw_id = candidate.get(f"{prefix}_technique_ID")
                        if not isinstance(raw_id, str):
                            raise ValueError("detected technique ID must be a string")
                        detected = corpus.find(category, raw_id)
                        if detected is None:
                            if category == "Execution":
                                # The original Execution script warned but kept
                                # unknown model IDs; preserve that behavior.
                                detected = MitreTechnique(
                                    category=category,
                                    technique_id=raw_id,
                                    technique_name=str(
                                        candidate.get(
                                            f"{prefix}_technique_name"
                                        )
                                        or ""
                                    ),
                                )
                            else:
                                raise ValueError(
                                    f"technique ID {raw_id!r} is not in {category}"
                                )
                    parsed = candidate
                    break
                except Exception:
                    continue
            if parsed is None or not parsed[boolean_key]:
                continue

            raw_name = parsed.get(f"{prefix}_technique_name")
            assert detected is not None

            parent = detected
            subtechnique_id = None
            subtechnique_name = None
            if detected.parent_id is not None:
                parent = corpus.find(category, detected.parent_id) or detected
                # B5: preserve the original sub-technique before replacing the
                # primary fields with its parent.
                subtechnique_id = detected.technique_id
                subtechnique_name = (
                    str(raw_name) if raw_name else detected.technique_name
                )

            timestamps = [
                timestamp
                for timestamp in (action.start_timestamp, action.end_timestamp)
                if timestamp is not None
            ]
            findings.append(
                MitreFinding(
                    category=category,
                    technique_id=parent.technique_id,
                    technique_name=(
                        parent.technique_name
                        if detected.parent_id is not None
                        else str(raw_name or detected.technique_name)
                    ),
                    subtechnique_id=subtechnique_id,
                    subtechnique_name=subtechnique_name,
                    reasoning=str(parsed.get("Reasoning") or ""),
                    timestamps=timestamps,
                    action_title=action.title,
                    action_description=action.description,
                    # B4: all tactics use the normalized timing fields produced
                    # by action extraction, including Credential Access and Execution.
                    start_timestamp=action.start_timestamp,
                    end_timestamp=action.end_timestamp,
                    time_spent=action.duration_seconds,
                )
            )
    return findings


def _parse_mitre_datetime(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    formats = (
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M",
        "%Y-%m-%dT%H:%M",
        "%Y-%m-%d",
    )
    for timestamp_format in formats:
        try:
            return datetime.strptime(value, timestamp_format)
        except ValueError:
            continue
    return None


def _verify_suricata_response(
    response_text: str,
    corpus: MitreCorpus,
) -> dict[str, Any]:
    # Intentional parity with the original character-set strip.
    parsed = json.loads(
        response_text.strip("```json").strip("```")  # noqa: B005
    )
    required = {
        "analysis_in_context_of_previous_chunks",
        "MITRE_techniques_detected",
        "updated_memory_summary",
    }
    if not isinstance(parsed, dict) or not required <= parsed.keys():
        raise ValueError("MITRE response is missing required keys")
    if not isinstance(parsed["analysis_in_context_of_previous_chunks"], str):
        raise ValueError("analysis_in_context_of_previous_chunks must be a string")
    if not isinstance(parsed["MITRE_techniques_detected"], list):
        raise ValueError("MITRE_techniques_detected must be a list")
    if not isinstance(parsed["updated_memory_summary"], str):
        raise ValueError("updated_memory_summary must be a string")

    technique_keys = {
        "start_timestamp",
        "end_timestamp",
        "technique_category",
        "technique_id",
        "technique_name",
        "reasoning",
    }
    for technique in parsed["MITRE_techniques_detected"]:
        if not isinstance(technique, dict) or not technique_keys <= technique.keys():
            raise ValueError("detected technique is missing required keys")
        if _parse_mitre_datetime(technique["start_timestamp"]) is None:
            raise ValueError("start_timestamp is not parseable")
        if _parse_mitre_datetime(technique["end_timestamp"]) is None:
            raise ValueError("end_timestamp is not parseable")
        category = technique["technique_category"]
        if category not in corpus.categories:
            raise ValueError(f"unknown MITRE category {category!r}")
        technique_id = technique["technique_id"]
        # Preserve the original Suricata behavior; whether to retain the full
        # sub-technique here remains a separately reviewed future change.
        if isinstance(technique_id, str) and "." in technique_id:
            technique_id = technique_id.split(".", 1)[0]
            technique["technique_id"] = technique_id
        if corpus.find(category, technique_id) is None:
            raise ValueError(
                f"technique_id {technique_id!r} not found in {category}"
            )
    return parsed


def _phase_chunk_elements(phases: list[AttackPhase]) -> list[str]:
    elements: list[str] = []
    for phase in phases:
        first = _phase_payload(phase.events[0])
        if first.get("timestamp"):
            elements.append(f"Phase: {first['timestamp']}")
        if phase.new_phase_start_summary:
            elements.append(
                f"New Phase started: {phase.new_phase_start_summary}"
            )
        if phase.summary:
            elements.append(f"Phase ongoing summary: {phase.summary}\n")
    return elements


def _map_suricata(
    phases: list[AttackPhase],
    corpus: MitreCorpus,
    llm: LLMClient,
    *,
    repair_llm: LLMClient,
    max_retries: int,
) -> list[MitreFinding]:
    memory = "You are at the top of the page, there are no previous memories"
    phases_per_chunk = 5
    overlap_chunks = ""
    findings: list[MitreFinding] = []
    category_repr = f"dict_keys({list(corpus.categories)!r})"
    documents = corpus.documents()

    for index in range(0, len(phases), phases_per_chunk):
        elements = _phase_chunk_elements(phases[index : index + phases_per_chunk])
        current_chunk = "\n".join(elements)
        prompt = load_prompt("suricata_mitre").format(
            memory_from_previous_chunks=memory,
            overlap_chunks=overlap_chunks,
            current_chunk=current_chunk,
            mitre_categories=category_repr,
        )
        response_text = ""
        context = ""
        parsed: dict[str, Any] | None = None
        error: Exception | None = None
        try:
            response = llm.query(prompt, documents)
            response_text = response.text
            context = response.context
            parsed = _verify_suricata_response(response_text, corpus)
        except Exception as exc:
            error = exc

        # B8: query failures used to reference response/response_text before
        # assignment. Initialized values and corpus context make repair usable.
        if parsed is None:
            if not context:
                context = "\n\n".join(
                    document.text for document in documents[:5]
                )
            for _attempt in range(max_retries):
                try:
                    repaired = repair_llm.chat(
                        [
                            {
                                "role": "user",
                                "content": f"Context:\n {context}\n\n Prompt:\n {prompt}",
                            },
                            {"role": "assistant", "content": response_text},
                            {
                                "role": "user",
                                "content": (
                                    "The output is incorrect, here is a detailed "
                                    "message of where it went wrong "
                                    f"{error}. Please correct this and rewrite the "
                                    "answer, use the exact same formatting as the "
                                    "original  user prompt reqeust"
                                ),
                            },
                        ]
                    )
                    response_text = repaired
                    parsed = _verify_suricata_response(response_text, corpus)
                    break
                except Exception as exc:
                    error = exc
            if parsed is None:
                overlap_chunks += "\n".join(elements)
                continue

        overlap_chunks = "\n".join(elements[-2:])
        if parsed["updated_memory_summary"]:
            memory = parsed["updated_memory_summary"]
        for technique in parsed["MITRE_techniques_detected"]:
            start = _parse_mitre_datetime(technique["start_timestamp"])
            end = _parse_mitre_datetime(technique["end_timestamp"])
            timestamps = [timestamp for timestamp in (start, end) if timestamp]
            findings.append(
                MitreFinding(
                    category=technique["technique_category"],
                    technique_id=technique["technique_id"],
                    technique_name=technique["technique_name"],
                    reasoning=technique["reasoning"],
                    timestamps=timestamps,
                    start_timestamp=start,
                    end_timestamp=end,
                )
            )
    return findings


def map_mitre(
    activity: list[Action] | list[AttackPhase],
    corpus: MitreCorpus | str | Path,
    llm: LLMClient,
    *,
    repair_llm: LLMClient | None = None,
    max_retries: int = 3,
) -> list[MitreFinding]:
    """Use the source-specific original mapping workflow."""

    if not activity:
        return []
    resolved_corpus = (
        corpus if isinstance(corpus, MitreCorpus) else load_mitre_corpus(corpus)
    )
    first = activity[0]
    if isinstance(first, Action):
        return _map_actions(
            activity,  # type: ignore[arg-type]
            resolved_corpus,
            llm,
            max_retries=max_retries,
        )
    return _map_suricata(
        activity,  # type: ignore[arg-type]
        resolved_corpus,
        llm,
        repair_llm=repair_llm or llm,
        max_retries=max_retries,
    )
