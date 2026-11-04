"""Research-stage orchestration with atomic, resumable intermediate outputs."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, TypeVar

from pydantic import BaseModel, TypeAdapter, ValidationError

from gambit.analysis import AnalysisConfig, extract_actions, segment_phases
from gambit.errors import InputValidationError, ResumeError
from gambit.io_utils import atomic_write_json
from gambit.llm import LLMClient
from gambit.mitre import load_mitre_corpus, map_mitre
from gambit.models import Action, AttackPhase, MitreFinding, RunManifest
from gambit.opnotes import load_opnotes
from gambit.prompts import PROMPT_VERSION
from gambit.suricata import load_suricata

SourceKind = Literal["opnotes", "suricata"]
StageModel = TypeVar("StageModel", bound=BaseModel)


@dataclass(frozen=True)
class AnalysisResult:
    actions: list[Action]
    phases: list[AttackPhase]
    mitre_findings: list[MitreFinding]
    manifest: RunManifest


def hash_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    try:
        with Path(path).open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise InputValidationError(f"cannot hash input file {path}: {exc}") from exc
    return digest.hexdigest()


def _dump_models(items: list[BaseModel]) -> list[dict[str, object]]:
    return [item.model_dump(mode="json") for item in items]


def _manifest_model_identity(client: LLMClient) -> str:
    return str(getattr(client, "manifest_identity", client.model_name))


def _read_manifest(path: Path) -> RunManifest:
    try:
        return RunManifest.model_validate_json(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValidationError) as exc:
        raise ResumeError(f"cannot validate existing run manifest: {exc}") from exc


def _read_stage(path: Path, model: type[StageModel]) -> list[StageModel]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        return TypeAdapter(list[model]).validate_python(payload)
    except (OSError, UnicodeError, json.JSONDecodeError, ValidationError) as exc:
        raise ResumeError(f"cannot validate existing stage {path.name}: {exc}") from exc


def _save_manifest(output_dir: Path, manifest: RunManifest) -> None:
    atomic_write_json(
        output_dir / "run_manifest.json", manifest.model_dump(mode="json")
    )


def _mark_stage(
    output_dir: Path,
    manifest: RunManifest,
    stage: str,
) -> RunManifest:
    stages = list(dict.fromkeys([*manifest.stages_completed, stage]))
    updated = manifest.model_copy(update={"stages_completed": stages})
    _save_manifest(output_dir, updated)
    return updated


def _validate_resume(
    existing: RunManifest,
    *,
    source_hash: str,
    corpus_hash: str,
    primary_model: str,
    utility_model: str,
    configuration: dict[str, object],
) -> None:
    comparisons = {
        "source_hash": (existing.source_hash, source_hash),
        "corpus_hash": (existing.corpus_hash, corpus_hash),
        "prompt_version": (existing.prompt_version, PROMPT_VERSION),
        "primary_model": (existing.primary_model, primary_model),
        "utility_model": (existing.utility_model, utility_model),
        "configuration": (existing.configuration, configuration),
    }
    mismatches = [name for name, (old, new) in comparisons.items() if old != new]
    if mismatches:
        raise ResumeError(
            "existing output cannot be resumed because these fields changed: "
            + ", ".join(mismatches)
            + "; choose a new, empty output directory for this run"
        )


def run_analysis(
    *,
    source: SourceKind,
    input_path: str | Path,
    mitre_corpus_path: str | Path,
    output_dir: str | Path,
    primary_llm: LLMClient,
    utility_llm: LLMClient,
    config: AnalysisConfig | None = None,
    resume: bool = True,
    source_id: str | None = None,
    default_year: int | None = None,
    aggregate_suricata: bool = True,
) -> AnalysisResult:
    """Run one source pipeline and persist every stage atomically."""

    if source not in {"opnotes", "suricata"}:
        raise InputValidationError("source must be 'opnotes' or 'suricata'")
    resolved_config = config or AnalysisConfig()
    destination = Path(output_dir)
    destination.mkdir(parents=True, exist_ok=True)

    corpus = load_mitre_corpus(mitre_corpus_path)
    source_hash = hash_file(input_path)
    primary_identity = _manifest_model_identity(primary_llm)
    utility_identity = _manifest_model_identity(utility_llm)
    configuration: dict[str, object] = {
        "source": source,
        "analysis": resolved_config.to_dict(),
        "aggregate_suricata": aggregate_suricata,
        "default_year": default_year,
    }
    manifest_path = destination / "run_manifest.json"
    if manifest_path.exists():
        if not resume:
            raise ResumeError(
                "output directory already contains a run manifest; "
                "choose an empty output directory or enable resume"
            )
        manifest = _read_manifest(manifest_path)
        _validate_resume(
            manifest,
            source_hash=source_hash,
            corpus_hash=corpus.corpus_hash,
            primary_model=primary_identity,
            utility_model=utility_identity,
            configuration=configuration,
        )
        manifest = manifest.model_copy(
            update={"status": "running", "completed_at": None}
        )
    else:
        manifest = RunManifest(
            source_hash=source_hash,
            corpus_hash=corpus.corpus_hash,
            prompt_version=PROMPT_VERSION,
            primary_model=primary_identity,
            utility_model=utility_identity,
            configuration=configuration,
            started_at=datetime.now(UTC),
        )
    _save_manifest(destination, manifest)

    actions_path = destination / "actions.json"
    phases_path = destination / "phases.json"
    findings_path = destination / "mitre_findings.json"

    try:
        if "actions" in manifest.stages_completed:
            actions = _read_stage(actions_path, Action)
        elif source == "opnotes":
            document = load_opnotes(
                input_path, source_id=source_id, default_year=default_year
            )
            actions = extract_actions(
                document,
                primary_llm,
                utility_llm=utility_llm,
                config=resolved_config,
            )
            atomic_write_json(actions_path, _dump_models(actions))
            manifest = _mark_stage(destination, manifest, "actions")
        else:
            actions = []
            atomic_write_json(actions_path, [])
            manifest = _mark_stage(destination, manifest, "actions")

        if "phases" in manifest.stages_completed:
            phases = _read_stage(phases_path, AttackPhase)
        elif source == "suricata":
            events = load_suricata(input_path, aggregate=aggregate_suricata)
            phases = segment_phases(events, utility_llm, config=resolved_config)
            atomic_write_json(phases_path, _dump_models(phases))
            manifest = _mark_stage(destination, manifest, "phases")
        else:
            phases = []
            atomic_write_json(phases_path, [])
            manifest = _mark_stage(destination, manifest, "phases")

        if "mitre_findings" in manifest.stages_completed:
            findings = _read_stage(findings_path, MitreFinding)
        else:
            activity: list[Action] | list[AttackPhase] = (
                actions if source == "opnotes" else phases
            )
            findings = map_mitre(
                activity,
                corpus,
                primary_llm if source == "opnotes" else utility_llm,
                repair_llm=utility_llm,
                max_retries=resolved_config.max_retries,
            )
            atomic_write_json(findings_path, _dump_models(findings))
            manifest = _mark_stage(destination, manifest, "mitre_findings")

        manifest = manifest.model_copy(
            update={"status": "completed", "completed_at": datetime.now(UTC)}
        )
        _save_manifest(destination, manifest)
        return AnalysisResult(
            actions=actions,
            phases=phases,
            mitre_findings=findings,
            manifest=manifest,
        )
    except KeyboardInterrupt:
        manifest = manifest.model_copy(update={"status": "interrupted"})
        _save_manifest(destination, manifest)
        raise
    except Exception:
        manifest = manifest.model_copy(update={"status": "failed"})
        _save_manifest(destination, manifest)
        raise
