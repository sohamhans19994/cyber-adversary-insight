"""Recreate the two GAMBIT annotation paths with the research data layout.

The default invocation runs both analysis paths:

    python run_experiments.py

Optional parameters allow paths and model conditions to vary between research
runs. API keys are intentionally not parameters or constants; they are read from
the process environment only when the model adapter is constructed.
"""

from __future__ import annotations

import argparse
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from gambit.analysis import AnalysisConfig
from gambit.errors import GambitError
from gambit.llm import DeterministicFakeLLM, LLMClient, OpenAIClient
from gambit.pipeline import AnalysisResult, run_analysis

ROOT = Path(__file__).resolve().parent

DEFAULT_OPNOTES_INPUT = ROOT / "data" / "opnotes" / "example.ctd"
DEFAULT_SURICATA_INPUT = ROOT / "data" / "suricata" / "example.csv"
DEFAULT_OPNOTES_MITRE = ROOT / "data" / "mitre" / "opnotes"
DEFAULT_SURICATA_MITRE = ROOT / "data" / "mitre" / "suricata"
DEFAULT_OUTPUT = ROOT / "outputs"
DEFAULT_PRIMARY_MODEL = "gpt-4o"
DEFAULT_UTILITY_MODEL = "gpt-4o-mini"
DEFAULT_EMBEDDING_MODEL = "text-embedding-ada-002"
DEFAULT_CONTEXT_WINDOW = 128_000

SourceSelection = Literal["both", "opnotes", "suricata"]


@dataclass(frozen=True)
class ExperimentSettings:
    """Recorded conditions for one annotation experiment."""

    source: SourceSelection = "both"
    opnotes_input: Path = DEFAULT_OPNOTES_INPUT
    suricata_input: Path = DEFAULT_SURICATA_INPUT
    opnotes_mitre: Path = DEFAULT_OPNOTES_MITRE
    suricata_mitre: Path = DEFAULT_SURICATA_MITRE
    output_dir: Path = DEFAULT_OUTPUT
    primary_model: str = DEFAULT_PRIMARY_MODEL
    utility_model: str = DEFAULT_UTILITY_MODEL
    embedding_model: str = DEFAULT_EMBEDDING_MODEL
    api_base: str | None = None
    embedding_api_base: str | None = None
    context_window: int = DEFAULT_CONTEXT_WINDOW
    max_output_tokens: int | None = None
    offline: bool = False
    resume: bool = True
    max_retries: int = 3
    phase_lookback: int = 5
    default_year: int | None = None
    aggregate_suricata: bool = True


def _clients(
    settings: ExperimentSettings,
    *,
    temperature: float,
) -> tuple[LLMClient, LLMClient]:
    if settings.offline:
        return DeterministicFakeLLM(), DeterministicFakeLLM()
    return (
        OpenAIClient(
            settings.primary_model,
            temperature=temperature,
            embedding_model=settings.embedding_model,
            api_base=settings.api_base,
            embedding_api_base=settings.embedding_api_base,
            context_window=settings.context_window,
            max_output_tokens=settings.max_output_tokens,
        ),
        OpenAIClient(
            settings.utility_model,
            temperature=temperature,
            embedding_model=settings.embedding_model,
            api_base=settings.api_base,
            embedding_api_base=settings.embedding_api_base,
            context_window=settings.context_window,
            max_output_tokens=settings.max_output_tokens,
        ),
    )


def _report(label: str, result: AnalysisResult, output_dir: Path) -> None:
    print(
        f"{label}: {len(result.actions)} actions, "
        f"{len(result.phases)} phases, "
        f"{len(result.mitre_findings)} MITRE findings"
    )
    print(f"  output: {output_dir}")


def run_experiments(settings: ExperimentSettings) -> dict[str, AnalysisResult]:
    """Run the selected experiment paths and return their structured results."""

    config = AnalysisConfig(
        max_retries=settings.max_retries,
        phase_lookback=settings.phase_lookback,
    )
    results: dict[str, AnalysisResult] = {}

    if settings.source in {"both", "opnotes"}:
        primary_llm, utility_llm = _clients(settings, temperature=0.1)
        opnotes_output = settings.output_dir / "opnotes"
        result = run_analysis(
            source="opnotes",
            input_path=settings.opnotes_input,
            mitre_corpus_path=settings.opnotes_mitre,
            output_dir=opnotes_output,
            primary_llm=primary_llm,
            utility_llm=utility_llm,
            config=config,
            resume=settings.resume,
            default_year=settings.default_year,
        )
        results["opnotes"] = result
        _report("OPNOTES", result, opnotes_output)

    if settings.source in {"both", "suricata"}:
        primary_llm, utility_llm = _clients(settings, temperature=0.0)
        suricata_output = settings.output_dir / "suricata"
        result = run_analysis(
            source="suricata",
            input_path=settings.suricata_input,
            mitre_corpus_path=settings.suricata_mitre,
            output_dir=suricata_output,
            primary_llm=primary_llm,
            utility_llm=utility_llm,
            config=config,
            resume=settings.resume,
            aggregate_suricata=settings.aggregate_suricata,
        )
        results["suricata"] = result
        _report("Suricata", result, suricata_output)

    return results


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Recreate the OPNOTES and Suricata annotation paths using data/ defaults. "
            "Authenticated endpoints read API keys from the environment."
        )
    )
    parser.add_argument(
        "--source",
        choices=("both", "opnotes", "suricata"),
        default="both",
        help="experiment path to run (default: both)",
    )
    parser.add_argument("--opnotes-input", type=Path, default=DEFAULT_OPNOTES_INPUT)
    parser.add_argument(
        "--suricata-input", type=Path, default=DEFAULT_SURICATA_INPUT
    )
    parser.add_argument("--opnotes-mitre", type=Path, default=DEFAULT_OPNOTES_MITRE)
    parser.add_argument(
        "--suricata-mitre", type=Path, default=DEFAULT_SURICATA_MITRE
    )
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--primary-model",
        default=os.getenv("GAMBIT_PRIMARY_MODEL", DEFAULT_PRIMARY_MODEL),
    )
    parser.add_argument(
        "--utility-model",
        default=os.getenv("GAMBIT_UTILITY_MODEL", DEFAULT_UTILITY_MODEL),
    )
    parser.add_argument(
        "--embedding-model",
        default=os.getenv("GAMBIT_EMBEDDING_MODEL", DEFAULT_EMBEDDING_MODEL),
        help="embedding model used for MITRE retrieval",
    )
    parser.add_argument(
        "--api-base",
        default=os.getenv("GAMBIT_API_BASE") or os.getenv("OPENAI_BASE_URL"),
        help=(
            "OpenAI-compatible generation endpoint; a trailing /v1 is added "
            "when omitted"
        ),
    )
    parser.add_argument(
        "--embedding-api-base",
        default=os.getenv("GAMBIT_EMBEDDING_API_BASE"),
        help="separate OpenAI-compatible embedding endpoint (default: --api-base)",
    )
    parser.add_argument(
        "--context-window",
        type=int,
        default=os.getenv("GAMBIT_CONTEXT_WINDOW", str(DEFAULT_CONTEXT_WINDOW)),
        help="context window declared for non-OpenAI model names",
    )
    parser.add_argument(
        "--max-output-tokens",
        type=int,
        default=os.getenv("GAMBIT_MAX_OUTPUT_TOKENS"),
        help="optional maximum completion length",
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="use deterministic fake responses; performs no API or embedding calls",
    )
    parser.add_argument(
        "--no-resume",
        action="store_true",
        help="require a new, empty output location",
    )
    parser.add_argument("--max-retries", type=int, default=3)
    parser.add_argument("--phase-lookback", type=int, default=5)
    parser.add_argument("--default-year", type=int)
    parser.add_argument(
        "--no-aggregate-suricata",
        action="store_true",
        help="disable the original >5,000-row adjacent-alert aggregation",
    )
    return parser


def main() -> int:
    args = _parser().parse_args()
    if args.max_retries < 1:
        _parser().error("--max-retries must be at least 1")
    if args.phase_lookback < 1:
        _parser().error("--phase-lookback must be at least 1")
    if args.context_window < 1:
        _parser().error("--context-window must be at least 1")
    if args.max_output_tokens is not None and args.max_output_tokens < 1:
        _parser().error("--max-output-tokens must be at least 1")

    settings = ExperimentSettings(
        source=args.source,
        opnotes_input=args.opnotes_input,
        suricata_input=args.suricata_input,
        opnotes_mitre=args.opnotes_mitre,
        suricata_mitre=args.suricata_mitre,
        output_dir=args.output_dir,
        primary_model=args.primary_model,
        utility_model=args.utility_model,
        embedding_model=args.embedding_model,
        api_base=args.api_base,
        embedding_api_base=args.embedding_api_base,
        context_window=args.context_window,
        max_output_tokens=args.max_output_tokens,
        offline=args.offline,
        resume=not args.no_resume,
        max_retries=args.max_retries,
        phase_lookback=args.phase_lookback,
        default_year=args.default_year,
        aggregate_suricata=not args.no_aggregate_suricata,
    )
    try:
        run_experiments(settings)
    except GambitError as exc:
        print(f"Error: {exc}")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
