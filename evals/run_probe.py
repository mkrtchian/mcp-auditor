"""Send the probe corpus to the reference and every candidate
(`uv run python -m evals.run_probe`), and report each model's statistics and defects.

What is measured, what is reported and the limits are in `evals/probe_method.md`.
The command exits 0 whatever it finds.
"""

import argparse
import asyncio
import json
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table

from evals.model_conditions import ModelConditions
from evals.probe.analysis import (
    CallOutcome,
    CandidateStats,
    ProbeObservation,
    judge_call_weight,
    list_defects,
    summarize,
)
from evals.probe.candidates import CANDIDATES, MEASURED, PRICES_DATE, REFERENCE, Candidate
from evals.probe.corpus import (
    CORPUS_PATH,
    SCHEMA_NAMES,
    ProbeCall,
    ProbeCorpus,
    Role,
    load_corpus,
    schema_for,
)
from evals.probe.subset import (
    UnknownCandidate,
    defect_counts,
    defect_table,
    select_calls,
    select_candidates,
)
from mcp_auditor.adapters.llm import create_judge_llm, create_llm
from mcp_auditor.adapters.llm_throttling import ThrottlePatience
from mcp_auditor.domain.coverage import find_coverage_gap
from mcp_auditor.domain.models import AuditCategory, CoverageGap, ProviderUsage, TestCaseBatch
from mcp_auditor.domain.ports import LLMPort, ProviderRefusal, ProviderThrottled, UnreadableAnswer

DEFAULT_REPORT_PATH = "output/probe_report.json"
SUBSET_REPORT_PATH = "output/probe_subset.json"

console = Console()


@dataclass(frozen=True)
class CandidateModels:
    candidate: Candidate
    main: LLMPort
    judge: LLMPort


@dataclass(frozen=True)
class ProbeResult:
    corpus: ProbeCorpus
    judge_weight: float
    observations: list[ProbeObservation]
    reference: CandidateStats
    candidates: list[CandidateStats]


def main() -> None:
    args = _parse_arguments()
    load_dotenv()
    if not CORPUS_PATH.exists():
        console.print(
            f"[red]No corpus at {CORPUS_PATH}.[/red] Run evals.capture_probe_corpus first."
        )
        sys.exit(1)
    corpus = load_corpus(CORPUS_PATH)
    if args.candidates is not None or args.schema is not None:
        _run_subset(corpus, args)
        return
    report = args.report or DEFAULT_REPORT_PATH
    models = _build_models(MEASURED)
    observations = asyncio.run(_send_corpus(corpus, models, Path(report).with_suffix(".jsonl")))
    result = _analyze(corpus, observations)
    _write_report(Path(report), result)
    _print_table(result)
    console.print(f"Report written to {report}")


def _parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Send the probe corpus to every candidate model")
    parser.add_argument("--report", type=str, default=None)
    parser.add_argument(
        "--candidates", nargs="+", metavar="NAME", help="subset run: these candidates only"
    )
    parser.add_argument("--schema", choices=SCHEMA_NAMES, help="subset run: this schema only")
    return parser.parse_args()


def _run_subset(corpus: ProbeCorpus, args: argparse.Namespace) -> None:
    """Debugging only: sends a slice of the corpus and computes no statistics."""
    try:
        candidates = MEASURED if args.candidates is None else select_candidates(args.candidates)
    except UnknownCandidate as unknown:
        console.print(f"[red]{unknown}[/red]")
        sys.exit(1)
    subset = corpus.model_copy(update={"calls": select_calls(corpus, args.schema)})
    models = _build_models(candidates)
    sink = Path(args.report or SUBSET_REPORT_PATH).with_suffix(".jsonl")
    observations = asyncio.run(_send_corpus(subset, models, sink))
    console.print(defect_table(defect_counts(candidates, observations)))
    console.print(f"Observations written to {sink}")


# Keeps the provider's queue out of the latency, a 429 is an error ("rerun the probe").
_NO_PATIENCE = ThrottlePatience(max_total_wait=0.0)


def _build_models(candidates: list[Candidate]) -> list[CandidateModels]:
    built: list[CandidateModels] = []
    for candidate in candidates:
        try:
            main = create_llm(candidate.settings, patience=_NO_PATIENCE)
            judge = create_judge_llm(candidate.settings, patience=_NO_PATIENCE)
        except Exception as error:
            console.print(f"[red]Cannot build the models of {candidate.name}:[/red] {error}")
            sys.exit(1)
        built.append(CandidateModels(candidate, main, judge))
    return built


async def _send_corpus(
    corpus: ProbeCorpus, models: list[CandidateModels], sink: Path
) -> list[ProbeObservation]:
    """Each observation reaches `sink` as it is measured, so a hung run keeps what it measured."""
    sink.parent.mkdir(parents=True, exist_ok=True)
    sink.write_text("")
    observations: list[ProbeObservation] = []
    total = len(corpus.calls) * len(models)
    for index, call in enumerate(corpus.calls):
        for candidate_models in _rotation(models, index):
            observation = await observe(candidate_models, call, corpus.budget)
            append_observation(sink, observation)
            observations.append(observation)
            console.print(_progress_line(len(observations), total, observation))
    return observations


def append_observation(sink: Path, observation: ProbeObservation) -> None:
    with sink.open("a") as lines:
        lines.write(observation.model_dump_json() + "\n")


def _progress_line(done: int, total: int, observation: ProbeObservation) -> str:
    line = (
        f"call {done}/{total} {observation.candidate} {observation.call_id} "
        f"{observation.outcome.value} {observation.seconds:.1f}s"
    )
    if observation.truncated_attempts > 0:
        line += f" ({observation.truncated_attempts} truncated)"
    return line


def _rotation(models: list[CandidateModels], call_index: int) -> list[CandidateModels]:
    """No candidate always runs first after a pause."""
    start = call_index % len(models)
    return models[start:] + models[:start]


async def observe(models: CandidateModels, call: ProbeCall, budget: int) -> ProbeObservation:
    llm = models.judge if call.role == "judge" else models.main
    started = time.perf_counter()
    answer = await _answer(llm, call)
    seconds = time.perf_counter() - started
    return ProbeObservation(
        candidate=models.candidate.name,
        call_id=call.call_id,
        schema_name=call.schema_name,
        role=call.role,
        seconds=seconds,
        usage=answer.usage,
        outcome=answer.outcome,
        coverage_gap=_coverage_gap(answer.output, budget),
        error=answer.error,
        truncated_attempts=answer.truncated_attempts,
    )


@dataclass(frozen=True)
class _Answer:
    outcome: CallOutcome
    usage: ProviderUsage
    output: object = None
    error: str | None = None
    truncated_attempts: int = 0


async def _answer(llm: LLMPort, call: ProbeCall) -> _Answer:
    try:
        output, usage = await llm.generate_structured(call.prompt, schema_for(call.schema_name))
        return _Answer(CallOutcome.PARSED, usage, output)
    except UnreadableAnswer as unreadable:
        return _Answer(
            CallOutcome.PARSE_FAILURE,
            unreadable.usage,
            truncated_attempts=unreadable.truncated_parse_attempts,
        )
    except ProviderRefusal as refusal:
        return _Answer(CallOutcome.PARSE_FAILURE, refusal.usage, error=refusal.provider_message)
    except ProviderThrottled as throttled:
        return _Answer(CallOutcome.ERROR, throttled.usage, error=str(throttled))
    except Exception as exception:
        return _Answer(
            CallOutcome.ERROR, ProviderUsage(), error=f"{type(exception).__name__}: {exception}"
        )


def _coverage_gap(output: object, budget: int) -> CoverageGap | None:
    if not isinstance(output, TestCaseBatch):
        return None
    return find_coverage_gap(output, budget, list(AuditCategory))


def _analyze(corpus: ProbeCorpus, observations: list[ProbeObservation]) -> ProbeResult:
    weight = judge_call_weight(corpus)

    def stats_of(candidate: Candidate) -> CandidateStats:
        of_candidate = [o for o in observations if o.candidate == candidate.name]
        return summarize(candidate, of_candidate, weight)

    return ProbeResult(
        corpus=corpus,
        judge_weight=weight,
        observations=observations,
        reference=stats_of(REFERENCE),
        candidates=[stats_of(candidate) for candidate in CANDIDATES],
    )


def _write_report(path: Path, result: ProbeResult) -> None:
    report = {
        "corpus": {
            "captured_at": result.corpus.captured_at,
            "commit": result.corpus.commit,
            "calls": len(result.corpus.calls),
            "judge_weight": result.judge_weight,
        },
        "prices_date": PRICES_DATE,
        "candidates": [_candidate_entry(c) for c in MEASURED],
        "statistics": [s.model_dump() for s in _measured_stats(result)],
        "defects": {s.candidate: list_defects(s) for s in _measured_stats(result)},
        "observations": [o.model_dump(mode="json") for o in result.observations],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2))


def _measured_stats(result: ProbeResult) -> list[CandidateStats]:
    return [result.reference, *result.candidates]


def _candidate_entry(candidate: Candidate) -> dict[str, Any]:
    settings = candidate.settings
    conditions = ModelConditions.of(settings)
    return {
        "name": candidate.name,
        "provider": conditions.provider,
        "openrouter_providers": (
            list(settings.resolve_openrouter_providers())
            if settings.provider == "openrouter"
            else []
        ),
        "model": conditions.model,
        "judge_model": conditions.judge_model,
        "reasoning": conditions.reasoning,
        "judge_reasoning": conditions.judge_reasoning,
        "temperature": "provider default",
        "prices": asdict(candidate.prices),
        "reasoning_expected": candidate.reasoning_expected,
    }


def _print_table(result: ProbeResult) -> None:
    table = Table(title="Probe")
    for column in ("Candidate", "Main median", "Judge median", "Weighted cost", "Cost ratio"):
        table.add_column(column)
    for column in ("Parse failures", "Incomplete batches", "Errors", "Reasoning tokens", "Defects"):
        table.add_column(column)
    for stats in _measured_stats(result):
        table.add_row(*_stats_cells(stats, result.reference))
    console.print(table)
    _print_defects(result)


def _stats_cells(stats: CandidateStats, reference: CandidateStats) -> list[str]:
    return [
        stats.candidate,
        _seconds(stats, "main"),
        _seconds(stats, "judge"),
        f"${stats.weighted_cost:.4f}",
        _ratio(stats.weighted_cost, reference.weighted_cost),
        str(sum(stats.parse_failures.values())),
        str(stats.incomplete_batches),
        str(stats.errors),
        str(stats.reasoning_tokens),
        str(len(list_defects(stats))),
    ]


def _seconds(stats: CandidateStats, role: Role) -> str:
    median_seconds = stats.median_seconds.get(role)
    return "-" if median_seconds is None else f"{median_seconds:.2f} s"


def _ratio(value: float, reference: float) -> str:
    return "-" if reference == 0 else f"{value / reference:.2f}x"


def _print_defects(result: ProbeResult) -> None:
    for stats in _measured_stats(result):
        for defect in list_defects(stats):
            console.print(f"{stats.candidate}: {defect}")


if __name__ == "__main__":
    main()
