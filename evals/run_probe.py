"""Replay the probe corpus against every candidate (`uv run python -m evals.run_probe`).

What is measured, the bar values and the limits are in `evals/probe_method.md`.
The verdict is the report: the command exits 0 whether or not a challenger is admitted.
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
from rich.progress import Progress
from rich.table import Table

from evals.honeypots import REPO_ROOT
from evals.probe import (
    Admission,
    Bars,
    CallOutcome,
    CandidateStats,
    ProbeObservation,
    admit,
    reference_failures,
    summarize,
)
from evals.probe_candidates import CHALLENGERS, PRICES_DATE, REFERENCE, Candidate
from evals.probe_corpus import ProbeCall, ProbeCorpus, Role, load_corpus, schema_for
from mcp_auditor.adapters.llm import create_judge_llm, create_llm
from mcp_auditor.domain.coverage import find_coverage_gap
from mcp_auditor.domain.models import AuditCategory, CoverageGap, TestCaseBatch, TokenUsage
from mcp_auditor.domain.ports import LLMPort

CORPUS_PATH = REPO_ROOT / "evals" / "fixtures" / "probe_corpus.json"
DEFAULT_REPORT_PATH = "output/probe_report.json"
CANDIDATES = [REFERENCE, *CHALLENGERS]

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
    challengers: list[CandidateStats]
    admissions: list[Admission]


def main() -> None:
    parser = argparse.ArgumentParser(description="Replay the probe corpus against every candidate")
    parser.add_argument("--report", type=str, default=DEFAULT_REPORT_PATH)
    args = parser.parse_args()
    load_dotenv()
    if not CORPUS_PATH.exists():
        console.print(
            f"[red]No corpus at {CORPUS_PATH}.[/red] Run evals.capture_probe_corpus first."
        )
        sys.exit(1)
    corpus = load_corpus(CORPUS_PATH)
    models = _build_models(CANDIDATES)
    observations = asyncio.run(_replay(corpus, models))
    result = _analyze(corpus, observations)
    _write_report(Path(args.report), result)
    _print_table(result)
    console.print(f"Report written to {args.report}")


def _build_models(candidates: list[Candidate]) -> list[CandidateModels]:
    built: list[CandidateModels] = []
    for candidate in candidates:
        try:
            main = create_llm(candidate.settings)
            judge = create_judge_llm(candidate.settings)
        except Exception as error:
            console.print(f"[red]Cannot build the models of {candidate.name}:[/red] {error}")
            sys.exit(1)
        built.append(CandidateModels(candidate, main, judge))
    return built


async def _replay(corpus: ProbeCorpus, models: list[CandidateModels]) -> list[ProbeObservation]:
    observations: list[ProbeObservation] = []
    with Progress(console=console) as progress:
        task = progress.add_task("Probing", total=len(corpus.calls) * len(models))
        for index, call in enumerate(corpus.calls):
            for candidate_models in _rotation(models, index):
                observations.append(await _observe(candidate_models, call, corpus.budget))
                progress.advance(task)
    return observations


def _rotation(models: list[CandidateModels], call_index: int) -> list[CandidateModels]:
    """No candidate always runs first after a pause."""
    start = call_index % len(models)
    return models[start:] + models[:start]


async def _observe(models: CandidateModels, call: ProbeCall, budget: int) -> ProbeObservation:
    llm = models.judge if call.role == "judge" else models.main
    outcome, usage, output, error = CallOutcome.PARSED, TokenUsage(), None, None
    started = time.perf_counter()
    try:
        output, usage = await llm.generate_structured(call.prompt, schema_for(call.schema_name))
    except ValueError:
        outcome = CallOutcome.PARSE_FAILURE
    except Exception as exception:
        outcome, error = CallOutcome.ERROR, f"{type(exception).__name__}: {exception}"
    seconds = time.perf_counter() - started
    return ProbeObservation(
        candidate=models.candidate.name,
        call_id=call.call_id,
        schema_name=call.schema_name,
        role=call.role,
        seconds=seconds,
        usage=usage,
        outcome=outcome,
        coverage_gap=_coverage_gap(output, budget),
        error=error,
    )


def _coverage_gap(output: object, budget: int) -> CoverageGap | None:
    if not isinstance(output, TestCaseBatch):
        return None
    return find_coverage_gap(output, budget, list(AuditCategory))


def _analyze(corpus: ProbeCorpus, observations: list[ProbeObservation]) -> ProbeResult:
    judge_weight = corpus.judge_calls_captured / sum(c.role == "judge" for c in corpus.calls)
    stats = [
        summarize(c, [o for o in observations if o.candidate == c.name], judge_weight)
        for c in CANDIDATES
    ]
    reference, challengers = stats[0], stats[1:]
    return ProbeResult(
        corpus=corpus,
        judge_weight=judge_weight,
        observations=observations,
        reference=reference,
        challengers=challengers,
        admissions=[admit(s, reference, Bars()) for s in challengers],
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
        "bars": Bars().model_dump(),
        "candidates": [_candidate_entry(c) for c in CANDIDATES],
        "reference": result.reference.model_dump(),
        "reference_failed_bars_recorded_only": reference_failures(result.reference, Bars()),
        "challengers": [s.model_dump() for s in result.challengers],
        "admissions": [a.model_dump() for a in result.admissions],
        "observations": [o.model_dump(mode="json") for o in result.observations],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2))


def _candidate_entry(candidate: Candidate) -> dict[str, Any]:
    settings = candidate.settings
    model, judge_model = settings.resolve_model(), settings.resolve_judge_model()
    return {
        "name": candidate.name,
        "provider": settings.provider,
        "model": model,
        "judge_model": judge_model,
        "reasoning": settings.resolve_reasoning(model),
        "judge_reasoning": settings.resolve_reasoning(judge_model),
        "temperature": "provider default",
        "prices": asdict(candidate.prices),
        "reasoning_expected": candidate.reasoning_expected,
    }


def _print_table(result: ProbeResult) -> None:
    table = Table(title="Probe admission")
    for column in ("Candidate", "Main median", "Judge median", "Weighted cost", "Cost ratio"):
        table.add_column(column)
    for column in ("Parse failures", "Refusals", "Errors", "Reasoning tokens", "Verdict"):
        table.add_column(column)
    table.add_row(*_stats_cells(result.reference, result.reference), "reference (exempt)")
    for stats, admission in zip(result.challengers, result.admissions, strict=True):
        verdict = "[green]admitted[/green]" if admission.admitted else "[red]not admitted[/red]"
        table.add_row(*_stats_cells(stats, result.reference), verdict)
    console.print(table)
    _print_reasons(result)


def _stats_cells(stats: CandidateStats, reference: CandidateStats) -> list[str]:
    return [
        stats.candidate,
        _seconds(stats, "main"),
        _seconds(stats, "judge"),
        f"${stats.weighted_cost:.4f}",
        _ratio(stats.weighted_cost, reference.weighted_cost),
        str(sum(stats.parse_failures.values())),
        str(stats.refusals),
        str(stats.errors),
        str(stats.reasoning_tokens),
    ]


def _seconds(stats: CandidateStats, role: Role) -> str:
    median_seconds = stats.median_seconds.get(role)
    return "-" if median_seconds is None else f"{median_seconds:.2f} s"


def _ratio(value: float, reference: float) -> str:
    return "-" if reference == 0 else f"{value / reference:.2f}x"


def _print_reasons(result: ProbeResult) -> None:
    for reason in reference_failures(result.reference, Bars()):
        console.print(f"{result.reference.candidate} (recorded only): {reason}")
    for admission in result.admissions:
        for reason in admission.reasons:
            console.print(f"{admission.candidate}: {reason}")


if __name__ == "__main__":
    main()
