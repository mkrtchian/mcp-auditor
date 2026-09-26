"""The probe's analysis: per-candidate statistics and the defects the probe reports.

Pure: the runner (`evals/run_probe.py`) makes the calls and hands the observations
over. What the probe reports and its limits are in `evals/probe_method.md`.
"""

from collections import Counter
from enum import StrEnum
from statistics import median

from pydantic import BaseModel

from evals.probe_candidates import Candidate, Prices
from evals.probe_corpus import Role
from mcp_auditor.domain.models import CoverageGap, TestCaseBatch, TokenUsage

_GENERATION_SCHEMA = TestCaseBatch.__name__


class CallOutcome(StrEnum):
    PARSED = "parsed"
    PARSE_FAILURE = "parse_failure"  # ValueError from the adapter after its attempts
    ERROR = "error"  # any other exception (API error, timeout)


class ProbeObservation(BaseModel):
    candidate: str
    call_id: str
    schema_name: str
    role: Role
    seconds: float
    usage: TokenUsage
    outcome: CallOutcome
    coverage_gap: CoverageGap | None = None  # TestCaseBatch calls only
    error: str | None = None
    truncated_attempts: int = 0  # attempts cut by the output cap on a parse failure


class CandidateStats(BaseModel):
    candidate: str
    median_seconds: dict[Role, float]
    parse_failures: dict[str, int]  # per schema, nonzero only
    refusals: int
    errors: int
    weighted_cost: float  # dollars, judge calls weighted by captured over sampled
    reasoning_tokens: int
    reasoning_expected: bool | None


def summarize(
    candidate: Candidate, observations: list[ProbeObservation], judge_weight: float
) -> CandidateStats:
    return CandidateStats(
        candidate=candidate.name,
        median_seconds=_median_seconds_per_role(observations),
        parse_failures=dict(
            Counter(o.schema_name for o in observations if o.outcome == CallOutcome.PARSE_FAILURE)
        ),
        refusals=sum(_is_refusal(o) for o in observations),
        errors=sum(o.outcome == CallOutcome.ERROR for o in observations),
        weighted_cost=sum(
            call_cost(o.usage, candidate.prices) * (judge_weight if o.role == "judge" else 1.0)
            for o in observations
        ),
        reasoning_tokens=sum(o.usage.reasoning_tokens for o in observations),
        reasoning_expected=candidate.reasoning_expected,
    )


class DefectCounts(BaseModel):
    candidate: str
    calls: int
    parse_failures: int
    parse_failures_with_truncation: int  # at least one attempt cut by the output cap
    refusals: int  # same rule as `summarize`
    errors: int


def count_defects(candidate: str, observations: list[ProbeObservation]) -> DefectCounts:
    parse_failures = [o for o in observations if o.outcome == CallOutcome.PARSE_FAILURE]
    return DefectCounts(
        candidate=candidate,
        calls=len(observations),
        parse_failures=len(parse_failures),
        parse_failures_with_truncation=sum(o.truncated_attempts > 0 for o in parse_failures),
        refusals=sum(_is_refusal(o) for o in observations),
        errors=sum(o.outcome == CallOutcome.ERROR for o in observations),
    )


def _median_seconds_per_role(observations: list[ProbeObservation]) -> dict[Role, float]:
    seconds: dict[Role, list[float]] = {}
    for observation in observations:
        seconds.setdefault(observation.role, []).append(observation.seconds)
    return {role: median(values) for role, values in seconds.items()}


def _is_refusal(observation: ProbeObservation) -> bool:
    if observation.schema_name != _GENERATION_SCHEMA:
        return False
    return observation.outcome == CallOutcome.PARSE_FAILURE or observation.coverage_gap is not None


def call_cost(usage: TokenUsage, prices: Prices) -> float:
    uncached_input = usage.input_tokens - usage.cached_input_tokens
    dollars_per_million = (
        uncached_input * prices.input
        + usage.cached_input_tokens * prices.cached_input
        + usage.output_tokens * prices.output
    )
    return dollars_per_million / 1_000_000


def list_defects(stats: CandidateStats) -> list[str]:
    return [*_count_defects(stats), *_reasoning_defects(stats)]


def _count_defects(stats: CandidateStats) -> list[str]:
    defects = [
        f"{count} parse failure(s) on {schema}" for schema, count in stats.parse_failures.items()
    ]
    if stats.refusals:
        defects.append(f"{stats.refusals} refusal(s) on {_GENERATION_SCHEMA} calls")
    if stats.errors:
        defects.append(f"{stats.errors} error(s): not measured on the whole corpus, rerun")
    return defects


def _reasoning_defects(stats: CandidateStats) -> list[str]:
    if stats.reasoning_expected is None:
        return []
    if stats.reasoning_expected and stats.reasoning_tokens == 0:
        return ["0 reasoning tokens where the setting expects some: it did not reach the API"]
    if not stats.reasoning_expected and stats.reasoning_tokens > 0:
        return [
            f"{stats.reasoning_tokens} reasoning tokens where the setting expects none: "
            "it did not reach the API"
        ]
    return []
