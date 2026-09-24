from typing import Any

from evals.probe import CallOutcome, CandidateStats, ProbeObservation
from evals.probe_candidates import Candidate, Prices
from evals.probe_corpus import Role
from mcp_auditor.config import Settings
from mcp_auditor.domain.models import AuditCategory, CoverageGap, TokenUsage

ONE_DOLLAR_PER_MILLION_INPUT = Prices(input=1.0, cached_input=0.0, output=0.0)


def a_candidate(prices: Prices = ONE_DOLLAR_PER_MILLION_INPUT) -> Candidate:
    return Candidate(
        name="challenger",
        settings=Settings(provider="google", model="some-model", judge_model="", reasoning=""),
        prices=prices,
        reasoning_expected=True,
    )


def an_observation(
    role: Role = "main",
    schema_name: str = "TestCaseBatch",
    seconds: float = 1.0,
    outcome: CallOutcome = CallOutcome.PARSED,
    **changes: Any,
) -> ProbeObservation:
    return ProbeObservation(
        candidate="challenger",
        call_id=f"honeypot/{schema_name}/000",
        schema_name=schema_name,
        role=role,
        seconds=seconds,
        usage=changes.pop("usage", TokenUsage()),
        outcome=outcome,
        coverage_gap=changes.pop("coverage_gap", None),
        **changes,
    )


def a_million_input_tokens() -> TokenUsage:
    return TokenUsage(input_tokens=1_000_000)


def a_coverage_gap() -> CoverageGap:
    return CoverageGap(
        requested_cases=10, received_cases=8, missing_categories=[AuditCategory.INJECTION]
    )


def reference_stats() -> CandidateStats:
    return CandidateStats(
        candidate="reference",
        median_seconds={"main": 1.0, "judge": 1.0},
        parse_failures={},
        refusals=0,
        errors=0,
        weighted_cost=1.0,
        reasoning_tokens=0,
        reasoning_expected=None,
    )


def challenger_stats(**changes: Any) -> CandidateStats:
    """Clean on every bar against reference_stats(), apart from the changes."""
    clean = reference_stats().model_copy(update={"candidate": "challenger"})
    return clean.model_copy(update=changes)
