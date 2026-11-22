from typing import Any

from evals.probe.analysis import CandidateStats
from evals.probe.candidates import Candidate, Prices
from mcp_auditor.config import Settings
from mcp_auditor.domain.models import AuditCategory, CoverageGap, ProviderUsage

ONE_DOLLAR_PER_MILLION_INPUT = Prices(input=1.0, cached_input=0.0, output=0.0)


def a_candidate(prices: Prices = ONE_DOLLAR_PER_MILLION_INPUT) -> Candidate:
    return Candidate(
        name="candidate",
        settings=Settings(provider="google", model="some-model", judge_model="", reasoning=""),
        prices=prices,
        reasoning_expected=True,
    )


def a_million_input_tokens() -> ProviderUsage:
    return ProviderUsage(input_tokens=1_000_000)


def a_coverage_gap() -> CoverageGap:
    return CoverageGap(
        requested_cases=10, received_cases=8, missing_categories=[AuditCategory.INJECTION]
    )


def candidate_stats(**changes: Any) -> CandidateStats:
    """Clean, apart from the changes."""
    clean = CandidateStats(
        candidate="candidate",
        median_seconds={"main": 1.0, "judge": 1.0},
        parse_failures={},
        refusals=0,
        errors=0,
        weighted_cost=1.0,
        reasoning_tokens=0,
        reasoning_expected=None,
    )
    return clean.model_copy(update=changes)
