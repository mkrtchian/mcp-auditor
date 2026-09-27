"""Faulted candidates built from the observations of the recording refused on 2026-09-27.

A candidate holds observations, not cases, so its distribution coverage cannot be computed
from it: each fault states the coverage its generator would give (`compute_distribution_coverage`
counts the categories among a tool's judged cases, chains excluded).
"""

import random
from dataclasses import dataclass

from evals.baseline import Baseline, BaselineConditions, load_baseline
from evals.eval_session import DEFAULT_BUDGET, DEFAULT_RUNS, EvalOptions, candidate_conditions
from evals.gate import Cell, Observation, cell_key
from evals.honeypots import MERGED_GROUND_TRUTH, REPO_ROOT, HoneypotConfig
from evals.metrics import EvalMetrics, VerdictMap, compute_consistency, label_scores
from mcp_auditor.config import Settings
from mcp_auditor.domain.models import (
    AuditCategory,
    AuditPayload,
    AuditReport,
    AuditStep,
    ChainGoal,
    ChainPlanBatch,
    EvalResult,
    EvalVerdict,
    Judgment,
    RefusedStep,
    Severity,
    StepObservation,
    TestCase,
    TestCaseBatch,
    TokenUsage,
    ToolDefinition,
    ToolReport,
)
from mcp_auditor.domain.ports import LLMPort

FIXTURE_PATH = REPO_ROOT / "evals" / "fixtures" / "fault_injection_baseline.json"

# The chain honeypot plants its info_leakage flaws as three-step chains (its docstring and
# the comments on each step): a single-step case covers these cells but cannot reach the flaw.
# Every other cell of that server is covered by single-step cases in every recorded run.
CHAIN_ONLY_FLAWS: list[Cell] = [
    ("project_manager", AuditCategory.INFO_LEAKAGE),
    ("user_directory", AuditCategory.INFO_LEAKAGE),
]

STABLE_CORRECT_FAILS: list[Cell] = [
    ("get_user", AuditCategory.ERROR_HANDLING),
    ("execute_query", AuditCategory.INFO_LEAKAGE),
    ("delete_record", AuditCategory.INPUT_VALIDATION),
]
# Every PASS cell is stable and correct in the recording.
EXPECTED_PASSES: list[Cell] = [
    cell for cell, verdict in MERGED_GROUND_TRUTH.items() if verdict == EvalVerdict.PASS
]
STABLE_CORRECT_CELLS = STABLE_CORRECT_FAILS + EXPECTED_PASSES

# The stable and correct cells that the random judge of seed 0 leaves correct in every run.
SPARED_BY_THE_RANDOM_JUDGE: list[Cell] = [
    ("execute_query", AuditCategory.RESOURCE_ABUSE),
    ("list_items", AuditCategory.INPUT_VALIDATION),
    ("list_items", AuditCategory.ERROR_HANDLING),
    ("search_users", AuditCategory.RESOURCE_ABUSE),
    ("delete_record", AuditCategory.INJECTION),
    ("project_manager", AuditCategory.RESOURCE_ABUSE),
]

# The stable and correct FAIL cells whose detection the half-loss draw of seed 0 loses in a run.
LOST_BY_THE_HALF_LOSS_DRAW: list[Cell] = [
    ("get_user", AuditCategory.ERROR_HANDLING),
    ("delete_record", AuditCategory.INPUT_VALIDATION),
]

# Replays under the rule of 4 reproductions out of at most 5, stopping early.
REPRODUCING = [True, True, True, True]
REPRODUCING_TWICE = [True, False, True, False, False]
REPRODUCING_THREE_TIMES = [True, True, False, True, False]

ObservationRuns = list[dict[Cell, Observation]]


@dataclass(frozen=True)
class FaultedCandidate:
    runs: ObservationRuns
    distribution_coverage: float


def the_fault_injection_baseline() -> Baseline:
    baseline = load_baseline(FIXTURE_PATH)
    assert baseline is not None
    return baseline


def a_judge_passing_everything() -> FaultedCandidate:
    return _every_cell_observed(Observation.PASS, distribution_coverage=1.0)


def a_judge_failing_everything() -> FaultedCandidate:
    return _every_cell_observed(Observation.FAIL, distribution_coverage=1.0)


def no_verdict() -> FaultedCandidate:
    return _every_cell_observed(Observation.UNCOVERED, distribution_coverage=0.0)


def a_judge_failing_at_random(seed: int) -> FaultedCandidate:
    runs = [
        {cell: Observation.FAIL if _coin(seed, index, cell) else Observation.PASS for cell in run}
        for index, run in enumerate(_recorded_runs())
    ]
    return FaultedCandidate(runs=runs, distribution_coverage=1.0)


def half_the_detections_lost(seed: int) -> FaultedCandidate:
    runs = [
        {
            cell: Observation.PASS
            if seen == Observation.FAIL and _coin(seed, index, cell)
            else seen
            for cell, seen in run.items()
        }
        for index, run in enumerate(_recorded_runs())
    ]
    return FaultedCandidate(runs=runs, distribution_coverage=1.0)


def a_generator_dropping(category: AuditCategory) -> FaultedCandidate:
    """Four categories of five per tool are left, so coverage reads 0.80."""
    runs = [
        {cell: Observation.UNCOVERED if cell[1] == category else seen for cell, seen in run.items()}
        for run in _recorded_runs()
    ]
    return FaultedCandidate(runs=runs, distribution_coverage=0.8)


def chain_steps_refused() -> FaultedCandidate:
    """The cells of `CHAIN_ONLY_FLAWS` keep only single-step verdicts, which pass."""
    runs = [
        {cell: Observation.PASS if cell in CHAIN_ONLY_FLAWS else seen for cell, seen in run.items()}
        for run in _recorded_runs()
    ]
    return FaultedCandidate(runs=runs, distribution_coverage=1.0)


def metrics_of(candidate: FaultedCandidate) -> EvalMetrics:
    """Recall and precision from the observations, as `rescore` computes them."""
    verdict_maps: list[VerdictMap] = [
        {
            cell: None if seen == Observation.UNCOVERED else EvalVerdict(seen.value)
            for cell, seen in run.items()
        }
        for run in candidate.runs
    ]
    consistency, _ = compute_consistency(verdict_maps, MERGED_GROUND_TRUTH)
    return EvalMetrics(
        **label_scores(verdict_maps, MERGED_GROUND_TRUTH),
        consistency=consistency,
        distribution_coverage=candidate.distribution_coverage,
    )


def _every_cell_observed(seen: Observation, distribution_coverage: float) -> FaultedCandidate:
    runs = [{cell: seen for cell in run} for run in _recorded_runs()]
    return FaultedCandidate(runs=runs, distribution_coverage=distribution_coverage)


def _recorded_runs() -> ObservationRuns:
    return the_fault_injection_baseline().observation_runs()


def _coin(seed: int, run_index: int, cell: Cell) -> bool:
    return random.Random(f"{seed}/{run_index}/{cell_key(cell)}").random() < 0.5


# The harness's deterministic parts.

HARNESS_CONDITIONS_OPTIONS = EvalOptions(
    runs=DEFAULT_RUNS, budget=DEFAULT_BUDGET, report="", record_baseline=False, ungated=False
)


def the_current_conditions() -> BaselineConditions:
    """The conditions CI runs at, which the fixture was recorded at."""
    return candidate_conditions(Settings.model_construct(), HARNESS_CONDITIONS_OPTIONS)


def the_current_conditions_at_budget(budget: int) -> BaselineConditions:
    return the_current_conditions().model_copy(update={"budget": budget})


def the_fixture_missing(cell: Cell) -> Baseline:
    fixture = the_fault_injection_baseline()
    runs = [
        {key: seen for key, seen in run.items() if key != cell_key(cell)} for run in fixture.runs
    ]
    return fixture.model_copy(update={"runs": runs})


def many_detections_and_a_pass_and_an_uncovered_cell() -> VerdictMap:
    detections: VerdictMap = {
        (f"tool_{index}", category): EvalVerdict.FAIL
        for index in range(20)
        for category in AuditCategory
    }
    return {
        **detections,
        ("passing_tool", AuditCategory.INJECTION): EvalVerdict.PASS,
        ("uncovered_tool", AuditCategory.INJECTION): None,
    }


def a_test_case_batch(*categories: AuditCategory) -> TestCaseBatch:
    return TestCaseBatch(cases=[_a_payload(category) for category in categories])


def a_chain_plan(*categories: AuditCategory) -> ChainPlanBatch:
    return ChainPlanBatch(
        chains=[
            ChainGoal(description="a goal", category=category, first_step=_a_payload(category))
            for category in categories
        ]
    )


def a_step_observation() -> StepObservation:
    return StepObservation(observation="nothing", should_continue=False)


def a_payload() -> AuditPayload:
    return _a_payload(AuditCategory.INJECTION)


def _a_payload(category: AuditCategory) -> AuditPayload:
    return AuditPayload(category=category, description="a case", arguments={})


@dataclass(frozen=True)
class HoneypotReports:
    """One fixed report per honeypot, as the audit of each would return it."""

    by_honeypot: dict[str, AuditReport]

    async def audit(self, honeypot: HoneypotConfig) -> AuditReport:
        return self.by_honeypot[honeypot.name]


def a_report_per_honeypot() -> HoneypotReports:
    return HoneypotReports(
        {
            "honeypot": _a_report(
                "get_user", EvalVerdict.FAIL, TokenUsage(input_tokens=100, output_tokens=10)
            ).model_copy(update={"refused_steps": [_a_refused_step("get_user")]}),
            "subtle": _a_report(
                "list_items", EvalVerdict.PASS, TokenUsage(input_tokens=200, output_tokens=20)
            ),
            "chain_honeypot": _a_report(
                "project_manager", EvalVerdict.FAIL, TokenUsage(input_tokens=300, output_tokens=30)
            ),
        }
    )


def _a_report(tool: str, verdict: EvalVerdict, usage: TokenUsage) -> AuditReport:
    result = EvalResult(
        tool_name=tool,
        category=AuditCategory.INFO_LEAKAGE,
        payload={},
        verdict=verdict,
        justification="judged",
        severity=Severity.LOW,
    )
    tool_report = ToolReport(
        tool=ToolDefinition(name=tool, input_schema={"type": "object"}),
        cases=[TestCase(payload=_a_payload(AuditCategory.INFO_LEAKAGE), eval_result=result)],
    )
    return AuditReport(target=tool, tool_reports=[tool_report], token_usage=usage)


def _a_refused_step(tool: str) -> RefusedStep:
    return RefusedStep(tool_name=tool, step=AuditStep.JUDGMENT, provider_message="refused")


async def verdicts_of(judge: LLMPort, calls: int) -> list[EvalVerdict]:
    return [
        (await judge.generate_structured("a prompt", Judgment))[0].verdict for _ in range(calls)
    ]
