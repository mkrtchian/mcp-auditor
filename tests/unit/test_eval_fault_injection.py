"""The gate fed faulted candidates built from the recording refused on 2026-09-27.

These tests pin what the gate does with each fault on floors at 0.50, misses included. The
recording's own recall, 0.46, already sits under the recall floor, so every fault that does
not raise recall is red on it whatever else the gate sees.
"""

from dataclasses import dataclass

import pytest
from pydantic import BaseModel

import tests.unit.support.test_eval_fault_injection_given as given
import tests.unit.support.test_eval_fault_injection_then as then
from evals.baseline import Baseline
from evals.fault_injection import (
    CategoryDroppingGenerator,
    ChainRefusingModel,
    FailingJudge,
    PassingJudge,
    RandomJudge,
    SilentJudge,
    lose_detections,
)
from evals.gate import Cell, CellComparison, CellOutcome, FlipCause, compare, settle
from evals.gate_verdict import GateInput, GateMode, GateResult, judge_gate
from evals.honeypots import MERGED_GROUND_TRUTH, audit_honeypots
from evals.recording import Recording, RecordingRefused, decide_recording
from evals.run_fault_injection import fixture_refusals
from mcp_auditor.domain.models import (
    AuditCategory,
    AuditPayload,
    ChainPlanBatch,
    EvalVerdict,
    Judgment,
    StepObservation,
    TestCaseBatch,
)
from mcp_auditor.domain.ports import LLMPort, ProviderRefusal
from tests.fakes.llm import FakeLLM

INJECTION = AuditCategory.INJECTION
INFO_LEAKAGE = AuditCategory.INFO_LEAKAGE


def test_a_judge_passing_everything_is_caught_by_the_recall_floor_and_the_regressions():
    run = _through_the_gate(given.a_judge_passing_everything(), given.REPRODUCING)

    then.flipped(run.cells, given.STABLE_CORRECT_FAILS, FlipCause.WRONG_VERDICT)
    then.red_on(
        run.paired,
        "recall 0.00 under its floor 0.50",
        "regression on get_user/error_handling",
        "regression on execute_query/info_leakage",
        "regression on delete_record/input_validation",
    )
    then.red_on(run.floors_only, "recall 0.00 under its floor 0.50")
    then.refused_on(run.recording, "recall")


def test_a_judge_failing_everything_is_caught_by_the_precision_floor_and_the_regressions():
    run = _through_the_gate(given.a_judge_failing_everything(), given.REPRODUCING)

    then.flipped(run.cells, given.EXPECTED_PASSES, FlipCause.WRONG_VERDICT)
    then.settled_as(run.paired, given.EXPECTED_PASSES, CellOutcome.REGRESSION)
    assert run.paired.reasons[0] == "precision 0.22 under its floor 0.50"
    then.red_on(run.floors_only, "precision 0.22 under its floor 0.50")
    then.refused_on(run.recording, "precision")


def test_a_judge_failing_at_random_seed_0_is_caught_by_the_floors_but_its_flips_do_not_reproduce():
    run = _through_the_gate(given.a_judge_failing_at_random(seed=0), given.REPRODUCING_TWICE)

    flips = [
        cell for cell in given.STABLE_CORRECT_CELLS if cell not in given.SPARED_BY_THE_RANDOM_JUDGE
    ]
    then.flipped(run.cells, flips, FlipCause.WRONG_VERDICT)
    then.settled_as(run.paired, flips, CellOutcome.FLIP_NOT_REPRODUCED)
    floors = ("recall 0.38 under its floor 0.50", "precision 0.19 under its floor 0.50")
    then.red_on(run.paired, *floors)
    then.red_on(run.floors_only, *floors)
    then.refused_on(run.recording, "recall", "precision")


def test_no_verdict_flips_every_stable_and_correct_cell_as_uncovered():
    run = _through_the_gate(given.no_verdict(), given.REPRODUCING)

    then.flipped(run.cells, given.STABLE_CORRECT_CELLS, FlipCause.UNCOVERED)
    floors = (
        "recall 0.00 under its floor 0.50",
        "distribution_coverage 0.00 under its floor 0.50",
    )
    assert run.paired.reasons[:2] == list(floors)
    then.settled_as(run.paired, given.STABLE_CORRECT_CELLS, CellOutcome.REGRESSION)
    then.red_on(run.floors_only, *floors)
    then.refused_on(run.recording, "recall", "distribution_coverage")


@pytest.mark.parametrize(
    "replays", [given.REPRODUCING_TWICE, given.REPRODUCING_THREE_TIMES], ids=["2_of_5", "3_of_5"]
)
def test_half_the_detections_lost_is_missed_by_the_paired_comparison(replays: list[bool]):
    run = _through_the_gate(given.half_the_detections_lost(seed=0), replays)

    then.flipped(run.cells, given.LOST_BY_THE_HALF_LOSS_DRAW, FlipCause.WRONG_VERDICT)
    then.settled_as(run.paired, given.LOST_BY_THE_HALF_LOSS_DRAW, CellOutcome.FLIP_NOT_REPRODUCED)
    then.red_on(run.paired, "recall 0.29 under its floor 0.50")
    then.red_on(run.floors_only, "recall 0.29 under its floor 0.50")
    then.refused_on(run.recording, "recall")


@pytest.mark.parametrize("category", list(AuditCategory))
def test_a_dropped_category_flips_its_stable_and_correct_cells_and_clears_the_coverage_floor(
    category: AuditCategory,
):
    run = _through_the_gate(given.a_generator_dropping(category), given.REPRODUCING)

    dropped = [cell for cell in given.STABLE_CORRECT_CELLS if cell[1] == category]
    then.flipped(run.cells, dropped, FlipCause.UNCOVERED)
    then.settled_as(run.paired, dropped, CellOutcome.REGRESSION)
    assert "distribution_coverage" not in run.floors_only.floor_breaches


def test_chain_steps_refused_move_no_cell_on_the_chain_only_flaws_and_the_recall_floor_fires():
    run = _through_the_gate(given.chain_steps_refused(), given.REPRODUCING)

    assert run.cells[given.CHAIN_ONLY_FLAWS[0]].outcome == CellOutcome.INCONCLUSIVE
    assert run.cells[given.CHAIN_ONLY_FLAWS[1]].outcome == CellOutcome.UNCHANGED
    then.flipped(run.cells, [], FlipCause.WRONG_VERDICT)
    then.red_on(run.paired, "recall 0.42 under its floor 0.50")
    then.red_on(run.floors_only, "recall 0.42 under its floor 0.50")
    then.refused_on(run.recording, "recall")


def test_losing_detections_turns_fail_cells_pass_and_nothing_else():
    verdicts = given.many_detections_and_a_pass_and_an_uncovered_cell()

    degraded = lose_detections(verdicts, seed=0, audit_index=0)

    then.only_detections_lost(verdicts, degraded)


def test_losing_detections_draws_the_same_loss_for_the_same_seed_and_audit():
    verdicts = given.many_detections_and_a_pass_and_an_uncovered_cell()

    assert lose_detections(verdicts, seed=0, audit_index=3) == lose_detections(
        verdicts, seed=0, audit_index=3
    )


def test_losing_detections_draws_afresh_at_each_audit():
    verdicts = given.many_detections_and_a_pass_and_an_uncovered_cell()

    assert lose_detections(verdicts, seed=0, audit_index=0) != lose_detections(
        verdicts, seed=0, audit_index=1
    )


@pytest.mark.parametrize(
    ("judge", "verdict"), [(PassingJudge(), EvalVerdict.PASS), (FailingJudge(), EvalVerdict.FAIL)]
)
async def test_a_fixed_judge_returns_its_verdict(judge: LLMPort, verdict: EvalVerdict):
    judgment, _ = await judge.generate_structured("a prompt", Judgment)

    assert judgment.verdict == verdict


async def test_a_random_judge_draws_both_verdicts_the_same_way_for_the_same_seed():
    first = await given.verdicts_of(RandomJudge(seed=0), calls=20)
    second = await given.verdicts_of(RandomJudge(seed=0), calls=20)

    assert first == second
    assert set(first) == {EvalVerdict.PASS, EvalVerdict.FAIL}


async def test_a_silent_judge_refuses_every_judgment():
    with pytest.raises(ProviderRefusal):
        await SilentJudge().generate_structured("a prompt", Judgment)


@pytest.mark.parametrize("judge", [PassingJudge(), FailingJudge(), RandomJudge(seed=0)])
async def test_a_faulty_judge_answers_judgments_only(judge: LLMPort):
    with pytest.raises(TypeError):
        await judge.generate_structured("a prompt", TestCaseBatch)


async def test_a_generator_dropping_a_category_leaves_it_out_of_the_test_cases():
    inner = FakeLLM([given.a_test_case_batch(INJECTION, INFO_LEAKAGE, INJECTION)])

    batch, _ = await CategoryDroppingGenerator(inner, INJECTION).generate_structured(
        "a prompt", TestCaseBatch
    )

    assert [case.category for case in batch.cases] == [INFO_LEAKAGE]


async def test_a_generator_dropping_a_category_leaves_it_out_of_the_chain_goals():
    inner = FakeLLM([given.a_chain_plan(INFO_LEAKAGE, INJECTION)])

    plan, _ = await CategoryDroppingGenerator(inner, INFO_LEAKAGE).generate_structured(
        "a prompt", ChainPlanBatch
    )

    assert [goal.category for goal in plan.chains] == [INJECTION]


async def test_a_generator_dropping_a_category_passes_other_answers_through():
    observation = given.a_step_observation()
    inner = FakeLLM([observation])

    answer, _ = await CategoryDroppingGenerator(inner, INJECTION).generate_structured(
        "a prompt", StepObservation
    )

    assert answer == observation


@pytest.mark.parametrize("schema", [ChainPlanBatch, StepObservation, AuditPayload])
async def test_a_model_refusing_chains_refuses_every_chain_step(schema: type[BaseModel]):
    model = ChainRefusingModel(FakeLLM([]))

    with pytest.raises(ProviderRefusal):
        await model.generate_structured("a prompt", schema)


async def test_a_model_refusing_chains_still_generates_test_cases():
    batch = given.a_test_case_batch(INJECTION)

    answer, _ = await ChainRefusingModel(FakeLLM([batch])).generate_structured(
        "a prompt", TestCaseBatch
    )

    assert answer == batch


async def test_auditing_the_honeypots_merges_their_reports():
    reports = given.a_report_per_honeypot()

    verdicts, merged = await audit_honeypots(reports.audit)

    then.merged(verdicts, merged, list(reports.by_honeypot.values()))


def test_the_harness_accepts_the_fixture_at_the_current_conditions():
    fixture = given.the_fault_injection_baseline()

    assert fixture_refusals(fixture, given.the_current_conditions()) == []


def test_the_harness_refuses_a_fixture_recorded_at_other_conditions():
    fixture = given.the_fault_injection_baseline()

    reasons = fixture_refusals(fixture, given.the_current_conditions_at_budget(7))

    assert len(reasons) == 1
    assert "budget: baseline 10, candidate 7" in reasons[0]


def test_the_harness_refuses_a_fixture_whose_runs_miss_a_cell():
    fixture = given.the_fixture_missing(given.CHAIN_ONLY_FLAWS[0])

    reasons = fixture_refusals(fixture, given.the_current_conditions())

    assert reasons == [
        f"run {index}: cells ['project_manager/info_leakage'] missing" for index in range(3)
    ]


@dataclass(frozen=True)
class _GateRun:
    cells: dict[Cell, CellComparison]
    paired: GateResult
    floors_only: GateResult
    recording: Baseline | RecordingRefused


def _through_the_gate(candidate: given.FaultedCandidate, replays: list[bool]) -> _GateRun:
    """Every flip settles on the same scripted replays: the fault stays active in them."""
    baseline = given.the_fault_injection_baseline()
    metrics = given.metrics_of(candidate)
    cells = compare(baseline.observation_runs(), candidate.runs, MERGED_GROUND_TRUTH)
    settled = {
        cell: settle(comparison, replays, baseline.replay_rule)
        if comparison.outcome == CellOutcome.FLIP
        else comparison
        for cell, comparison in cells.items()
    }
    paired = judge_gate(
        GateInput(
            mode=GateMode.PAIRED,
            metrics=metrics,
            baseline_status=baseline.status,
            cells=settled,
        )
    )
    floors_only = judge_gate(GateInput(mode=GateMode.FLOORS_ONLY, metrics=metrics, cells=cells))
    recording = Recording(
        conditions=baseline.conditions,
        commit=baseline.commit,
        recorded_at=baseline.recorded_at,
        runs=candidate.runs,
        metrics=metrics,
        completed_all=True,
    )
    return _GateRun(cells, paired, floors_only, decide_recording(None, recording, floors_only))
