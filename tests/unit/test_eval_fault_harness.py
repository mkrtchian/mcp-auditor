"""The faults the harness plants, and its deterministic parts."""

import pytest
from pydantic import BaseModel

import tests.unit.support.test_eval_fault_harness_given as given
import tests.unit.support.test_eval_fault_harness_then as then
from evals.fault_harness import fixture_refusals
from evals.fault_injection import (
    CategoryDroppingGenerator,
    ChainRefusingModel,
    FailingJudge,
    PassingJudge,
    RandomJudge,
    SilentJudge,
    lose_detections,
)
from evals.honeypots import audit_honeypots
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


def test_the_harness_accepts_the_fixture():
    fixture = given.the_fault_injection_baseline()

    assert fixture_refusals(fixture) == []


def test_the_harness_refuses_a_fixture_whose_runs_miss_a_cell():
    fixture = given.the_fixture_missing(given.CHAIN_ONLY_FLAWS[0])

    reasons = fixture_refusals(fixture)

    assert reasons == [
        f"run {index}: cells ['project_manager/info_leakage'] missing" for index in range(3)
    ]
