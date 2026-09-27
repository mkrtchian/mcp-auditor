"""The fakes that stand for the generator and the judge in the fault injection test."""

import pytest
from pydantic import BaseModel

import tests.unit.support.test_eval_fault_fakes_given as given
from mcp_auditor.domain.models import (
    AttackContext,
    AuditCategory,
    AuditPayload,
    ChainPlanBatch,
    EvalVerdict,
    Judgment,
    StepObservation,
    TestCaseBatch,
)
from mcp_auditor.domain.ports import ProviderRefusal
from tests.fakes.fixture_judge import FixtureJudge
from tests.fakes.scripted_audit_model import ScriptedAuditModel

PASS = EvalVerdict.PASS
FAIL = EvalVerdict.FAIL


async def test_the_scripted_model_writes_one_case_per_category_of_the_attack_prompt():
    prompt = given.an_attack_prompt(list(AuditCategory))

    batch, _ = await ScriptedAuditModel().generate_structured(prompt, TestCaseBatch)

    assert [case.category for case in batch.cases] == list(AuditCategory)


async def test_the_scripted_model_writes_only_the_categories_a_completion_asks_for():
    missing = [AuditCategory.INJECTION, AuditCategory.RESOURCE_ABUSE]

    batch, _ = await ScriptedAuditModel().generate_structured(
        given.an_attack_prompt(missing), TestCaseBatch
    )

    assert [case.category for case in batch.cases] == missing


async def test_the_scripted_model_refuses_a_batch_prompt_without_a_category_list():
    with pytest.raises(ValueError, match="a reworded prompt"):
        await ScriptedAuditModel().generate_structured("a reworded prompt", TestCaseBatch)


async def test_the_scripted_model_gathers_no_attack_context():
    context, _ = await ScriptedAuditModel().generate_structured("a prompt", AttackContext)

    assert context.is_empty


async def test_the_scripted_model_plans_one_info_leakage_chain():
    plan, _ = await ScriptedAuditModel().generate_structured("a prompt", ChainPlanBatch)

    assert [goal.category for goal in plan.chains] == [AuditCategory.INFO_LEAKAGE]
    assert plan.chains[0].first_step.arguments == {}


async def test_the_scripted_model_stops_each_chain_after_its_first_step():
    observation, _ = await ScriptedAuditModel().generate_structured("a prompt", StepObservation)

    assert not observation.should_continue


async def test_the_scripted_model_plans_an_empty_info_leakage_step():
    payload, _ = await ScriptedAuditModel().generate_structured("a prompt", AuditPayload)

    assert payload.category == AuditCategory.INFO_LEAKAGE
    assert payload.arguments == {}


async def test_the_scripted_model_refuses_an_unknown_schema():
    class Unknown(BaseModel):
        pass

    with pytest.raises(TypeError):
        await ScriptedAuditModel().generate_structured("a prompt", Unknown)


async def test_the_fixture_judge_follows_the_runs_of_a_single_step_cell_and_wraps():
    prompt = given.a_single_step_judge_prompt(given.A_CELL_FAILED_IN_THE_FIRST_RUN_ONLY)

    verdicts = await given.verdicts_of(FixtureJudge(given.the_fixture()), prompt, calls=4)

    assert verdicts == [FAIL, PASS, PASS, FAIL]


async def test_the_fixture_judge_follows_the_runs_of_a_chain_only_cell_on_chain_prompts():
    prompt = given.a_chain_judge_prompt(given.A_CHAIN_ONLY_CELL_FAILED_IN_THE_SECOND_RUN_ONLY)

    verdicts = await given.verdicts_of(FixtureJudge(given.the_fixture()), prompt, calls=4)

    assert verdicts == [PASS, FAIL, PASS, PASS]


async def test_the_fixture_judge_passes_a_chain_only_cell_on_single_step_prompts():
    judge = FixtureJudge(given.the_fixture())
    cell = given.A_CHAIN_ONLY_CELL_FAILED_IN_THE_SECOND_RUN_ONLY

    single_step = await given.verdicts_of(judge, given.a_single_step_judge_prompt(cell), calls=3)
    chain = await given.verdicts_of(judge, given.a_chain_judge_prompt(cell), calls=2)

    assert single_step == [PASS, PASS, PASS]
    assert chain == [PASS, FAIL]


async def test_the_fixture_judge_counts_single_step_and_chain_judgments_apart():
    judge = FixtureJudge(given.the_fixture())
    cell = given.A_CELL_FAILED_IN_THE_FIRST_RUN_ONLY

    single_step = await given.verdicts_of(judge, given.a_single_step_judge_prompt(cell), calls=1)
    chain = await given.verdicts_of(judge, given.a_chain_judge_prompt(cell), calls=1)

    assert single_step == [FAIL]
    assert chain == [FAIL]


async def test_the_fixture_judge_passes_a_cell_outside_the_ground_truth():
    prompt = given.a_single_step_judge_prompt(given.A_CELL_OUTSIDE_THE_GROUND_TRUTH)

    verdicts = await given.verdicts_of(FixtureJudge(given.the_fixture()), prompt, calls=3)

    assert verdicts == [PASS, PASS, PASS]


async def test_the_fixture_judge_refuses_an_uncovered_observation():
    cell = given.A_CELL_FAILED_IN_THE_FIRST_RUN_ONLY
    judge = FixtureJudge(given.the_fixture_with_uncovered(cell))

    with pytest.raises(ProviderRefusal):
        await judge.generate_structured(given.a_single_step_judge_prompt(cell), Judgment)


async def test_the_fixture_judge_refuses_a_cell_the_fixture_did_not_record():
    cell = given.A_CELL_FAILED_IN_THE_FIRST_RUN_ONLY
    judge = FixtureJudge(given.the_fixture_without(cell))

    with pytest.raises(ProviderRefusal):
        await judge.generate_structured(given.a_single_step_judge_prompt(cell), Judgment)


async def test_the_fixture_judge_refuses_a_prompt_it_cannot_read():
    judge = FixtureJudge(given.the_fixture())

    with pytest.raises(ValueError, match="a reworded prompt"):
        await judge.generate_structured("a reworded prompt", Judgment)
