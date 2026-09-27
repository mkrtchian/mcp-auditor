"""A fault planted in the models reaches the eval gate through a real audit of the three
honeypots, with fakes in place of the LLM. See `evals/fault_injection_method.md`."""

import pytest
import pytest_asyncio

import tests.integration.support.test_gate_fault_injection_given as given
import tests.integration.support.test_gate_fault_injection_then as then
from evals.fault_catalog import FAULTS, Fault
from evals.fault_harness import FaultResult, fixture_refusals

pytestmark = pytest.mark.asyncio(loop_scope="module")

FIXTURE = given.the_fixture()
FAULTS_WITH_EXPECTATION = [fault for fault in FAULTS if fault.expectation is not None]


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def results() -> dict[str, FaultResult]:
    assert fixture_refusals(FIXTURE) == []
    return await given.every_scenario_injected(FIXTURE)


async def test_the_healthy_audit_reproduces_the_fixture(results: dict[str, FaultResult]):
    healthy = results[given.HEALTHY.name]
    assert given.HEALTHY.expectation is not None
    then.expectation_met(healthy, given.HEALTHY.expectation)
    then.the_fixture_reproduced(healthy, FIXTURE)


@pytest.mark.parametrize("fault", FAULTS_WITH_EXPECTATION, ids=lambda fault: fault.name)
async def test_the_gate_answers_each_fault(fault: Fault, results: dict[str, FaultResult]):
    assert fault.expectation is not None
    then.expectation_met(results[fault.name], fault.expectation)


async def test_a_random_judge_flips_pass_cells(results: dict[str, FaultResult]):
    then.some_pass_cells_flipped(results["judge_fails_at_random"])


async def test_losing_half_the_detections_obeys_the_gate_rules(results: dict[str, FaultResult]):
    then.the_half_loss_obeys_the_rules(results["half_the_detections_lost"], FIXTURE)
