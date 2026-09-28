"""A fault planted in the models reaches the eval gate through a real audit of the three
honeypots, with fakes in place of the LLM. See `evals/fault_injection_method.md`."""

import pytest

import tests.integration.support.test_gate_fault_injection_given as given
import tests.integration.support.test_gate_fault_injection_then as then
from evals.fault_catalog import FAULTS, Fault
from mcp_auditor.domain.models import AuditCategory

FIXTURE = given.the_fixture()
RANDOM_JUDGE = "judge_fails_at_random"
HALF_LOSS = "half_the_detections_lost"
DECLARED_DROP = "generator_drops_error_handling_declared"
PINNED_FAULTS = [f for f in FAULTS if f.expectation is not None and f.name != RANDOM_JUDGE]


async def test_the_healthy_audit_reproduces_the_fixture():
    healthy = await given.injected(given.HEALTHY, FIXTURE)
    assert given.HEALTHY.expectation is not None
    then.expectation_met(healthy, given.HEALTHY.expectation)
    then.the_fixture_reproduced(healthy, FIXTURE)


@pytest.mark.parametrize("fault", PINNED_FAULTS, ids=lambda fault: fault.name)
async def test_the_gate_answers_each_fault(fault: Fault):
    assert fault.expectation is not None
    then.expectation_met(await given.injected(fault, FIXTURE), fault.expectation)


async def test_a_random_judge_breaks_precision_and_flips_pass_cells():
    fault = given.fault_named(RANDOM_JUDGE)
    result = await given.injected(fault, FIXTURE)
    assert fault.expectation is not None
    then.expectation_met(result, fault.expectation)
    then.some_pass_cells_flipped(result)


async def test_losing_half_the_detections_obeys_the_gate_rules():
    result = await given.injected(given.fault_named(HALF_LOSS), FIXTURE)
    then.the_half_loss_obeys_the_rules(result, FIXTURE)


async def test_a_declaration_clears_exactly_the_dropped_category():
    result = await given.injected(given.fault_named(DECLARED_DROP), FIXTURE)
    then.only_the_declared_category_flipped(result, FIXTURE, AuditCategory.ERROR_HANDLING)
