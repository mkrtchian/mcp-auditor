from evals.baseline import Baseline
from evals.honeypot.fault_catalog import FAULTS, GREEN, Expectation, Fault
from evals.honeypot.fault_harness import FaultResult, Harness, fixture_refusals
from evals.honeypots import AuditModels
from tests.fakes.fixture_judge import FixtureJudge
from tests.fakes.scripted_audit_model import ScriptedAuditModel

# One case per category: a full batch holds the budget, so no retry in the healthy run.
TEST_BUDGET = 5
HEALTHY = Fault("healthy", Expectation(GREEN, GREEN, False, ()))


def fault_named(name: str) -> Fault:
    return next(fault for fault in FAULTS if fault.name == name)


async def injected(scenario: Fault, fixture: Baseline) -> FaultResult:
    assert fixture_refusals(fixture) == []
    return await a_harness(fixture).inject(scenario)


def a_harness(fixture: Baseline) -> Harness:
    """Each scenario gets its own harness: the fakes count judgments per cell, so a shared one
    would read the fixture's runs out of step."""
    models = AuditModels(llm=ScriptedAuditModel(), judge_llm=FixtureJudge(fixture))
    return Harness(fixture, models, TEST_BUDGET)
