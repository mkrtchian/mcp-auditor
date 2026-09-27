from evals.baseline import Baseline, load_baseline
from evals.fault_catalog import FAULTS, GREEN, Expectation, Fault
from evals.fault_harness import FIXTURE_PATH, FaultResult, Harness, fixture_refusals
from evals.honeypots import AuditModels
from tests.fakes.fixture_judge import FixtureJudge
from tests.fakes.scripted_audit_model import ScriptedAuditModel

BUDGET = 5  # One case per category: a full batch holds the budget, so no retry in the healthy run.
HEALTHY = Fault("healthy", Expectation(GREEN, GREEN, False, ()))


def the_fixture() -> Baseline:
    fixture = load_baseline(FIXTURE_PATH)
    assert fixture is not None, f"no fixture at {FIXTURE_PATH}"
    return fixture


def fault_named(name: str) -> Fault:
    return next(fault for fault in FAULTS if fault.name == name)


async def injected(scenario: Fault, fixture: Baseline) -> FaultResult:
    assert fixture_refusals(fixture) == []
    return await a_harness(fixture).inject(scenario)


def a_harness(fixture: Baseline) -> Harness:
    """Each scenario gets its own harness: the fakes count judgments per cell, so a shared one
    would read the fixture's runs out of step."""
    models = AuditModels(llm=ScriptedAuditModel(), judge_llm=FixtureJudge(fixture))
    return Harness(fixture, models, BUDGET)
