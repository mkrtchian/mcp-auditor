import asyncio

from evals.baseline import Baseline, load_baseline
from evals.fault_catalog import FAULTS, GREEN, Expectation, Fault
from evals.fault_harness import FIXTURE_PATH, FaultResult, Harness
from evals.honeypots import AuditModels
from tests.fakes.fixture_judge import FixtureJudge
from tests.fakes.scripted_audit_model import ScriptedAuditModel

BUDGET = 5  # One case per category: a full batch holds the budget, so no retry in the healthy run.
HEALTHY = Fault("healthy", Expectation(GREEN, GREEN, False, ()))


def the_fixture() -> Baseline:
    fixture = load_baseline(FIXTURE_PATH)
    assert fixture is not None, f"no fixture at {FIXTURE_PATH}"
    return fixture


async def every_scenario_injected(fixture: Baseline) -> dict[str, FaultResult]:
    """Each scenario gets its own harness: the fakes count judgments per cell, so a shared one
    would read the fixture's runs out of step."""
    scenarios = [HEALTHY, *FAULTS]
    results = await asyncio.gather(*(a_harness(fixture).inject(scenario) for scenario in scenarios))
    return {result.fault: result for result in results}


def a_harness(fixture: Baseline) -> Harness:
    models = AuditModels(llm=ScriptedAuditModel(), judge_llm=FixtureJudge(fixture))
    return Harness(fixture, models, BUDGET)
