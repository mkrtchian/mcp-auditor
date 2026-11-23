import tests.integration.committed.evals.support.test_fault_injection_fixture_given as given
from evals.honeypot.fault_harness import fixture_refusals
from tests.fakes.fixture_judge import CHAIN_ONLY_FLAWS
from tests.unit.evals.support.fault_injection_baseline import the_fault_injection_baseline


def test_the_harness_accepts_the_fixture():
    fixture = the_fault_injection_baseline()

    assert fixture_refusals(fixture) == []


def test_the_harness_refuses_a_fixture_whose_runs_miss_a_cell():
    fixture = given.the_fixture_missing(CHAIN_ONLY_FLAWS[0])

    reasons = fixture_refusals(fixture)

    assert reasons == [
        f"run {index}: cells ['project_manager/info_leakage'] missing" for index in range(3)
    ]
