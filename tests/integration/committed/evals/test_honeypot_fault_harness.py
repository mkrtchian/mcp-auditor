import tests.unit.evals.support.test_honeypot_fault_harness_given as given
from evals.honeypot.fault_harness import fixture_refusals


def test_the_harness_accepts_the_fixture():
    fixture = given.the_fault_injection_baseline()

    assert fixture_refusals(fixture) == []
