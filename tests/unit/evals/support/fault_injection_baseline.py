from evals.baseline import Baseline, load_baseline
from evals.honeypot.fault_harness import FIXTURE_PATH


def the_fault_injection_baseline() -> Baseline:
    baseline = load_baseline(FIXTURE_PATH)
    assert baseline is not None, f"no fixture at {FIXTURE_PATH}"
    return baseline
