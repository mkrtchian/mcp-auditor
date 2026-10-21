from evals.cve_gate import CVEGateVerdict, TargetComparison, TargetOutcome
from evals.cve_session import CVESessionResult


def the_one_target_ends(
    result: CVESessionResult, outcome: TargetOutcome, verdict: CVEGateVerdict | None = None
) -> TargetComparison:
    assert result.gate is not None
    [comparison] = result.gate.targets
    assert comparison.outcome == outcome
    if verdict is not None:
        assert result.gate.verdict == verdict
    return comparison
