from evals.cve.detection.gate import TargetComparison, TargetOutcome
from evals.cve.detection.session import DetectionSessionResult
from evals.gate_outcome import GateOutcome


def the_one_target_ends(
    result: DetectionSessionResult, outcome: TargetOutcome, gate_outcome: GateOutcome | None = None
) -> TargetComparison:
    assert result.gate is not None
    [comparison] = result.gate.targets
    assert comparison.outcome == outcome
    if gate_outcome is not None:
        assert result.gate.outcome == gate_outcome
    return comparison
