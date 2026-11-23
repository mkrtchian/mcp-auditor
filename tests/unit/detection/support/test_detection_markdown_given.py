from evals.cve.detection.gate import DetectionGateResult, TargetComparison
from evals.cve.detection.oracle import DetectionReport
from evals.gate_outcome import GateOutcome
from tests.unit.detection.support.detection_reports import a_detection_report


def a_report_gated_on(*targets: TargetComparison) -> DetectionReport:
    gate = DetectionGateResult(outcome=GateOutcome.GREEN, reasons=[], targets=list(targets))
    return a_detection_report([]).model_copy(update={"gate": gate})
