from datetime import date

import tests.unit.detection.support.test_detection_oracle_given as oracle_given
from evals.cve.detection.gate import DetectionGateResult, TargetComparison, TargetOutcome
from evals.cve.detection.oracle import DetectionReport, TargetResult, UngradedStatus
from evals.cve.grammar import TargetStatus
from evals.gate_outcome import GateOutcome

DETECTED_FLAW = "CVE-2025-53109"
NOT_RUN_FLAW = "CVE-2025-68143"


def a_report_with_a_not_run_target(reasons: list[str], gated: bool) -> DetectionReport:
    report = a_gated_report() if gated else a_no_baseline_report()
    return report.model_copy(update={"results": [*report.results, a_not_run_result(reasons)]})


def a_gated_report(**update: object) -> DetectionReport:
    report = oracle_given.a_detection_report(
        [oracle_given.a_target_result(DETECTED_FLAW, TargetStatus.DETECTED, detected_runs=3)]
    )
    return report.model_copy(update={"gate": oracle_given.a_red_gate(), **update})


def a_no_baseline_report(**update: object) -> DetectionReport:
    return a_gated_report(gate=None, **update)


def a_not_run_result(reasons: list[str]) -> TargetResult:
    return TargetResult(
        flaw_id=NOT_RUN_FLAW,
        severity="7.5 HIGH",
        note="test note",
        status=UngradedStatus.NOT_RUN,
        not_run_reasons=reasons,
    )


def a_report_gated_on_a_detail(detail: str) -> DetectionReport:
    comparison = TargetComparison(
        flaw_id=NOT_RUN_FLAW,
        outcome=TargetOutcome.NOT_RUN,
        candidate_runs=[],
        detail=detail,
    )
    gate = DetectionGateResult(outcome=GateOutcome.NOT_COMPARABLE, reasons=[], targets=[comparison])
    return a_gated_report(gate=gate)


def a_priced_no_baseline_report() -> DetectionReport:
    return a_no_baseline_report(
        costs=[oracle_given.a_target_cost(DETECTED_FLAW)], prices_as_of=date(2026, 10, 1)
    )
