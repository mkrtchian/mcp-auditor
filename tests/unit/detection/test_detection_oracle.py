from evals.cve.detection.oracle import (
    DetectionReport,
    UngradedStatus,
    not_run,
    out_of_scope_results,
    result_for,
)
from evals.cve.grammar import FlawClass, MissKind, TargetStatus
from mcp_auditor.domain.models import AuditCategory
from tests.unit.detection.support import detection_reports


def test_not_run_keeps_the_target_description():
    result = not_run(detection_reports.FakeTarget())

    assert result.status == UngradedStatus.NOT_RUN
    assert result.runs == 0
    assert result.classes == [FlawClass.READ_OUTSIDE_SCOPE]
    assert result.awaited_capability == "declared-scope awareness"


def test_out_of_scope_results_carry_no_class():
    cves = [
        detection_reports.FakeOutOfScopeFlaw(
            flaw_id="CVE-2025-68144", severity="7.8 HIGH", reason="silent write"
        )
    ]

    results = out_of_scope_results(cves)

    assert len(results) == 1
    assert results[0].status == UngradedStatus.OUT_OF_SCOPE
    assert results[0].flaw_id == "CVE-2025-68144"
    assert results[0].note == "silent write"
    assert results[0].classes == []


def test_result_for_a_detected_resolution():
    grades = [
        detection_reports.a_detected_grade(),
        detection_reports.a_missed_grade(MissKind.NOT_AIMED),
    ]

    result = result_for(detection_reports.FakeTarget(), grades, test_budget=10)

    assert result.status == TargetStatus.DETECTED
    assert result.miss_kind is None
    assert result.classes == [FlawClass.READ_OUTSIDE_SCOPE]
    assert result.awaited_capability == "declared-scope awareness"
    assert (result.runs, result.detected_runs, result.surfaced_runs, result.aimed_runs) == (
        2,
        1,
        1,
        1,
    )
    assert result.budget == 10
    assert result.evidence is not None and detection_reports.NONCE in result.evidence
    assert result.category == AuditCategory.INJECTION


def test_a_result_lists_a_union_target_classes_sorted():
    target = detection_reports.FakeTarget(
        classes=frozenset({FlawClass.READ_OUTSIDE_SCOPE, FlawClass.COMMAND_EXECUTION})
    )

    result = not_run(target)

    assert result.classes == [
        FlawClass.COMMAND_EXECUTION,
        FlawClass.READ_OUTSIDE_SCOPE,
    ]


def test_a_result_of_a_target_with_no_class_lists_none():
    result = not_run(detection_reports.FakeTarget(classes=frozenset()))

    assert result.classes == []


def test_result_for_a_missed_resolution():
    grades = [
        detection_reports.a_missed_grade(MissKind.AIMED_BLOCKED, fail_without_proof=True),
        detection_reports.a_missed_grade(MissKind.NOT_AIMED),
        detection_reports.a_missed_grade(MissKind.NOT_AIMED),
    ]

    result = result_for(detection_reports.FakeTarget(), grades, test_budget=10)

    assert result.status == TargetStatus.MISSED
    assert result.miss_kind == MissKind.AIMED_BLOCKED
    assert (result.runs, result.detected_runs, result.aimed_runs) == (3, 0, 1)
    assert result.fail_without_proof_runs == 1
    assert result.evidence is None


def test_a_report_json_written_before_costs_and_measurement_still_loads():
    dumped = detection_reports.a_detection_report([]).model_dump(mode="json")
    for field in ("measurement", "costs", "prices_as_of"):
        dumped.pop(field)

    report = DetectionReport.model_validate(dumped)

    assert (report.measurement, report.costs, report.prices_as_of) == (None, [], None)


def test_a_report_writes_its_results_and_gate_under_the_glossary_keys():
    report = detection_reports.a_detection_report(
        [not_run(detection_reports.FakeTarget(), ["keeps no place"])]
    )
    dumped = report.model_copy(update={"gate": detection_reports.a_red_gate()}).model_dump(
        mode="json"
    )

    assert {"flaw_id", "not_run_reasons"} <= dumped["results"][0].keys()
    assert "outcome" in dumped["gate"]
    assert "retests" in dumped["gate"]["targets"][0]
