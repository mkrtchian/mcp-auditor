from pathlib import Path

from evals.cve.detection.judged_cases_export import export_detection_judged_cases
from evals.cve.detection.session_model import DetectionAudit
from tests.unit.support.grammar_inputs import a_case, a_chain, a_report, a_step
from tests.unit.support.judged_case_exports import (
    SINGLE_STEP_FIELDS,
    every_record_is_a_single_step_with,
    exported_records,
)


def test_each_detection_line_carries_its_flaw_and_run_but_no_expected_verdict(
    tmp_path: Path,
) -> None:
    report = a_report([a_case(), a_case(verdict=None)], chains=[a_chain([a_step()])])
    audits = [
        DetectionAudit("CVE-2025-0001", 0, report),
        DetectionAudit("CVE-2025-0002", 1, report),
    ]

    export_detection_judged_cases(audits, tmp_path / "detection_report.json")

    records = exported_records(tmp_path / "detection_judged_cases.jsonl")
    assert [(record["flaw_id"], record["run_index"]) for record in records] == [
        ("CVE-2025-0001", 0),
        ("CVE-2025-0002", 1),
    ]
    every_record_is_a_single_step_with(records, SINGLE_STEP_FIELDS | {"flaw_id"})
    assert all(record["verdict"] == "fail" for record in records)
