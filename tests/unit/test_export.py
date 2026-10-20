from pathlib import Path

import pytest

import tests.unit.support.test_export_given as given
import tests.unit.support.test_export_then as then
from evals.cve_session_model import CVEAudit
from evals.export import export_cve_judged_cases, export_judged_cases
from evals.ground_truth import GroundTruth
from mcp_auditor.domain.models import AuditCategory, EvalVerdict


def test_a_judged_case_is_written_with_the_single_step_fields_and_its_label(
    tmp_path: Path,
) -> None:
    ground_truth: GroundTruth = {("get_user", AuditCategory.INPUT_VALIDATION): EvalVerdict.FAIL}
    runs = [(0, given.a_report([given.a_judged_case(EvalVerdict.FAIL)]))]

    export_judged_cases(runs, ground_truth, tmp_path / "eval_report.json")

    records = then.exported_records(tmp_path / "judged_cases.jsonl")
    then.every_record_is_a_single_step_with(
        records, then.SINGLE_STEP_FIELDS | {"expected_verdict", "correct"}
    )
    assert records[0]["expected_verdict"] == "fail"


@pytest.mark.parametrize(
    ("verdict", "label", "correct"),
    [("fail", "fail", True), ("pass", "fail", False), ("pass", None, None)],
)
def test_each_record_compares_its_verdict_to_the_label_of_its_cell(
    tmp_path: Path, verdict: str, label: str | None, correct: bool | None
) -> None:
    cell = ("get_user", AuditCategory.INPUT_VALIDATION)
    ground_truth: GroundTruth = {} if label is None else {cell: EvalVerdict(label)}
    runs = [(0, given.a_report([given.a_judged_case(EvalVerdict(verdict))]))]

    export_judged_cases(runs, ground_truth, tmp_path / "eval_report.json")

    [record] = then.exported_records(tmp_path / "judged_cases.jsonl")
    assert (record["verdict"], record["expected_verdict"], record["correct"]) == (
        verdict,
        label,
        correct,
    )


def test_each_record_carries_the_index_of_its_run(tmp_path: Path) -> None:
    case = given.a_judged_case(EvalVerdict.FAIL)
    runs = [(0, given.a_report([case])), (1, given.a_report([case]))]

    export_judged_cases(runs, {}, tmp_path / "eval_report.json")

    records = then.exported_records(tmp_path / "judged_cases.jsonl")
    assert [record["run_index"] for record in records] == [0, 1]


def test_cases_without_eval_result_are_excluded(tmp_path: Path) -> None:
    runs = [(0, given.a_report([given.an_unjudged_case(), given.a_judged_case(EvalVerdict.PASS)]))]

    export_judged_cases(runs, {}, tmp_path / "eval_report.json")

    records = then.exported_records(tmp_path / "judged_cases.jsonl")
    assert len(records) == 1
    assert records[0]["verdict"] == "pass"


def test_chain_verdicts_are_exported_with_steps(tmp_path: Path) -> None:
    ground_truth: GroundTruth = {("get_user", AuditCategory.INFO_LEAKAGE): EvalVerdict.FAIL}
    report = given.a_report(cases=[], chains=[given.a_chain_with_leakage_verdict()])

    export_judged_cases([(0, report)], ground_truth, tmp_path / "eval_report.json")

    [record] = then.exported_records(tmp_path / "judged_cases.jsonl")
    assert record["type"] == "chain"
    assert record["goal"] == "probe then exploit"
    steps: list[dict[str, object]] = record["steps"]  # type: ignore[assignment]
    assert len(steps) == 1
    assert steps[0]["arguments"] == {"action": "list"}
    assert steps[0]["observation"] == "found ids"
    assert record["verdict"] == "fail"
    assert record["expected_verdict"] == "fail"
    assert record["correct"] is True


def test_each_cve_line_carries_its_cve_and_run_but_no_expected_verdict(tmp_path: Path) -> None:
    report = given.a_report_with_a_judged_case_an_unjudged_case_and_a_chain()
    audits = [CVEAudit("CVE-2025-0001", 0, report), CVEAudit("CVE-2025-0002", 1, report)]

    export_cve_judged_cases(audits, tmp_path / "cve_report.json")

    records = then.exported_records(tmp_path / "cve_judged_cases.jsonl")
    assert [(record["cve_id"], record["run_index"]) for record in records] == [
        ("CVE-2025-0001", 0),
        ("CVE-2025-0002", 1),
    ]
    then.every_record_is_a_single_step_with(records, then.SINGLE_STEP_FIELDS | {"cve_id"})
    assert all(record["verdict"] == "fail" for record in records)
