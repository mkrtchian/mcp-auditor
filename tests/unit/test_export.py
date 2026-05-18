import json
from pathlib import Path

import tests.unit.support.test_export_given as given
from evals.export import export_judged_cases
from evals.ground_truth import GroundTruth
from mcp_auditor.domain.models import AuditCategory, EvalVerdict


def _read_jsonl(path: Path) -> list[dict[str, object]]:
    lines = path.read_text().strip().splitlines()
    return [json.loads(line) for line in lines]


class TestExportWritesCorrectJsonl:
    def test_writes_correct_fields_and_correct_values(self, tmp_path: Path) -> None:
        ground_truth: GroundTruth = {("get_user", AuditCategory.INPUT_VALIDATION): EvalVerdict.FAIL}
        case_matching = given.a_judged_case(EvalVerdict.FAIL, AuditCategory.INPUT_VALIDATION)
        case_mismatching = given.a_judged_case(EvalVerdict.PASS, AuditCategory.INPUT_VALIDATION)
        case_no_gt = given.a_judged_case(EvalVerdict.PASS, AuditCategory.ERROR_HANDLING)
        runs = [
            (0, given.a_report([case_matching, case_mismatching, case_no_gt])),
            (1, given.a_report([case_matching, case_mismatching, case_no_gt])),
        ]
        report_path = tmp_path / "eval_report.json"

        export_judged_cases(runs, ground_truth, report_path)

        records = _read_jsonl(tmp_path / "judged_cases.jsonl")
        assert len(records) == 6

        expected_keys = {
            "run_index",
            "type",
            "tool_name",
            "tool_description",
            "category",
            "description",
            "arguments",
            "response",
            "error",
            "verdict",
            "justification",
            "expected_verdict",
            "correct",
        }
        for record in records:
            assert set(record.keys()) == expected_keys
            assert record["type"] == "single_step"

        run_0_matching, run_0_mismatching, run_0_no_gt = records[0], records[1], records[2]
        run_1_matching, run_1_mismatching, run_1_no_gt = records[3], records[4], records[5]

        assert run_0_matching["run_index"] == 0
        assert run_0_matching["verdict"] == "fail"
        assert run_0_matching["expected_verdict"] == "fail"
        assert run_0_matching["correct"] is True

        assert run_0_mismatching["verdict"] == "pass"
        assert run_0_mismatching["expected_verdict"] == "fail"
        assert run_0_mismatching["correct"] is False

        assert run_0_no_gt["expected_verdict"] is None
        assert run_0_no_gt["correct"] is None

        assert run_1_matching["run_index"] == 1
        assert run_1_matching["correct"] is True
        assert run_1_mismatching["correct"] is False
        assert run_1_no_gt["correct"] is None


class TestExportSkipsUnjudgedCases:
    def test_cases_without_eval_result_are_excluded(self, tmp_path: Path) -> None:
        unjudged = given.an_unjudged_case()
        judged = given.a_judged_case(EvalVerdict.PASS)
        runs = [(0, given.a_report([unjudged, judged]))]
        report_path = tmp_path / "eval_report.json"

        export_judged_cases(runs, {}, report_path)

        records = _read_jsonl(tmp_path / "judged_cases.jsonl")
        assert len(records) == 1
        assert records[0]["verdict"] == "pass"


class TestExportIncludesChains:
    def test_chain_verdicts_are_exported_with_steps(self, tmp_path: Path) -> None:
        ground_truth: GroundTruth = {("get_user", AuditCategory.INFO_LEAKAGE): EvalVerdict.FAIL}
        chain = given.a_chain_with_leakage_verdict()
        report = given.a_report(cases=[], chains=[chain])
        runs = [(0, report)]
        report_path = tmp_path / "eval_report.json"

        export_judged_cases(runs, ground_truth, report_path)

        records = _read_jsonl(tmp_path / "judged_cases.jsonl")
        assert len(records) == 1
        record = records[0]
        assert record["type"] == "chain"
        assert record["goal"] == "probe then exploit"
        steps: list[dict[str, object]] = record["steps"]  # type: ignore[assignment]
        assert len(steps) == 1
        assert steps[0]["arguments"] == {"action": "list"}
        assert steps[0]["observation"] == "found ids"
        assert record["verdict"] == "fail"
        assert record["expected_verdict"] == "fail"
        assert record["correct"] is True


class TestExportHandlesMissingGroundTruth:
    def test_missing_ground_truth_yields_null_expected_and_correct(self, tmp_path: Path) -> None:
        case = given.a_judged_case(EvalVerdict.FAIL)
        runs = [(0, given.a_report([case]))]
        report_path = tmp_path / "eval_report.json"

        export_judged_cases(runs, {}, report_path)

        records = _read_jsonl(tmp_path / "judged_cases.jsonl")
        assert len(records) == 1
        assert records[0]["expected_verdict"] is None
        assert records[0]["correct"] is None
