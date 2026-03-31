import json
from pathlib import Path

import tests.unit.support.test_export_given as given
from evals.export import export_judged_cases
from mcp_auditor.domain.models import AuditCategory, EvalVerdict


def _read_jsonl(path: Path) -> list[dict[str, object]]:
    lines = path.read_text().strip().splitlines()
    return [json.loads(line) for line in lines]


class TestExportWritesCorrectJsonl:
    def test_writes_correct_fields_and_correct_values(self, tmp_path: Path) -> None:
        ground_truth = given.input_validation_ground_truth()
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

        # Run 0, case matching ground truth: FAIL == FAIL -> correct=True
        assert records[0]["run_index"] == 0
        assert records[0]["verdict"] == "fail"
        assert records[0]["expected_verdict"] == "fail"
        assert records[0]["correct"] is True

        # Run 0, case mismatching ground truth: PASS != FAIL -> correct=False
        assert records[1]["verdict"] == "pass"
        assert records[1]["expected_verdict"] == "fail"
        assert records[1]["correct"] is False

        # Run 0, case not in ground truth: correct=None, expected_verdict=None
        assert records[2]["expected_verdict"] is None
        assert records[2]["correct"] is None

        # Run 1 mirrors run 0
        assert records[3]["run_index"] == 1
        assert records[3]["correct"] is True
        assert records[4]["correct"] is False
        assert records[5]["correct"] is None


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
        ground_truth = given.info_leakage_ground_truth()
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
