import json
from pathlib import Path

from evals.export import export_judged_cases
from evals.ground_truth import GroundTruth
from mcp_auditor.domain.models import (
    AuditCategory,
    AuditPayload,
    AuditReport,
    EvalResult,
    EvalVerdict,
    Severity,
    TestCase,
    TokenUsage,
    ToolDefinition,
    ToolReport,
)

TOOL = ToolDefinition(name="get_user", description="Fetches a user", input_schema={})


def _make_judged_case(
    verdict: EvalVerdict,
    category: AuditCategory = AuditCategory.INPUT_VALIDATION,
) -> TestCase:
    return TestCase(
        payload=AuditPayload(
            tool_name="get_user",
            category=category,
            description="test desc",
            arguments={"id": 1},
        ),
        response="some response",
        error=None,
        eval_result=EvalResult(
            tool_name="get_user",
            category=category,
            payload={"id": 1},
            verdict=verdict,
            justification="because",
            severity=Severity.HIGH,
        ),
    )


def _make_report(cases: list[TestCase]) -> AuditReport:
    return AuditReport(
        target="test",
        tool_reports=[ToolReport(tool=TOOL, cases=cases)],
        token_usage=TokenUsage(),
    )


def _read_jsonl(path: Path) -> list[dict[str, object]]:
    lines = path.read_text().strip().splitlines()
    return [json.loads(line) for line in lines]


class TestExportWritesCorrectJsonl:
    def test_writes_correct_fields_and_correct_values(self, tmp_path: Path) -> None:
        ground_truth: GroundTruth = {
            ("get_user", AuditCategory.INPUT_VALIDATION): EvalVerdict.FAIL,
        }
        case_matching = _make_judged_case(EvalVerdict.FAIL, AuditCategory.INPUT_VALIDATION)
        case_mismatching = _make_judged_case(
            EvalVerdict.PASS, AuditCategory.INPUT_VALIDATION
        )
        case_no_gt = _make_judged_case(EvalVerdict.PASS, AuditCategory.ERROR_HANDLING)

        runs: list[tuple[int, AuditReport]] = [
            (0, _make_report([case_matching, case_mismatching, case_no_gt])),
            (1, _make_report([case_matching, case_mismatching, case_no_gt])),
        ]
        report_path = tmp_path / "eval_report.json"

        export_judged_cases(runs, ground_truth, report_path)

        export_path = tmp_path / "judged_cases.jsonl"
        assert export_path.exists()
        records = _read_jsonl(export_path)
        assert len(records) == 6

        expected_keys = {
            "run_index",
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
        unjudged = TestCase(
            payload=AuditPayload(
                tool_name="get_user",
                category=AuditCategory.INPUT_VALIDATION,
                description="test",
                arguments={},
            ),
        )
        judged = _make_judged_case(EvalVerdict.PASS)
        runs: list[tuple[int, AuditReport]] = [
            (0, _make_report([unjudged, judged])),
        ]
        report_path = tmp_path / "eval_report.json"

        export_judged_cases(runs, {}, report_path)

        records = _read_jsonl(tmp_path / "judged_cases.jsonl")
        assert len(records) == 1
        assert records[0]["verdict"] == "pass"


class TestExportHandlesMissingGroundTruth:
    def test_missing_ground_truth_yields_null_expected_and_correct(self, tmp_path: Path) -> None:
        case = _make_judged_case(EvalVerdict.FAIL)
        runs: list[tuple[int, AuditReport]] = [(0, _make_report([case]))]
        report_path = tmp_path / "eval_report.json"

        export_judged_cases(runs, {}, report_path)

        records = _read_jsonl(tmp_path / "judged_cases.jsonl")
        assert len(records) == 1
        assert records[0]["expected_verdict"] is None
        assert records[0]["correct"] is None
