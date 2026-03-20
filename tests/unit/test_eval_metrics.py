from evals.ground_truth import GroundTruth
from evals.metrics import (
    VerdictMap,
    aggregate_verdicts,
    compute_consistency,
    compute_distribution_coverage,
    compute_precision,
    compute_recall,
)
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

FAIL = EvalVerdict.FAIL
PASS = EvalVerdict.PASS
INPUT_VALIDATION = AuditCategory.INPUT_VALIDATION
ERROR_HANDLING = AuditCategory.ERROR_HANDLING
INFO_LEAKAGE = AuditCategory.INFO_LEAKAGE
INJECTION = AuditCategory.INJECTION
RESOURCE_ABUSE = AuditCategory.RESOURCE_ABUSE

ALL_CATEGORIES = list(AuditCategory)


def _make_result(tool: str, category: AuditCategory, verdict: EvalVerdict) -> EvalResult:
    return EvalResult(
        tool_name=tool,
        category=category,
        payload={},
        verdict=verdict,
        justification="test",
        severity=Severity.LOW,
    )


def _make_report(results_by_tool: dict[str, list[EvalResult]]) -> AuditReport:
    tool_reports = [
        ToolReport(
            tool=ToolDefinition(name=name, description="test", input_schema={"type": "object"}),
            cases=[
                TestCase(
                    payload=AuditPayload(
                        tool_name=r.tool_name,
                        category=r.category,
                        description="test",
                        arguments=r.payload,
                    ),
                    eval_result=r,
                )
                for r in results
            ],
        )
        for name, results in results_by_tool.items()
    ]
    return AuditReport(target="test", tool_reports=tool_reports, token_usage=TokenUsage())


def test_aggregate_verdicts_worst_case():
    report = _make_report(
        {
            "get_user": [
                _make_result("get_user", INPUT_VALIDATION, PASS),
                _make_result("get_user", INPUT_VALIDATION, FAIL),
            ]
        }
    )

    verdicts = aggregate_verdicts(report)

    assert verdicts[("get_user", INPUT_VALIDATION)] == FAIL


def test_aggregate_verdicts_all_pass():
    report = _make_report(
        {
            "get_user": [
                _make_result("get_user", INPUT_VALIDATION, PASS),
                _make_result("get_user", INPUT_VALIDATION, PASS),
            ]
        }
    )

    verdicts = aggregate_verdicts(report)

    assert verdicts[("get_user", INPUT_VALIDATION)] == PASS


def test_aggregate_verdicts_missing_pair():
    report = _make_report({"get_user": [_make_result("get_user", INPUT_VALIDATION, PASS)]})

    verdicts = aggregate_verdicts(report)

    assert verdicts.get(("get_user", ERROR_HANDLING)) is None


def test_recall_all_detected():
    ground_truth: GroundTruth = {
        ("a", INPUT_VALIDATION): FAIL,
        ("a", ERROR_HANDLING): FAIL,
        ("b", INPUT_VALIDATION): PASS,
    }
    aggregated: VerdictMap = {
        ("a", INPUT_VALIDATION): FAIL,
        ("a", ERROR_HANDLING): FAIL,
        ("b", INPUT_VALIDATION): PASS,
    }

    assert compute_recall(aggregated, ground_truth) == 1.0


def test_recall_partial():
    ground_truth: GroundTruth = {
        ("a", INPUT_VALIDATION): FAIL,
        ("a", ERROR_HANDLING): FAIL,
        ("a", INFO_LEAKAGE): FAIL,
        ("a", INJECTION): FAIL,
        ("a", RESOURCE_ABUSE): FAIL,
    }
    aggregated: VerdictMap = {
        ("a", INPUT_VALIDATION): FAIL,
        ("a", ERROR_HANDLING): FAIL,
        ("a", INFO_LEAKAGE): FAIL,
        ("a", INJECTION): PASS,
        ("a", RESOURCE_ABUSE): PASS,
    }

    assert compute_recall(aggregated, ground_truth) == 0.6


def test_recall_none_detected():
    ground_truth: GroundTruth = {
        ("a", INPUT_VALIDATION): FAIL,
        ("a", ERROR_HANDLING): FAIL,
    }
    aggregated: VerdictMap = {
        ("a", INPUT_VALIDATION): PASS,
        ("a", ERROR_HANDLING): PASS,
    }

    assert compute_recall(aggregated, ground_truth) == 0.0


def test_recall_uncovered_counts_as_miss():
    ground_truth: GroundTruth = {
        ("a", INPUT_VALIDATION): FAIL,
        ("a", ERROR_HANDLING): FAIL,
    }
    aggregated: dict[tuple[str, AuditCategory], EvalVerdict | None] = {
        ("a", INPUT_VALIDATION): FAIL,
        ("a", ERROR_HANDLING): None,
    }

    assert compute_recall(aggregated, ground_truth) == 0.5


def test_precision_no_false_positives():
    ground_truth: GroundTruth = {
        ("a", INPUT_VALIDATION): FAIL,
        ("a", ERROR_HANDLING): PASS,
    }
    aggregated: VerdictMap = {
        ("a", INPUT_VALIDATION): FAIL,
        ("a", ERROR_HANDLING): PASS,
    }

    assert compute_precision(aggregated, ground_truth) == 1.0


def test_precision_with_false_positive():
    ground_truth: GroundTruth = {
        ("a", INPUT_VALIDATION): FAIL,
        ("a", ERROR_HANDLING): PASS,
    }
    aggregated: VerdictMap = {
        ("a", INPUT_VALIDATION): FAIL,
        ("a", ERROR_HANDLING): FAIL,
    }

    assert compute_precision(aggregated, ground_truth) == 0.5


def test_precision_no_predictions():
    ground_truth: GroundTruth = {
        ("a", INPUT_VALIDATION): PASS,
        ("a", ERROR_HANDLING): PASS,
    }
    aggregated: dict[tuple[str, AuditCategory], EvalVerdict | None] = {
        ("a", INPUT_VALIDATION): PASS,
        ("a", ERROR_HANDLING): PASS,
    }

    assert compute_precision(aggregated, ground_truth) == 1.0


def test_consistency_perfect():
    run1: VerdictMap = {("a", INPUT_VALIDATION): FAIL, ("a", ERROR_HANDLING): PASS}
    run2: VerdictMap = {("a", INPUT_VALIDATION): FAIL, ("a", ERROR_HANDLING): PASS}
    run3: VerdictMap = {("a", INPUT_VALIDATION): FAIL, ("a", ERROR_HANDLING): PASS}

    score, details = compute_consistency([run1, run2, run3])

    assert score == 1.0
    assert all(d.rate == 1.0 for d in details.values())


def test_consistency_mixed():
    run1: dict[tuple[str, AuditCategory], EvalVerdict | None] = {
        ("a", INPUT_VALIDATION): FAIL,
        ("a", ERROR_HANDLING): PASS,
    }
    run2: dict[tuple[str, AuditCategory], EvalVerdict | None] = {
        ("a", INPUT_VALIDATION): FAIL,
        ("a", ERROR_HANDLING): FAIL,
    }
    run3: dict[tuple[str, AuditCategory], EvalVerdict | None] = {
        ("a", INPUT_VALIDATION): PASS,
        ("a", ERROR_HANDLING): FAIL,
    }

    # ("a", INPUT_VALIDATION): 2 FAIL, 1 PASS -> agreement = 2/3
    # ("a", ERROR_HANDLING): 1 PASS, 2 FAIL -> agreement = 2/3
    # average = 2/3
    expected = 2.0 / 3.0
    score, details = compute_consistency([run1, run2, run3])

    assert abs(score - expected) < 1e-9
    assert details["a/input_validation"].agree == 2
    assert details["a/error_handling"].agree == 2


def test_distribution_full_coverage():
    report = _make_report(
        {"get_user": [_make_result("get_user", cat, PASS) for cat in ALL_CATEGORIES]}
    )

    coverage = compute_distribution_coverage(report, ALL_CATEGORIES)

    assert coverage["get_user"] == 1.0


def test_distribution_partial():
    three_categories = [INPUT_VALIDATION, ERROR_HANDLING, INFO_LEAKAGE]
    report = _make_report(
        {"get_user": [_make_result("get_user", cat, PASS) for cat in three_categories]}
    )

    coverage = compute_distribution_coverage(report, ALL_CATEGORIES)

    assert coverage["get_user"] == 3.0 / 5.0
