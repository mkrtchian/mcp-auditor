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
    AuditReport,
    EvalResult,
    EvalVerdict,
    Severity,
    TokenUsage,
    ToolDefinition,
    ToolReport,
)

FAIL = EvalVerdict.FAIL
PASS = EvalVerdict.PASS
IV = AuditCategory.INPUT_VALIDATION
EH = AuditCategory.ERROR_HANDLING
IL = AuditCategory.INFO_LEAKAGE
INJ = AuditCategory.INJECTION
RA = AuditCategory.RESOURCE_ABUSE

ALL_CATEGORIES = list(AuditCategory)

_DUMMY_TOOL = ToolDefinition(
    name="t", description="test tool", input_schema={"type": "object"}
)


def _make_result(
    tool: str, category: AuditCategory, verdict: EvalVerdict
) -> EvalResult:
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
            tool=ToolDefinition(
                name=name, description="test", input_schema={"type": "object"}
            ),
            results=results,
        )
        for name, results in results_by_tool.items()
    ]
    return AuditReport(
        target="test", tool_reports=tool_reports, token_usage=TokenUsage()
    )


# --- aggregate_verdicts ---


def test_aggregate_verdicts_worst_case():
    report = _make_report(
        {
            "get_user": [
                _make_result("get_user", IV, PASS),
                _make_result("get_user", IV, FAIL),
            ]
        }
    )

    verdicts = aggregate_verdicts(report)

    assert verdicts[("get_user", IV)] == FAIL


def test_aggregate_verdicts_all_pass():
    report = _make_report(
        {
            "get_user": [
                _make_result("get_user", IV, PASS),
                _make_result("get_user", IV, PASS),
            ]
        }
    )

    verdicts = aggregate_verdicts(report)

    assert verdicts[("get_user", IV)] == PASS


def test_aggregate_verdicts_missing_pair():
    report = _make_report(
        {"get_user": [_make_result("get_user", IV, PASS)]}
    )

    verdicts = aggregate_verdicts(report)

    assert verdicts.get(("get_user", EH)) is None


# --- compute_recall ---


def test_recall_all_detected():
    ground_truth: GroundTruth = {
        ("a", IV): FAIL,
        ("a", EH): FAIL,
        ("b", IV): PASS,
    }
    aggregated: VerdictMap = {
        ("a", IV): FAIL,
        ("a", EH): FAIL,
        ("b", IV): PASS,
    }

    assert compute_recall(aggregated, ground_truth) == 1.0


def test_recall_partial():
    ground_truth: GroundTruth = {
        ("a", IV): FAIL,
        ("a", EH): FAIL,
        ("a", IL): FAIL,
        ("a", INJ): FAIL,
        ("a", RA): FAIL,
    }
    aggregated: VerdictMap = {
        ("a", IV): FAIL,
        ("a", EH): FAIL,
        ("a", IL): FAIL,
        ("a", INJ): PASS,
        ("a", RA): PASS,
    }

    assert compute_recall(aggregated, ground_truth) == 0.6


def test_recall_none_detected():
    ground_truth: GroundTruth = {
        ("a", IV): FAIL,
        ("a", EH): FAIL,
    }
    aggregated: VerdictMap = {
        ("a", IV): PASS,
        ("a", EH): PASS,
    }

    assert compute_recall(aggregated, ground_truth) == 0.0


def test_recall_uncovered_counts_as_miss():
    ground_truth: GroundTruth = {
        ("a", IV): FAIL,
        ("a", EH): FAIL,
    }
    aggregated: dict[tuple[str, AuditCategory], EvalVerdict | None] = {
        ("a", IV): FAIL,
        ("a", EH): None,
    }

    assert compute_recall(aggregated, ground_truth) == 0.5


# --- compute_precision ---


def test_precision_no_false_positives():
    ground_truth: GroundTruth = {
        ("a", IV): FAIL,
        ("a", EH): PASS,
    }
    aggregated: VerdictMap = {
        ("a", IV): FAIL,
        ("a", EH): PASS,
    }

    assert compute_precision(aggregated, ground_truth) == 1.0


def test_precision_with_false_positive():
    ground_truth: GroundTruth = {
        ("a", IV): FAIL,
        ("a", EH): PASS,
    }
    aggregated: VerdictMap = {
        ("a", IV): FAIL,
        ("a", EH): FAIL,
    }

    assert compute_precision(aggregated, ground_truth) == 0.5


def test_precision_no_predictions():
    ground_truth: GroundTruth = {
        ("a", IV): PASS,
        ("a", EH): PASS,
    }
    aggregated: dict[tuple[str, AuditCategory], EvalVerdict | None] = {
        ("a", IV): PASS,
        ("a", EH): PASS,
    }

    assert compute_precision(aggregated, ground_truth) == 1.0


# --- compute_consistency ---


def test_consistency_perfect():
    run1: VerdictMap = {("a", IV): FAIL, ("a", EH): PASS}
    run2: VerdictMap = {("a", IV): FAIL, ("a", EH): PASS}
    run3: VerdictMap = {("a", IV): FAIL, ("a", EH): PASS}

    assert compute_consistency([run1, run2, run3]) == 1.0


def test_consistency_mixed():
    run1: dict[tuple[str, AuditCategory], EvalVerdict | None] = {
        ("a", IV): FAIL,
        ("a", EH): PASS,
    }
    run2: dict[tuple[str, AuditCategory], EvalVerdict | None] = {
        ("a", IV): FAIL,
        ("a", EH): FAIL,
    }
    run3: dict[tuple[str, AuditCategory], EvalVerdict | None] = {
        ("a", IV): PASS,
        ("a", EH): FAIL,
    }

    # ("a", IV): 2 FAIL, 1 PASS -> agreement = 2/3
    # ("a", EH): 1 PASS, 2 FAIL -> agreement = 2/3
    # average = 2/3
    expected = 2.0 / 3.0
    assert abs(compute_consistency([run1, run2, run3]) - expected) < 1e-9


# --- compute_distribution_coverage ---


def test_distribution_full_coverage():
    report = _make_report(
        {
            "get_user": [
                _make_result("get_user", cat, PASS) for cat in ALL_CATEGORIES
            ]
        }
    )

    coverage = compute_distribution_coverage(report, ALL_CATEGORIES)

    assert coverage["get_user"] == 1.0


def test_distribution_partial():
    three_categories = [IV, EH, IL]
    report = _make_report(
        {
            "get_user": [
                _make_result("get_user", cat, PASS) for cat in three_categories
            ]
        }
    )

    coverage = compute_distribution_coverage(report, ALL_CATEGORIES)

    assert coverage["get_user"] == 3.0 / 5.0
