import tests.unit.support.test_eval_metrics_given as given
from evals.ground_truth import GroundTruth
from evals.metrics import (
    VerdictMap,
    aggregate_verdicts,
    blocked_reasons,
    compute_consistency,
    compute_distribution_coverage,
    compute_precision,
    compute_recall,
)
from mcp_auditor.domain.models import AuditCategory, EvalVerdict

FAIL = EvalVerdict.FAIL
PASS = EvalVerdict.PASS
INPUT_VALIDATION = AuditCategory.INPUT_VALIDATION
ERROR_HANDLING = AuditCategory.ERROR_HANDLING
INFO_LEAKAGE = AuditCategory.INFO_LEAKAGE
INJECTION = AuditCategory.INJECTION
RESOURCE_ABUSE = AuditCategory.RESOURCE_ABUSE
ALL_CATEGORIES = list(AuditCategory)


def test_aggregate_verdicts_worst_case():
    report = given.a_report(
        {
            "get_user": [
                given.a_result("get_user", INPUT_VALIDATION, PASS),
                given.a_result("get_user", INPUT_VALIDATION, FAIL),
            ]
        }
    )

    verdicts = aggregate_verdicts(report)

    assert verdicts[("get_user", INPUT_VALIDATION)] == FAIL


def test_aggregate_verdicts_all_pass():
    report = given.a_report(
        {
            "get_user": [
                given.a_result("get_user", INPUT_VALIDATION, PASS),
                given.a_result("get_user", INPUT_VALIDATION, PASS),
            ]
        }
    )

    verdicts = aggregate_verdicts(report)

    assert verdicts[("get_user", INPUT_VALIDATION)] == PASS


def test_aggregate_verdicts_chain_fail_overrides_single_step_pass():
    report = given.a_report(
        results_by_tool={
            "user_dir": [
                given.a_result("user_dir", INFO_LEAKAGE, PASS),
                given.a_result("user_dir", INFO_LEAKAGE, PASS),
            ]
        },
        chains_by_tool={
            "user_dir": [given.a_chain("user_dir", INFO_LEAKAGE, FAIL)],
        },
    )

    verdicts = aggregate_verdicts(report)

    assert verdicts[("user_dir", INFO_LEAKAGE)] == FAIL


def test_aggregate_verdicts_missing_pair():
    report = given.a_report({"get_user": [given.a_result("get_user", INPUT_VALIDATION, PASS)]})

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
    aggregated: VerdictMap = {
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
    aggregated: VerdictMap = {
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
    run1: VerdictMap = {
        ("a", INPUT_VALIDATION): FAIL,
        ("a", ERROR_HANDLING): PASS,
    }
    run2: VerdictMap = {
        ("a", INPUT_VALIDATION): FAIL,
        ("a", ERROR_HANDLING): FAIL,
    }
    run3: VerdictMap = {
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
    report = given.a_report(
        {"get_user": [given.a_result("get_user", cat, PASS) for cat in ALL_CATEGORIES]}
    )

    coverage = compute_distribution_coverage(report, ALL_CATEGORIES)

    assert coverage["get_user"] == 1.0


def test_distribution_partial():
    three_categories = [INPUT_VALIDATION, ERROR_HANDLING, INFO_LEAKAGE]
    report = given.a_report(
        {"get_user": [given.a_result("get_user", cat, PASS) for cat in three_categories]}
    )

    coverage = compute_distribution_coverage(report, ALL_CATEGORIES)

    assert coverage["get_user"] == 3.0 / 5.0


def test_a_blocked_case_leaves_verdict_metrics_untouched():
    ground_truth: GroundTruth = {
        ("get_user", INPUT_VALIDATION): FAIL,
        ("get_user", INJECTION): FAIL,
    }
    judged = given.a_report({"get_user": [given.a_result("get_user", INPUT_VALIDATION, FAIL)]})
    with_a_block = given.and_a_blocked_case(judged, "get_user", INJECTION)

    baseline = aggregate_verdicts(judged)
    aggregated = aggregate_verdicts(with_a_block)

    assert aggregated == baseline
    assert compute_recall(aggregated, ground_truth) == compute_recall(baseline, ground_truth)
    assert compute_precision(aggregated, ground_truth) == compute_precision(baseline, ground_truth)
    assert compute_consistency([aggregated]) == compute_consistency([baseline])


def test_distribution_coverage_drops_when_the_only_case_of_a_category_is_blocked():
    judged_categories = [cat for cat in ALL_CATEGORIES if cat != INJECTION]
    all_judged = given.a_report(
        {"get_user": [given.a_result("get_user", cat, PASS) for cat in ALL_CATEGORIES]}
    )
    without_injection = given.a_report(
        {"get_user": [given.a_result("get_user", cat, PASS) for cat in judged_categories]}
    )
    injection_blocked = given.and_a_blocked_case(without_injection, "get_user", INJECTION)

    coverage = compute_distribution_coverage(injection_blocked, ALL_CATEGORIES)
    full_coverage = compute_distribution_coverage(all_judged, ALL_CATEGORIES)

    assert coverage["get_user"] == 4.0 / 5.0
    assert coverage["get_user"] < full_coverage["get_user"]


def test_reports_no_blocked_payload_in_a_clean_report():
    report = given.a_report({"search": [given.a_result("search", INPUT_VALIDATION, FAIL)]})

    assert blocked_reasons(report) == []


def test_reports_the_reason_of_every_blocked_case_and_chain():
    clean = given.a_report({"search": [given.a_result("search", INPUT_VALIDATION, FAIL)]})
    report = given.and_a_blocked_case(clean, "search", INJECTION)
    with_a_blocked_chain = given.and_a_blocked_chain(report, "search", INJECTION)

    assert sorted(blocked_reasons(with_a_blocked_chain)) == [
        "destructive SQL statement: drop table",
        "destructive filesystem command: rm -rf",
    ]
