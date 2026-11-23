import tests.unit.evals.support.test_judge_report_given as given


def test_the_written_report_keeps_its_keys_in_order():
    report = given.a_report()

    assert list(report.model_dump(mode="json")) == [
        "timestamp",
        "conditions",
        "inputs_fingerprint",
        "per_run",
        "per_category",
        "gate",
        "runs",
        "retest_observations",
        "throttled_judgments",
        "recorded",
        "recording_refused",
        "concurrency",
        "throttled_requests",
    ]


def test_a_run_row_states_its_scores_and_its_confusion_matrix():
    report = given.a_report()

    assert report.model_dump(mode="json")["per_run"][0] == {
        "precision": 1.0,
        "recall": 1.0,
        "f1": 1.0,
        "confusion_matrix": {"tp": 2, "fp": 0, "tn": 2, "fn": 0},
    }


def test_a_run_row_leaves_the_uncovered_cases_out():
    report = given.a_report_with_a_case_uncovered_in_the_first_run()

    first_run = report.model_dump(mode="json")["per_run"][0]

    assert first_run["confusion_matrix"] == {"tp": 1, "fp": 0, "tn": 2, "fn": 0}


def test_the_categories_are_keyed_by_their_value():
    report = given.a_report()

    assert list(report.model_dump(mode="json")["per_category"]) == [
        "input_validation",
        "info_leakage",
    ]
